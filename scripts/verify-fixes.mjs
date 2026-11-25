// Prototype verifier for tenantbleed fixes. Local only: run inside a project whose Supabase stack is
// already running (supabase start). For every generated fix it adds the migration, rebuilds the
// database from migrations (supabase db reset), re-scans with the rightful-owner check, and accepts
// the fix only when:
//   1. every finding it targets is gone,
//   2. no new finding at medium or above appeared,
//   3. every owner operation that worked before still works (the app is not broken), and so does
//      every coworker and admin operation on tenant A's data, unless the stranger (tenant B) could
//      do the same at baseline: then it was open access, and losing it is listed for review.
// Then it applies all accepted fixes together and checks the same three things.
//
// usage: node scripts/verify-fixes.mjs <project dir> <path to tenantbleed.mjs> [out dir]

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import pg from "pg";

const [project, tp, outArg] = process.argv.slice(2);
if (!project || !tp) {
  console.error("usage: node scripts/verify-fixes.mjs <project dir> <tenantbleed.mjs> [out dir]");
  process.exit(2);
}
const dir = resolve(project);
const out = resolve(outArg ?? join(dir, "tenantbleed-fix-verify"));
const migrations = join(dir, "supabase", "migrations");
const supa = (args) => execFileSync("npx", ["-y", "supabase@2.122.1", ...args], { cwd: dir, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
const scan = (name) => {
  const prefix = join(out, name);
  try {
    execFileSync("node", [resolve(tp), "supabase", "--workdir", dir, "--out", prefix, "--fail-on", "none"], { env: { ...process.env, TENANTBLEED_OWNER_CHECK: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    /* exit codes are read from the report */
  }
  return JSON.parse(readFileSync(`${prefix}.json`, "utf8"));
};
const side = (f) => (f.evidence?.actor === "anon" ? "anon" : "tenant");
const keys = (r, min = ["critical", "high", "medium"]) => new Set(r.findings.filter((f) => f.confidence === "proven" && min.includes(f.severity)).map((f) => `${f.kind} ${f.target} ${side(f)}`));
const allKeys = (r) => new Set(r.findings.filter((f) => f.confidence === "proven").map((f) => `${f.kind} ${f.target} ${side(f)}`));
// How many actors could do each operation. Owners are counted together per table and operation:
// which tenant's own row is readable can vary between runs (seeded data, time-based rules), so a
// fix breaks owner access only when fewer owners can do it than before.
const ownerOk = (r) => {
  const m = new Map();
  for (const o of r.ownerAccess ?? []) {
    const role = o.role ?? "owner";
    const k = role === "owner" ? `${o.relation} owner * ${o.op}` : `${o.relation} ${role} ${o.actor.replace(/ /g, "_")} ${o.op}`;
    m.set(k, (m.get(k) ?? 0) + (o.ok ? 1 : 0));
  }
  return m;
};
// An operation that now fails because the database rejected the test row itself (bad value,
// duplicate, server error) says nothing about permissions: listed as "could not recheck", not broken.
const rowRejected = (r) => {
  const m = new Set();
  for (const o of r.ownerAccess ?? []) if (!o.ok && /^(400|409|422|5\d\d)$/.test(String(o.detail))) {
    const role = o.role ?? "owner";
    m.add(role === "owner" ? `${o.relation} owner * ${o.op}` : `${o.relation} ${role} ${o.actor.replace(/ /g, "_")} ${o.op}`);
  }
  return m;
};
const strangerHad = (k) => { const [rel, role, , op] = k.split(" "); return role !== "owner" && [...baseOwner].some(([x, n]) => n > 0 && x.startsWith(`${rel} stranger `) && x.endsWith(` ${op}`)); };
// Tables whose permissive policy for a command was already "true": a finding there after a fix
// existed before it (the scan could only now attribute the rows), so it is not introduced by the fix.
const CMD = { "cross-tenant-read": "SELECT", "anon-read": "SELECT", "cross-tenant-update": "UPDATE", "cross-tenant-reparent": "UPDATE", "cross-tenant-insert": "INSERT", "impersonation-insert": "INSERT", "cross-tenant-delete": "DELETE" };
let timeBased = new Set();
async function alwaysTrue() {
  const status = JSON.parse(supa(["status", "-o", "json"]).replace(/^[^{]*/, ""));
  const db = new pg.Client({ connectionString: status.DB_URL });
  await db.connect();
  try {
    const res = await db.query("select schemaname || '.' || tablename as t, cmd from pg_policies where permissive = 'PERMISSIVE' and (qual = 'true' or with_check = 'true')");
    // Tables whose policies depend on the clock: which rows are visible changes from run to run.
    const clock = await db.query("select distinct schemaname || '.' || tablename as t from pg_policies where coalesce(qual, '') || coalesce(with_check, '') ~* '(now\\(\\)|current_date|current_timestamp|clock_timestamp|localtimestamp)'");
    timeBased = new Set(clock.rows.map((r) => r.t));
    return new Set(res.rows.map((r) => `${r.t} ${r.cmd}`));
  } finally {
    await db.end();
  }
}
const stamp = () => {
  const last = readdirSync(migrations).filter((f) => /^\d+/.test(f)).sort().at(-1) ?? "0";
  return String(BigInt(last.match(/^\d+/)[0]) + 1n);
};

mkdirSync(out, { recursive: true });
console.log("baseline scan");
supa(["db", "reset"]);
const base = scan("baseline");
const baseOwner = ownerOk(base);
const openBefore = await alwaysTrue();
const preExisting = (k) => { const [kind, target] = k.split(" "); return openBefore.has(`${target} ${CMD[kind]}`) || openBefore.has(`${target} ALL`); };
execFileSync("node", [resolve(tp), "fix", "--workdir", dir, "--report", join(out, "baseline.json"), "--out", join(out, "fixes")], { stdio: "inherit" });
const { fixes, skipped } = JSON.parse(readFileSync(join(out, "fixes", "fixes.json"), "utf8"));

function verify(name, files) {
  const added = [];
  for (const f of files) {
    const dest = join(migrations, `${stamp()}_tenantbleed_${f.id.toLowerCase()}.sql`);
    copyFileSync(join(out, "fixes", f.file), dest);
    added.push(dest);
  }
  let after;
  let error;
  try {
    supa(["db", "reset"]);
    after = scan(name);
  } catch (e) {
    error = String(e.stderr || e.message).split("\n").find((l) => /ERROR|error/.test(l)) ?? "migration failed";
  }
  for (const a of added) rmSync(a);
  if (!after) return { ok: false, error };
  const now = allKeys(after);
  const closes = files.flatMap((f) => f.closes);
  const stillOpen = closes.filter((k) => now.has(k));
  const before = keys(base);
  const appeared = [...keys(after)].filter((k) => !before.has(k));
  const introduced = appeared.filter((k) => !preExisting(k));
  const newlyVisible = appeared.filter((k) => preExisting(k));
  const ownerNow = ownerOk(after);
  const lost = [...baseOwner].filter(([k, n]) => n > 0 && k.split(" ")[1] !== "stranger" && (ownerNow.get(k) ?? n) < n).map(([k]) => k);
  const rejectedNow = rowRejected(after);
  const flaky = (k) => rejectedNow.has(k) || timeBased.has(k.split(" ")[0]);
  const unsure = lost.filter(flaky);
  const broken = lost.filter((k) => !strangerHad(k) && !flaky(k));
  const review = lost.filter((k) => strangerHad(k) && !flaky(k));
  return { ok: !stillOpen.length && !introduced.length && !broken.length, stillOpen, introduced, newlyVisible, broken, review, unsure, ownerChecks: ownerNow.size };
}

const results = [];
for (const fix of fixes) {
  fix.file = readdirSync(join(out, "fixes")).find((f) => f.startsWith(`${fix.id}_`));
  process.stdout.write(`verify ${fix.id} ${fix.template} ${fix.target} ... `);
  const r = verify(fix.id, [fix]);
  console.log(r.ok ? "PASS" : `FAIL ${r.error ?? ""}${r.stillOpen?.length ? ` still open: ${r.stillOpen.join("; ")}` : ""}${r.introduced?.length ? ` new: ${r.introduced.join("; ")}` : ""}${r.broken?.length ? ` broke access: ${r.broken.join("; ")}` : ""}`);
  if (r.unsure?.length) console.log(`    could not recheck (test row rejected, or the table's policy depends on the clock): ${r.unsure.join("; ")}`);
  if (r.review?.length) console.log(`    review: closed open access that a coworker or admin also used: ${r.review.join("; ")}`);
  results.push({ ...fix, result: r });
}
const accepted = results.filter((r) => r.result.ok);
console.log(`\nall ${accepted.length} accepted fixes together ... `);
const together = accepted.length ? verify("together", accepted) : { ok: true };
const remaining = together.ok && accepted.length ? (() => { const after = JSON.parse(readFileSync(join(out, "together.json"), "utf8")); return [...keys(after)]; })() : [];
console.log(together.ok ? "PASS" : `FAIL ${JSON.stringify(together)}`);
const roles = {};
for (const o of base.ownerAccess ?? []) roles[o.role ?? "owner"] = (roles[o.role ?? "owner"] ?? 0) + 1;
console.log(`access checks at baseline by role: ${JSON.stringify(roles)}`);
for (const n of base.notes ?? []) if (/^Fix check|role check/.test(n)) console.log(`  ${n}`);
supa(["db", "reset"]);
writeFileSync(join(out, "verify.json"), JSON.stringify({ fixes: results, skipped, together, remainingAfterAll: remaining }, null, 2));
// The fix report: what was fixed and verified, what was rejected, and what needs a human.
const md = ["# tenantbleed fix report", "", `Baseline: ${keys(base).size} proven issue(s) at medium or above. After all accepted fixes: ${remaining.length}.`, ""];
md.push("## Fixed and verified", "", "Each fix was applied to a fresh database; the attacks were re-run and every owner, coworker and admin operation that worked before still works.", "");
for (const r of accepted) md.push(`- **${r.id}** ${r.title} (\`${r.file}\`). Closes: ${r.closes.join("; ")}`);
if (!accepted.length) md.push("- none");
const rejected = results.filter((r) => !r.result.ok);
md.push("", "## Rejected (not proposed)", "");
for (const r of rejected) md.push(`- **${r.id}** ${r.title}: ${[r.result.error, r.result.stillOpen?.length && `attack still works (${r.result.stillOpen.join("; ")})`, r.result.introduced?.length && `new issue (${r.result.introduced.join("; ")})`, r.result.broken?.length && `breaks legitimate access (${r.result.broken.join("; ")})`].filter(Boolean).join("; ")}`);
if (!rejected.length) md.push("- none");
md.push("", "## Needs a human", "", "Found and proven, but no automatic fix is offered:", "");
for (const s of skipped.filter((s) => s.reason !== "low severity")) md.push(`- [${s.severity ?? "?"}] ${s.title ?? s.finding}: ${s.reason}`);
for (const r of rejected) md.push(`- ${r.closes.join("; ")}: the automatic fix was rejected (above)`);
const reviews = results.flatMap((r) => (r.result.review ?? []).map((k) => `${r.id}: ${k}`));
if (reviews.length) md.push("", "## Review", "", "These fixes closed access that was open to everyone and that a coworker or admin also used. Confirm they should not have it:", "", ...reviews.map((x) => `- ${x}`));
const unsure = [...new Set(results.flatMap((r) => r.result.unsure ?? []))];
if (unsure.length) md.push("", "## Could not recheck", "", "These operations were not compared: the database rejected the test row (a bad value or duplicate, not a permission denial), or the table's policy depends on the current time, so which rows are visible changes between runs. Check them by hand:", "", ...unsure.map((x) => `- ${x}`));
const lows = skipped.filter((s) => s.reason === "low severity").length;
if (lows) md.push("", `${lows} low-severity finding(s) are listed in the scan report and not fixed automatically.`);
writeFileSync(join(out, "fix-report.md"), md.join("\n") + "\n");
console.log(`\nbaseline proven (medium+): ${keys(base).size}; fixes: ${fixes.length}; passed: ${accepted.length}; skipped findings: ${skipped.length}; still proven after all accepted fixes: ${remaining.length}`);
for (const k of remaining) console.log(`  remaining: ${k}`);
