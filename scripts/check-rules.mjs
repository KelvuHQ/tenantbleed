// Rule coverage gate: every decision in scripts/rules.json must be produced by at least one planted
// app, and every rule name in the judge's code must be listed in rules.json.
// usage: node scripts/check-rules.mjs <folder with the planted apps' reports (scripts/test-fixtures.sh writes them)>
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const spec = JSON.parse(readFileSync(join(root, "scripts/rules.json"), "utf8"));
const dir = process.argv[2];
// Every report the suite wrote: each planted app's scan, and each replay of its facts.
const reports = readdirSync(dir)
  .filter((f) => f.endsWith(".json") && !f.endsWith(".input.json"))
  .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")))
  .filter((r) => Array.isArray(r.findings));

// What the planted apps produced.
const fired = new Set();
for (const r of reports) {
  for (const f of r.findings) {
    const side = f.confidence === "static" ? "-" : f.evidence?.actor === "anon" ? "anon" : "tenant";
    if (f.rule) fired.add(`${f.rule}|${f.severity}|${side}`);
    for (const a of f.alsoRules ?? []) fired.add(a);
  }
  for (const t of r.triage?.rows ?? []) if (t.rule) fired.add(t.rule);
}
const notes = reports.flatMap((r) => r.notes ?? []);
const has = (rule, variant) => {
  const [sev, side] = variant.split("|");
  if (side === "any") return fired.has(`${rule}|${sev}|tenant`) || fired.has(`${rule}|${sev}|anon`);
  return fired.has(`${rule}|${sev}|${side}`);
};

const missing = [];
let total = 0;
for (const [rule, variants] of Object.entries(spec.findings))
  for (const v of variants) {
    total++;
    if (!has(rule, v)) missing.push(`${rule} ${v}`);
  }
for (const rule of [...spec.modifiers, ...spec.triage]) {
  if (spec.untestable[rule]) continue;
  total++;
  if (![...fired].some((k) => k === rule || k.startsWith(`${rule}|`))) missing.push(rule);
}
for (const [name, re] of Object.entries(spec.notes)) {
  if (spec.untestable[`note ${name}`]) continue;
  total++;
  if (!notes.some((n) => new RegExp(re).test(n))) missing.push(`note ${name}`);
}

// Test-data steps and argument strategies (src/core/trace.ts): every id the engine code uses must be
// listed under "strategies", and every listed one must show up in a planted app's trace.
const traced = new Set(reports.flatMap((r) => (r.trace ?? []).map((t) => t.id)));
const STRATEGY = /"((?:row|check|value|args|world|owner-control)\/[a-z-]+)"/g;
const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith(".ts") ? [join(d, e.name)] : []));
const inCode = new Map();
for (const f of walk(join(root, "src"))) for (const m of readFileSync(f, "utf8").matchAll(STRATEGY)) inCode.set(m[1], f.slice(root.length + 1));
const strategies = spec.strategies ?? {};
for (const [id, file] of inCode) if (!(id in strategies)) missing.push(`strategy ${id} is used in ${file} but not listed in rules.json`);
for (const id of Object.keys(strategies).filter((k) => k !== "about")) {
  if (spec.untestable[`strategy ${id}`]) continue;
  total++;
  if (!inCode.has(id)) missing.push(`strategy ${id} is listed but no longer in the code`);
  else if (!traced.has(id)) missing.push(`strategy ${id}`);
}

// Rule names in the code that the registry does not list.
const known = new Set([...Object.keys(spec.findings), ...spec.modifiers, ...spec.triage]);
const unlisted = new Set();
for (const f of readdirSync(join(root, "src/judge")).filter((x) => x.endsWith(".ts"))) {
  const src = readFileSync(join(root, "src/judge", f), "utf8");
  for (const line of src.split("\n").filter((l) => /\b(rule|alsoRules)\b/.test(l)))
    for (const m of line.matchAll(/"((?:static|triage|modifier|read|graphql-read|reparent|insert|impersonate|rpc-leak|rpc-write|file-[a-z]+|update|delete|metadata)(?:\/[a-z-]+)?)"/g))
      if (!known.has(m[1])) unlisted.add(`${m[1]} (${f})`);
}

for (const m of missing) console.log(`UNTESTED  ${m}`);
for (const u of unlisted) console.log(`UNLISTED  ${u}`);
console.log(`rules: ${total - missing.length} of ${total} exercised by the planted apps, ${unlisted.size} rule(s) in the code missing from rules.json`);
process.exit(missing.length || unlisted.size ? 1 : 0);
