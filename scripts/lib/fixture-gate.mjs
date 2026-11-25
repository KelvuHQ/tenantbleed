// Shared scaffolding for the planted-app checkers (scripts/check-<app>.mjs): load a report, compare
// what was proven with what a planted app must produce, and exit non-zero on any failure. A checker
// holds only its app's expectations; this file holds the logic, once, for every engine.
import { readFileSync } from "node:fs";

export const loadReport = (path) => JSON.parse(readFileSync(path, "utf8"));
export const provenOf = (report) => report.findings.filter((f) => f.confidence === "proven");
export const sideOf = (f) => (f.evidence?.actor === "anon" ? "anon" : "tenant");
/** "kind target side": how expectations name a proven finding. */
export const keyOf = (f) => `${f.kind} ${f.target} ${sideOf(f)}`;

/**
 * A gate: named checks that print ok or FAIL, counted. `done(summary)` prints the summary line
 * (the fixture suite shows the last line) and exits 1 if any check failed.
 */
export function gate() {
  let failed = 0;
  let total = 0;
  const lines = [];
  return {
    check(ok, name, why = "") {
      total++;
      if (!ok) failed++;
      lines.push(`${ok ? "ok  " : "FAIL"}  ${name}${ok || !why ? "" : `: ${why}`}`);
      return ok;
    },
    /** A failure that is not one of the counted cases (a false positive, an empty table). */
    fail(message) {
      failed++;
      lines.push(`FAIL  ${message}`);
    },
    note(line) {
      lines.push(line);
    },
    get failed() {
      return failed;
    },
    get total() {
      return total;
    },
    /** The ok and FAIL lines so far, for a checker that prints its own summary. */
    lines() {
      return [...lines];
    },
    done(summary) {
      for (const l of lines) console.log(l);
      console.log(summary);
      process.exit(failed ? 1 : 0);
    },
  };
}

/**
 * The checks every planted app shares.
 * - expected: { "case name": ["kind target side", ...] }: each case must be proven.
 * - knownGaps: { "case name": "reason" }: still reported (GAP), but does not fail.
 * - mustBeClean: targets with no proven finding (controls).
 * - mustBeFilled: tables that must get test data.
 * Returns counts for the summary line.
 */
export function standardChecks(g, report, { expected = {}, knownGaps = {}, mustBeClean = [], mustBeFilled = [] }) {
  const proven = provenOf(report);
  const got = new Set(proven.map(keyOf));
  let gaps = 0;
  for (const [name, keys] of Object.entries(expected)) {
    const miss = keys.filter((k) => !got.has(k));
    const gap = knownGaps[name];
    if (miss.length && gap) {
      gaps++;
      g.note(`GAP   ${name}: missing ${miss.join("; ")} (known gap: ${gap})`);
      continue;
    }
    g.check(!miss.length, `${name}${!miss.length && gap ? " (listed as a known gap but now proven: remove it)" : ""}`, `missing ${miss.join("; ")}`);
  }
  const falsePositives = proven.filter((f) => mustBeClean.includes(f.target));
  for (const f of falsePositives) g.fail(`false positive: ${f.kind} ${f.target} (${f.title})`);
  const coverage = report.coverage ?? [];
  const unfilled = mustBeFilled.filter((t) => coverage.find((x) => x.relation === t)?.populated === false);
  for (const t of unfilled) g.fail(`no test data in ${t} ${coverage.find((x) => x.relation === t)?.reason ?? ""}`);
  reportContext(g, report);
  return { proven, got, gaps, falsePositives: falsePositives.length, unfilled: unfilled.length };
}

/**
 * The customer-report fields (src/core/report-context.ts), for every engine: the report names the app
 * and version, every finding has a stable unique id and standard references, and every proven finding
 * outside storage says where in the code to fix it.
 */
export function reportContext(g, report) {
  const t = report.target ?? {};
  g.check(!!(t.name && t.tool && t.commit && t.schemaVersion?.hash), "report names the app, its commit, schema version and tenantbleed version", JSON.stringify(t));
  const ids = report.findings.map((f) => f.fingerprint);
  const dup = ids.filter((id, i) => !id || ids.indexOf(id) !== i);
  g.check(!dup.length, "every finding has its own stable id", `missing or repeated: ${dup.join(", ")}`);
  const noStd = report.findings.filter((f) => !f.standards?.owasp.length || !f.standards?.cwe.length);
  g.check(!noStd.length, "every finding has OWASP and CWE references", noStd.map((f) => `${f.kind} ${f.target}`).join("; "));
  const noLoc = provenOf(report).filter((f) => !f.target.startsWith("bucket:") && !f.location?.length);
  g.check(!noLoc.length, "every proven finding says where to fix it", noLoc.map((f) => `${f.kind} ${f.target}`).join("; "));
}

/** Triage rows (linter warnings) for one target. */
export const triageRows = (report, target) => (report.triage?.rows ?? []).filter((r) => r.target === target);
