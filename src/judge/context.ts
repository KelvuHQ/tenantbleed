import type { Finding, FindingKind } from "../core/findings.js";
import type { JudgeInput } from "../core/judge-input.js";
import { columnsInProof, dataClasses, fingerprints, standardsOf, type SourceRef } from "../core/report-context.js";

/**
 * The customer-report fields of every finding (src/core/report-context.ts): a stable id, standard
 * references, the data involved, and where the deciding rule lives in the app's code. Facts only from
 * the input; the decisions about severity were made before this step and are not changed here.
 */

/** The policy command that governs each kind of access. */
const COMMAND: Partial<Record<FindingKind, string>> = {
  "cross-tenant-read": "SELECT",
  "anon-read": "SELECT",
  "view-leak": "SELECT",
  "cross-tenant-update": "UPDATE",
  "cross-tenant-reparent": "UPDATE",
  "cross-tenant-delete": "DELETE",
  "cross-tenant-insert": "INSERT",
  "impersonation-insert": "INSERT",
  "metadata-escalation": "SELECT",
  "self-escalation": "UPDATE",
  "self-enrollment": "INSERT",
};
const READS = new Set<FindingKind>(["cross-tenant-read", "anon-read", "view-leak", "rpc-leak"]);

export function addReportContext(findings: Finding[], input: Pick<JudgeInput, "schema" | "hints">): Finding[] {
  const ids = fingerprints(findings);
  const sources = input.hints.sources ?? [];
  const at = (s: SourceRef | undefined, what: string) => (s ? [{ file: s.file, line: s.line, what }] : []);
  const objectSource = (target: string) => sources.find((s) => s.kind !== "policy" && s.object === target);

  const location = (f: Finding): Finding["location"] => {
    const target = f.target.replace(/\(.*$/, "");
    const fn = input.schema.functions.some((x) => `${x.schema}.${x.name}` === target);
    if (fn) return at(sources.find((s) => s.kind === "function" && s.object === target), `function ${target}`);
    // A policy the finding names is the one to fix; else the policies for this kind of access.
    const named = /[Pp]olicy "([^"]+)"/.exec(`${f.title} ${f.detail}`)?.[1];
    const cmd = COMMAND[f.kind];
    const policies = input.schema.policies.filter(
      (p) => `${p.schema}.${p.table}` === target && (named ? p.name === named : !cmd || p.cmd === cmd || p.cmd === "ALL"),
    );
    const found = policies.flatMap((p) =>
      at(sources.find((s) => s.kind === "policy" && s.object === target && s.name === p.name), `policy "${p.name}" (${p.cmd})`),
    );
    if (found.length) return found;
    const s = objectSource(target);
    return at(s, `${s?.kind ?? "table"} ${target}`);
  };

  const data = (f: Finding): Finding["data"] => {
    if (f.target.startsWith("bucket:")) return { columns: [], classes: ["files"] };
    const rel = input.schema.relations.find((r) => `${r.schema}.${r.name}` === f.target);
    const fromProof = READS.has(f.kind) && f.evidence ? columnsInProof(f.evidence.proof) : [];
    const columns = fromProof.length ? fromProof : (rel?.columns.map((c) => c.name) ?? []);
    return columns.length ? { columns, classes: dataClasses(columns) } : undefined;
  };

  return findings.map((f, i) => {
    const out: Finding = { ...f, fingerprint: ids[i], standards: standardsOf(f.kind) };
    const loc = location(f);
    if (loc?.length) out.location = loc;
    const d = data(f);
    if (d) out.data = d;
    return out;
  });
}
