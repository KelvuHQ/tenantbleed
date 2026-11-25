export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export type FindingKind =
  | "cross-tenant-read"
  | "cross-tenant-update"
  | "cross-tenant-delete"
  | "cross-tenant-insert"
  | "cross-tenant-reparent"
  | "impersonation-insert"
  | "anon-read"
  | "rpc-leak"
  | "rpc-write"
  | "view-leak"
  | "metadata-escalation"
  | "self-escalation"
  | "self-enrollment"
  | "static";

export interface Evidence {
  /** Who made the request. */
  actor: string;
  /** Whose data was touched. */
  victim?: string;
  request: { method: string; path: string; body?: unknown };
  status: number;
  /** Short proof, e.g. the leaked row or the before/after values. */
  proof: string;
  /** Copy-paste reproduction against the local stack. */
  curl: string;
  /** How the test data or the call behind this proof was built (trace ids: "row/rules-paused",
   * "args/parent-column"), so a report can say what the proof relied on. */
  via?: string[];
}

export interface Finding {
  id: string;
  kind: FindingKind;
  severity: Severity;
  /** Relation, view or function this finding is about. */
  target: string;
  title: string;
  detail: string;
  /** "proven" = reproduced with real accounts. "static" = inferred from schema only. */
  confidence: "proven" | "static";
  evidence?: Evidence;
  fix?: string;
  /** Which judge rule decided this finding ("rpc-write/shared-change"): the fixture suite checks
   * that every rule in scripts/rules.json is exercised by a planted case. */
  rule: string;
  /** Rules of observations merged into this finding (a GraphQL read of a table already read over REST). */
  alsoRules?: string[];
  /** Stable id across runs ("TP-3f9c0a12b4"): the same failure keeps it, so reports can say fixed, new, still open. */
  fingerprint?: string;
  /** Where the rule that decides this access lives in the app's code (the policies, function or table). */
  location?: { file: string; line: number; what: string }[];
  /** Data involved: the columns in the leaked row (reads), or of the table or function's rows (writes), and their classes. */
  data?: { columns: string[]; classes: string[] };
  /** OWASP and CWE references (src/core/report-context.ts). */
  standards?: { owasp: string[]; cwe: string[] };
}

export function atLeast(sev: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(sev) <= SEVERITY_ORDER.indexOf(threshold);
}

/**
 * The build gate, shared by the CLI and the Action: 1 when a proven finding is at least as severe
 * as the threshold, 2 when the scan is incomplete and proved nothing (never read as clean), else 0.
 */
export function gateExitCode(r: { findings: Finding[]; complete: boolean }, threshold: Severity | "none"): number {
  const proven = r.findings.filter((f) => f.confidence === "proven");
  const failing = threshold === "none" ? [] : proven.filter((f) => atLeast(f.severity, threshold));
  return !r.complete && !proven.length ? 2 : failing.length ? 1 : 0;
}
