import type { TraceRow } from "./trace.js";
import type { Finding } from "./findings.js";
import type { ScanTarget } from "./report-context.js";

/**
 * The scan result the scanner produces and the judge returns, plus the
 * raw linter rows the engine collects. Plain JSON throughout.
 */

export interface CoverageRow {
  relation: string;
  kind: "table" | "view" | "function" | "bucket";
  reached: number;
  unreachable: number;
  populated: boolean;
  shared?: boolean;
  reason?: string;
  /** Its schema is not in the API's exposed list, so it was filled only to call functions, never served. */
  notExposed?: boolean;
  /** An app-wide staff list (admins, operators): left empty on purpose, not a failure to build data. */
  staffList?: boolean;
  /** Tenancy is carried by a JWT claim (the name here), which tenantbleed does not mint: the table is
   * tenant-scoped but could not be attacked, so it is not "shared" and not a silent gap. */
  jwtScoped?: string;
  /** Functions: the API reached it and every call failed inside it (a table its body reads is gone). */
  broken?: string;
  /** Functions: the owner control call. When an attack call found nothing, the same calls were made by
   * the rightful owner: "guarded" if the owner's call changed or returned their data (so the function
   * checks the caller), "no-effect" if it did nothing for the owner either (the test values missed),
   * "secret-gated" if it looks things up by a secret value and answered only to the victim's own value. */
  ownerControl?: "guarded" | "no-effect" | "secret-gated" | "victim-independent";
  /** What the owner's call did, for the report ("changed 1 of their rows: notes ...: body"). */
  ownerDetail?: string;
  /** Functions: calls refused with "permission denied", and one such message. */
  refused?: number;
  refusedMessage?: string;
}

export interface ScanResult {
  stack: string;
  /** The app and version scanned. */
  target?: ScanTarget;
  startedAt: string;
  durationMs: number;
  tenants: string[];
  relationsScanned: number;
  functionsScanned: number;
  findings: Finding[];
  coverage: CoverageRow[];
  notes: string[];
  /** False when a probe stopped early or the scan aborted. */
  complete: boolean;
  /** Rightful-owner operations (only with the owner check, used to verify fixes). */
  ownerAccess?: { relation: string; actor: string; role?: string; op: string; ok: boolean; detail?: string }[];
  /** Supabase linter (splinter) warnings, each labeled with what the scan showed. */
  triage?: Triage;
  /** Test-data steps and argument strategies the scan used, counted (src/core/trace.ts). */
  trace?: TraceRow[];
}

export type Verdict = "proven" | "flagged" | "tested" | "locked" | "shared" | "no-api" | "not-callable" | "extension" | "not-tested";

export interface TriageRow {
  lint: string;
  title: string;
  level: string;
  target: string;
  /** True for lints raised once per function or table regardless of a specific mistake. */
  inventory: boolean;
  verdict: Verdict;
  /** Which triage branch decided the verdict ("triage/function-owner-control-settled"). */
  rule: string;
  /** Proven or static findings on the same target. */
  findings: string[];
  reason: string;
  /** For warnings the scan could neither prove nor clear: a plain-English prompt to check it yourself. */
  checkPrompt?: string;
}

export interface Triage {
  ran: boolean;
  error?: string;
  /** All warnings splinter raised. */
  total: number;
  /** Warnings about performance or hygiene, which tenantbleed does not test. */
  other: number;
  rows: TriageRow[];
  /** Proven findings (medium or worse) on targets no linter warning names. */
  unflagged: string[];
}

/** One raw splinter row, as the engine collects it. */
export interface LintRow {
  name: string;
  title: string;
  level: string;
  metadata: Record<string, unknown> | null;
}
