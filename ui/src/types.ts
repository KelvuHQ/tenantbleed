// A UI-facing subset of the engine's ScanResult contract (src/core). The server returns these
// shapes as JSON; kept narrow to what the screens render.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Evidence {
  actor: string;
  victim?: string;
  request: { method: string; path: string; body?: unknown };
  status: number;
  proof: string;
  curl: string;
  via?: string[];
}

export interface Finding {
  id: string;
  kind: string;
  severity: Severity;
  target: string;
  title: string;
  detail: string;
  confidence: "proven" | "static";
  evidence?: Evidence;
  fix?: string;
  rule: string;
  fingerprint?: string;
  location?: { file: string; line: number; what: string }[];
  data?: { columns: string[]; classes: string[] };
  standards?: { owasp: string[]; cwe: string[] };
}

export interface CoverageRow {
  relation: string;
  kind: "table" | "view" | "function" | "bucket";
  reached: number;
  unreachable: number;
  populated: boolean;
  shared?: boolean;
  reason?: string;
  notExposed?: boolean;
  staffList?: boolean;
  jwtScoped?: string;
  broken?: string;
  ownerControl?: "guarded" | "no-effect" | "secret-gated" | "victim-independent";
  ownerDetail?: string;
  refused?: number;
  refusedMessage?: string;
}

export type Verdict = "proven" | "flagged" | "tested" | "locked" | "shared" | "no-api" | "not-callable" | "extension" | "not-tested";

export interface TriageRow {
  lint: string;
  title: string;
  level: string;
  target: string;
  inventory: boolean;
  verdict: Verdict;
  rule: string;
  findings: string[];
  reason: string;
  checkPrompt?: string;
}

export interface Triage {
  ran: boolean;
  error?: string;
  total: number;
  other: number;
  rows: TriageRow[];
  unflagged: string[];
}

export interface ScanTarget {
  name: string;
  commit?: string;
  branch?: string;
  dirty?: boolean;
  tool: string;
}

export interface ScanResult {
  stack: string;
  target?: ScanTarget;
  startedAt: string;
  durationMs: number;
  tenants: string[];
  relationsScanned: number;
  functionsScanned: number;
  findings: Finding[];
  coverage: CoverageRow[];
  notes: string[];
  complete: boolean;
  triage?: Triage;
}

export interface Fix {
  id: string;
  closes: string[];
  target: string;
  template: string;
  title: string;
  sql: string;
}

export interface Skipped {
  finding: string;
  title: string;
  severity: Severity;
  reason: string;
}

export interface FixesResponse {
  fixes: Fix[];
  skipped: Skipped[];
  prompts: Record<string, string>;
}

export interface TargetInfo {
  hasLocalProject: boolean;
  workdir: string;
  name?: string;
  exposedSchemas?: string[];
}

export interface ProjectCandidate {
  name?: string;
  workdir: string;
}

export interface ProgressEvent {
  step: string;
  done: number;
  total: number;
}
