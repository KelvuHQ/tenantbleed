import type { Finding } from "../core/findings.js";
import type { JudgeInput } from "../core/judge-input.js";
import type { ScanResult } from "../core/scan-result.js";
import { addReportContext } from "./context.js";
import { judgeObservations } from "./observations.js";
import { downgradeSeedOnly, explainDefaultGrants, restrictedOnlyInIntent } from "./repo-rules.js";
import { sharedOpenChecks, staticChecks } from "./static.js";
import { triage } from "./triage.js";

export type { JudgeInput };

const BETWEEN_USERS = new Set(["cross-tenant-read", "cross-tenant-update", "cross-tenant-delete", "cross-tenant-insert", "cross-tenant-reparent", "view-leak", "rpc-leak", "rpc-write"]);

/**
 * Single-workspace apps (a company intranet, a team tool with one workspace) share data between
 * every signed-in user on purpose. With "tenancy": "single", user-to-user findings drop to low and
 * only what an outsider can do keeps its severity. Without the setting, say when the scan looks
 * like that case instead of guessing.
 */
function singleWorkspace(findings: Finding[], coverage: { kind: string; shared?: boolean; populated: boolean; reached: number }[], tenancy: string | undefined, notes: string[]): Finding[] {
  const isBetweenUsers = (f: Finding) => BETWEEN_USERS.has(f.kind) && f.evidence?.actor !== "anon";
  if (tenancy === "single")
    return findings.map((f) =>
      isBetweenUsers(f)
        ? { ...f, alsoRules: [...(f.alsoRules ?? []), "modifier/single-workspace"], severity: "low", detail: `${f.detail} tenantbleed.json declares a single-workspace app, so other signed-in users are coworkers: reported as low.` }
        : f,
    );
  const tables = coverage.filter((c) => c.kind === "table" && !c.shared && c.populated && c.reached > 0).length;
  const readable = new Set(findings.filter((f) => f.kind === "cross-tenant-read" && isBetweenUsers(f)).map((f) => f.target)).size;
  if (tenancy !== "multi" && tables >= 5 && readable / tables >= 0.6)
    // rule: note/single-workspace-heads-up
    notes.unshift(
      `Heads-up: ${readable} of ${tables} tables are readable by every signed-in user. If this is a single-workspace app (everyone who can sign in is a coworker), add "tenancy": "single" to tenantbleed.json: user-to-user findings then drop to low and outsider access keeps its severity. Add "tenancy": "multi" to silence this note.`,
    );
  return findings;
}

/**
 * A static "this policy is unconditional" finding that no probe could exploit is latent:
 * another policy (usually SELECT) masks it today. Say so instead of crying wolf.
 */
function downgradeLatent(statics: Finding[], proven: Finding[]): Finding[] {
  return statics.map((f) => {
    // A constant-true helper opens SELECT too, so it is never merely latent: do not downgrade it.
    if (f.rule === "static/policy-helper-always-true") return f;
    const m = /\((UPDATE|DELETE|ALL),/.exec(f.title);
    if (!m) return f;
    const kinds = m[1] === "UPDATE" ? ["cross-tenant-update", "cross-tenant-reparent"] : m[1] === "DELETE" ? ["cross-tenant-delete"] : ["cross-tenant-update", "cross-tenant-delete", "cross-tenant-reparent"];
    if (proven.some((p) => p.target === f.target && kinds.includes(p.kind))) return f;
    return {
      ...f,
      alsoRules: [...(f.alsoRules ?? []), "modifier/latent"],
      severity: "low",
      title: `${f.title} (latent)`,
      detail: `${f.detail} Not exploitable in this scan: other policies (usually SELECT) hide other tenants' rows, and Postgres re-checks the new row. It becomes exploitable the day SELECT is loosened.`,
    };
  });
}

export function judge(input: JudgeInput): ScanResult {
  const notes = [...input.notes];
  // A relation or function whose schema the API does not expose was filled only so functions could be
  // called; the API never serves it, so it is "not exposed", not a coverage gap. (A 406/PGRST106 from
  // the probe is the ground truth; the schema list agrees.)
  const exposed = new Set(input.exposed);
  const coverage = input.coverage.map((c) => (exposed.has(c.relation.split(".")[0]) ? c : { ...c, notExposed: true }));
  const result: ScanResult = {
    stack: input.stack,
    startedAt: input.startedAt,
    durationMs: input.durationMs,
    tenants: input.tenants,
    relationsScanned: input.schema.relations.length,
    functionsScanned: input.schema.functions.length,
    findings: [],
    coverage,
    notes,
    complete: false,
  };
  if (input.target) result.target = input.target;
  if (input.ownerAccess) result.ownerAccess = input.ownerAccess;
  if (input.trace) result.trace = input.trace;
  let proven = singleWorkspace(judgeObservations(input.schema, input.world, input.observations), input.coverage, input.hints.tenancy, notes);
  if (input.aborted) {
    result.findings = addReportContext(proven, input);
    return result;
  }
  const seedOnly = new Set(input.hints.seedOnly);
  proven = explainDefaultGrants(downgradeSeedOnly(proven, seedOnly), restrictedOnlyInIntent(input.hints.functionGrants));
  result.findings = addReportContext([...proven, ...downgradeSeedOnly(downgradeLatent(staticChecks(input.schema, new Set(input.exposed)), proven), seedOnly), ...sharedOpenChecks(input.schema, coverage)], input);
  const empty = !input.schema.relations.length && !input.schema.functions.length;
  result.complete = input.probesFinished && !empty;
  if (empty)
    notes.unshift(
      input.hints.migrationsDisabled
        ? "Nothing was scanned: supabase/config.toml sets [db.migrations] enabled = false, so the local database has no app tables. Enable migrations (or load the schema another way) and scan again."
        : `Nothing was scanned: the exposed schemas (${input.schemas.join(", ")}) have no tables, views or functions. Check that migrations ran on this stack.`,
    );
  if (input.lint)
    result.triage =
      "error" in input.lint
        ? { ran: false, error: input.lint.error, total: 0, other: 0, rows: [], unflagged: [] }
        : triage(input.lint.rows, input.lint.triggerFunctions, input.schema, result.findings, result.coverage, input.lint.extensionObjects ?? {});
  return result;
}

