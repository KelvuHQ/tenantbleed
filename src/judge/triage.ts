// Linter triage: label each data-access warning from Supabase's linter with what the scan actually
// showed for that table, function or bucket. Proven warnings come first, with the finding that
// proves them; the rest say why they were not exploitable or could not be tested.

import type { Finding } from "../core/findings.js";
import { checkPrompt } from "./check-prompts.js";
import { timeMaintenance } from "./observations.js";
import type { CoverageRow, LintRow, Triage, TriageRow, Verdict } from "../core/scan-result.js";
import type { Schema } from "../supabase/introspect.js";

/** Static rules that describe a risk on their own (anyone can write auth.users), not a missing check. */
export const DEFINITE_SCHEMA_RISK = new Set(["static/auth-writer", "static/definer-http", "static/definer-vault", "static/definer-exec-arg", "static/definer-security-ddl"]);

/** Lints that claim someone can reach data they should not. The rest are performance or hygiene. */
const ACCESS_LINTS = new Set([
  "rls_disabled_in_public",
  "policy_exists_rls_disabled",
  "rls_enabled_no_policy",
  "rls_policy_always_true",
  "security_definer_view",
  "sensitive_columns_exposed",
  "auth_users_exposed",
  "rls_references_user_metadata",
  "public_bucket_allows_listing",
  "materialized_view_in_api",
  "foreign_table_in_api",
  "pg_graphql_anon_table_exposed",
  "pg_graphql_authenticated_table_exposed",
  "anon_dynamic_sql_function_executable",
  "authenticated_dynamic_sql_function_executable",
  "anon_security_definer_function_executable",
  "authenticated_security_definer_function_executable",
]);

/** One warning per function or table, whether or not anything is wrong: listed apart. */
const INVENTORY = new Set([
  "anon_security_definer_function_executable",
  "authenticated_security_definer_function_executable",
  "pg_graphql_anon_table_exposed",
  "pg_graphql_authenticated_table_exposed",
]);

const targetOf = (l: LintRow): string => {
  const m = (l.metadata ?? {}) as Record<string, string>;
  if (l.name === "public_bucket_allows_listing") return `bucket:${m.bucket_id ?? m.name ?? "?"}`;
  return `${m.schema ?? "public"}.${m.name ?? "?"}`;
};

const SEV = ["critical", "high", "medium", "low", "info"];

export function triage(lints: LintRow[], triggerFunctions: string[], schema: Schema, findings: Finding[], coverage: CoverageRow[], extensionObjects: Record<string, string> = {}): Triage {
  const cov = new Map(coverage.map((c) => [c.relation, c]));
  const triggers = new Set(triggerFunctions);
  const rows: TriageRow[] = [];
  let other = 0;
  for (const l of lints) {
    if (!ACCESS_LINTS.has(l.name)) {
      other++;
      continue;
    }
    const target = targetOf(l);
    const proven = findings.filter((f) => f.confidence === "proven" && f.target === target).sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
    // Info-level schema notes are reassurance ("checks the caller"), not a risk.
    const stat = findings.filter((f) => f.confidence === "static" && f.target === target && f.severity !== "info");
    const info = findings.filter((f) => f.confidence === "static" && f.target === target && f.severity === "info");
    // Schema findings that are a risk by themselves, whatever a call shows (src/judge/static.ts).
    const definite = stat.filter((f) => DEFINITE_SCHEMA_RISK.has(f.rule));
    const also = info.length ? ` Schema check: ${info.map((f) => f.title).join("; ")}.` : "";
    const fn = schema.functions.find((f) => `${f.schema}.${f.name}` === target);
    const rel = schema.relations.find((r) => `${r.schema}.${r.name}` === target);
    const isFunction = /function/.test(l.name) || !!fn || triggers.has(target);
    const c = cov.get(target);
    let verdict: Verdict;
    let reason: string;
    let rule: string;
    if (proven.length) {
      verdict = "proven";
      rule = "triage/proven";
      reason = `Exploited: ${proven.map((f) => `${f.id} (${f.severity})`).join(", ")}.`;
    } else if (extensionObjects[target]) {
      verdict = "extension";
      rule = "triage/extension";
      reason = `Part of the ${extensionObjects[target]} extension, not the app's own code. Install extensions in the extensions schema to keep them out of the API.`;
    } else if (rel?.partitionOf) {
      // PostgREST serves a partitioned table as its parent, so a leaf's own warning cannot be reached
      // from a browser (the read sweep confirmed it: it answered 404). Fix the policy on the parent.
      verdict = "no-api";
      rule = "triage/table-not-served";
      reason = `A partition of ${rel.partitionOf}, which the API serves only as its parent (the leaf itself answered 404/406). Fix the policy on ${rel.partitionOf}, not on each partition.`;
    } else if (isFunction && triggers.has(target)) {
      verdict = "not-callable";
      rule = "triage/function-trigger";
      reason = "Trigger function: the API cannot call it directly.";
    } else if (isFunction && fn && !fn.volatile && ["boolean", "void"].includes(fn.returnType)) {
      verdict = "not-callable";
      rule = "triage/function-yes-no-helper";
      reason = "Read-only yes/no helper: returns no data to leak, so it is not called.";
    } else if (isFunction && fn && fn.args.some((a) => !a.name || /^arg\d+$/.test(a.name))) {
      verdict = "not-callable";
      rule = "triage/function-unnamed-args";
      reason = "Unnamed arguments: the API cannot call it with arguments.";
    } else if (isFunction) {
      const schemaNote = stat.length ? ` Schema check: ${stat.map((f) => f.title).join("; ")}.` : also;
      if (c?.broken && c.reached === 0) {
        verdict = "not-callable";
        rule = "triage/function-broken";
        reason = `Every call failed inside the function (${c.broken}): it uses something the app's migrations do not create, so it cannot hand out or change anyone's data as the schema stands.`;
      } else if (c?.ownerControl === "guarded") {
        // The same call worked for the rightful owner and did nothing for anyone else.
        verdict = "tested";
        rule = "triage/function-owner-control-settled";
        reason = `Called with other users' ids: nothing leaked or changed. Owner control: the same call made by the owner ${c.ownerDetail ?? "worked"}, so the function tells callers apart.${schemaNote}`;
      } else if (definite.length) {
        // The schema alone shows the risk (anyone can create login accounts): no call needs to.
        verdict = "flagged";
        rule = "triage/function-schema-risk";
        reason = `No call showed it, but the schema check shows a risk on its own: ${definite.map((f) => f.title).join("; ")}.`;
      } else if (c?.ownerControl === "secret-gated") {
        verdict = "tested";
        rule = "triage/function-secret-gated";
        reason = `Looks things up by a secret value: it ${c.ownerDetail ?? "answered only to the exact value"}. That is how a share link or invite code works; it is only as safe as the value is long and random.${schemaNote}`;
      } else if (c?.ownerControl === "victim-independent") {
        // Nothing to aim at another user, and the answer is the same whether their rows exist or not.
        verdict = "tested";
        rule = "triage/function-victim-independent";
        reason = `Takes nothing that points at another user, and it ${c.ownerDetail ?? "gave the same answer with and without other users' rows"}, so its answer does not depend on anyone else's data.${schemaNote}`;
      } else if (c && c.reached > 0 && c.ownerControl === "no-effect" && timeMaintenance(fn)) {
        // Nothing changed for anyone because the test rows are new; the body says why that is safe.
        verdict = "tested";
        rule = "triage/function-time-maintenance";
        reason = `Maintenance by age: it only changes rows past a time limit and takes no argument that picks a user (at most a batch size or a retention period), so a caller can at most run it early. The scan's rows are new, so the call changed nothing.${schemaNote}`;
      } else if (c && c.reached > 0 && stat.length && c.ownerControl === "no-effect") {
        verdict = "not-tested";
        rule = "triage/function-owner-control-no-effect";
        reason = `Called with other users' ids and nothing happened, but the owner's own call with the same values did nothing either, so the test values did not reach its data.${schemaNote}`;
      } else if (c && c.reached > 0) {
        verdict = stat.length ? "flagged" : "tested";
        rule = stat.length ? "triage/function-flagged" : "triage/function-tested";
        reason = stat.length ? `Called with other users' ids; no leak proven, but the schema check flags it: ${stat.map((f) => f.title).join("; ")}.` : `Called with other users' ids: no other user's data came back and nothing changed.${also}`;
      } else if (c?.notExposed) {
        verdict = "no-api";
        rule = "triage/function-not-served";
        reason = `In schema ${target.split(".")[0]}, which the API does not expose; filled only so functions could be called.`;
      } else if (c && c.unreachable > 0) {
        verdict = "no-api";
        rule = "triage/function-not-served";
        reason = "The API does not serve it (404/406).";
      } else if (c?.refused && /permission denied for (?:function|schema|table|view|materialized view|sequence|relation)\s+"?([\w.]+)"?/i.test(c.refusedMessage ?? "")) {
        // The database, not the app, refuses it: it uses an object the API roles have no rights on,
        // so nobody can call it from a browser. (A bare "permission denied" or a 42501 the app RAISEs
        // is the app's own check and stays not-tested, settled by owner control.)
        const obj = /permission denied for (?:function|schema|table|view|materialized view|sequence|relation)\s+"?([\w.]+)"?/i.exec(c.refusedMessage ?? "")![1];
        verdict = "not-callable";
        rule = "triage/function-no-execute-right";
        reason = `The database refuses it to the API roles: it uses ${obj}, which they have no rights on. Nobody can call it from a browser.`;
      } else if (c?.refused) {
        verdict = "not-tested";
        rule = "triage/function-refused-for-everyone";
        reason = `Every call was refused (${c.refusedMessage ?? "permission denied"}), the owner's own call included, so a caller check cannot be told from test values the app does not accept.${schemaNote}`;
      } else {
        verdict = "not-tested";
        rule = fn ? "triage/function-not-called" : "triage/function-outside-scan";
        reason = fn ? "Not called: tenantbleed could not build its arguments from the test data." : "Not in the scanned schemas.";
      }
    } else if (l.name === "rls_enabled_no_policy") {
      verdict = "locked";
      rule = "triage/table-locked";
      reason = "RLS is on with no policies, so the API returns nothing to anyone. Fine if only the backend uses it.";
    } else if (!c) {
      verdict = stat.length ? "flagged" : "not-tested";
      rule = stat.length ? "triage/table-flagged-not-reached" : "triage/table-not-reached";
      reason = stat.length ? stat.map((f) => f.title).join("; ") : "Not reached by the scan (not in the scanned schemas, or not a table the API serves).";
    } else if (c.notExposed) {
      verdict = "no-api";
      rule = "triage/table-not-served";
      reason = `In schema ${target.split(".")[0]}, which the API does not expose; filled only so functions could be called.`;
    } else if (c.shared) {
      verdict = "shared";
      rule = "triage/table-shared";
      reason = "Shared by design: no path from its rows to a user (or listed as shared in tenantbleed.json), so everyone seeing it is expected.";
    } else if (!c.populated) {
      verdict = "not-tested";
      rule = "triage/table-no-test-data";
      reason = `Could not create test data: ${c.reason ?? "unknown"}.`;
    } else if (c.reached === 0 && c.unreachable > 0) {
      verdict = "no-api";
      rule = "triage/table-not-served";
      reason = "The API does not serve it (404/406).";
    } else if (c.reached === 0) {
      verdict = "no-api";
      rule = "triage/table-no-api-role";
      reason = "No API role has access to it.";
    } else if (stat.length) {
      verdict = "flagged";
      rule = "triage/table-flagged";
      reason = `Attacked as two test users and anonymously; nothing proven, but the schema check flags it: ${stat.map((f) => f.title).join("; ")}.`;
    } else {
      verdict = "tested";
      rule = "triage/table-tested";
      reason = `Attacked as two test users and anonymously: no access to other users' rows was proven.${also}`;
    }
    const checkPromptText = verdict === "flagged" || verdict === "not-tested" ? checkPrompt({ lint: l.name, target, verdict, reason, fn }) : undefined;
    rows.push({ lint: l.name, title: l.title, level: l.level, target, inventory: INVENTORY.has(l.name), verdict, rule, findings: (proven.length ? proven : [...stat, ...info]).map((f) => f.id).sort(), reason, ...(checkPromptText ? { checkPrompt: checkPromptText } : {}) });
  }
  const flaggedTargets = new Set(rows.map((r) => r.target));
  const unflagged = findings.filter((f) => f.confidence === "proven" && ["critical", "high", "medium"].includes(f.severity) && !flaggedTargets.has(f.target)).map((f) => f.id);
  return { ran: true, total: lints.length, other, rows, unflagged };
}
