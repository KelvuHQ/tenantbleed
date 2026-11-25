// Gate for fixtures/supabase-regress: real bugs from the 169-app field run, copied in the shape the
// apps shipped them. Each must be proven (on the side named), every table must be filled with test
// data, and the fixed twins (controls) must stay clean. Extra findings on the buggy objects are fine.
// A case the current engine cannot prove even though the copy is faithful goes in knownGaps with the
// reason: it is still reported, but does not fail the gate.
import { gate, loadReport, standardChecks } from "./lib/fixture-gate.mjs";

const expected = {
  "16 membership check anyone can ask about anyone (rpc-leak/derived-value)": ["rpc-leak public.is_team_member tenant", "rpc-leak public.is_team_member anon"],
  "1 owner check skipped for anon (set_artifact_password)": ["rpc-write public.set_artifact_password anon"],
  "2 visibility flip without caller check": ["rpc-write public.propagate_workspace_visibility_to_items tenant", "rpc-write public.propagate_workspace_visibility_to_items anon"],
  "3 shared-scope policy without role check": ["anon-read public.vault_secrets anon"],
  "4 service-role function left to anon by default grants": ["rpc-leak public.admin_revoke_agent_member anon", "rpc-write public.admin_revoke_agent_member anon"],
  "5a forged audit rows": ["rpc-write public.log_audit anon"],
  "5b invoice numbers for any tenant": ["rpc-write public.generate_invoice_number anon", "rpc-write public.generate_invoice_number tenant"],
  "6a caller-chosen monthly limit": ["rpc-write public.create_form_submission_if_allowed anon", "rpc-write public.create_form_submission_if_allowed tenant"],
  "6b storage counter for any workspace": ["rpc-write public.increment_storage_bytes anon", "rpc-write public.reserve_storage_if_allowed anon"],
  "7a notification for any tenant and user": ["rpc-write public.notify_user anon"],
  "7b owner-run report view": ["view-leak public.report_ziyaret tenant", "anon-read public.report_ziyaret anon"],
  "8 user id as argument (get_user_teams)": ["rpc-leak public.get_user_teams tenant", "rpc-leak public.get_user_teams anon"],
  "9a policy update by user id argument": ["rpc-leak public.memo_policy_update tenant", "rpc-leak public.memo_policy_update anon"],
  "9b policy delete by user id argument": ["rpc-write public.memo_policy_delete anon"],
  "10 runner upsert with caller ids": ["rpc-write public.upsert_run_verification anon", "rpc-write public.upsert_run_verification tenant"],
  "11 document notifier for any document": ["rpc-write public.create_document_action_notifications anon"],
  "12 own-profile update sets is_admin, which ten read policies trust (found 2026-11-21)": ["self-escalation public.profiles tenant"],
  "13 self-add as admin to anyone's team (found 2026-11-21)": ["self-enrollment public.gov_team_members tenant"],
  "14 bookings readable once the listing is live (found 2026-11-21)": ["cross-tenant-read public.stay_bookings tenant"],
};
// Cases the engine cannot prove yet although the fixture copies the app faithfully: name -> reason.
const knownGaps = {};
const mustBeClean = ["public.crew_squad_members", "public.set_artifact_password_safe", "public.admin_revoke_agent_member_locked", "public.generate_invoice_number_locked", "public.report_ziyaret_safe", "public.get_user_teams_safe"];
const mustBeFilled = ["public.artifacts", "public.todos", "public.collections", "public.collection_todos", "public.collection_artifacts", "public.vault_secrets", "public.teams", "public.team_members", "public.tenants", "public.audit_log", "public.invoice_sequences", "public.workspaces", "public.form_submissions", "public.visits", "public.notifications", "public.crews", "public.crew_members", "public.retention_policies", "public.run_verifications", "public.generated_documents"];

const g = gate();
{
  const rep = loadReport(process.argv[2]);
  const helper = (rep.findings ?? []).filter((f) => f.rule === "static/policy-helper-always-true");
  const sevs = new Set(helper.map((f) => f.severity));
  g.check(helper.some((f) => f.target === "public.svc_surveys") && sevs.has("high"), "16a a constant-true helper on an ALL policy is flagged high", helper.map((f) => `${f.target} ${f.severity}`).join(", ") || "none");
  g.check(helper.some((f) => f.target === "public.svc_reports") && sevs.has("medium"), "16b a constant-true helper on a SELECT policy is flagged medium");
}
{
  const rep = loadReport(process.argv[2]);
  const readState = (rep.findings ?? []).filter((f) => /^read-state/.test(f.rule ?? "") && f.target === "public.hall_bookings");
  g.check(readState.length === 0, "control hall_bookings has no state-read finding (its live policy is using(false))", readState.map((f) => f.rule).join(", "));
}
{
  // 09b step 1: a table scoped by a JWT claim is classified as tenant-scoped (claim named), not shared.
  const rep = loadReport(process.argv[2]);
  const c = (rep.coverage ?? []).find((x) => x.relation === "public.tenant_records");
  g.check(!!c && c.jwtScoped === "org_id", "09b JWT-claim tenancy is read from the policy (claim org_id)", JSON.stringify(c));
  g.check(!!c && c.shared !== true, "09b JWT-scoped table is not mislabelled shared", JSON.stringify(c));
}
const r = standardChecks(g, loadReport(process.argv[2]), { expected, knownGaps, mustBeClean, mustBeFilled });
const total = Object.keys(expected).length;
const solved = total - (g.failed - r.falsePositives - r.unfilled) - r.gaps;
g.done(`regress cases: ${solved} of ${total} proven, ${r.gaps} known gaps, ${r.falsePositives} false positives, ${r.unfilled} tables without test data`);
