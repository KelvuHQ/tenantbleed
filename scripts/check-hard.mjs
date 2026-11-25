// Gate for fixtures/supabase-hard: the shapes the field test could not settle, fixed false alarms,
// the owner control, and the rule and strategy coverage cases. Each planted bug must be proven (on
// the side named), every table must be filled with test data, and the controls must stay clean.
// Extra findings on planted objects (the other side, a second attack) are fine.
import { gate, loadReport, provenOf, standardChecks, triageRows } from "./lib/fixture-gate.mjs";

const expected = {
  "A1 an excluded-user argument (args/excluded-id)": ["rpc-write public.notify_org_members tenant"],
  "D1 a count about another organization (rpc-leak/derived-value)": ["rpc-leak public.org_headcount tenant", "rpc-leak public.org_headcount anon"],
  "D2 a visitor learns a count (rpc-leak/derived-value)": ["rpc-leak public.visitor_note_count anon"],
  "F2 time zone argument (args/well-known-format)": ["rpc-leak public.studio_day_report tenant"],
  "H1 JSON shape checks": ["cross-tenant-read public.agent_runs tenant"],
  "H2 number from a fixed list": ["cross-tenant-read public.audit_schedules tenant"],
  "H3 text arrays": ["cross-tenant-read public.user_prefs tenant"],
  "H4 ordered dates": ["cross-tenant-read public.period_reports tenant"],
  "H5 parents must agree": ["cross-tenant-read public.member_brands tenant"],
  "H7 hidden schema, write": ["rpc-write public.rename_account tenant"],
  "H7 hidden schema, read": ["rpc-leak public.list_accounts tenant"],
  "F1 argument named after its table": ["rpc-write public.generate_invoice tenant"],
  "F2 write behind a word": ["rpc-write public.increment_usage tenant"],
  "F3 shared configuration": ["rpc-write public.update_webhook_config anon"],
  "F4 counter on the right parent": ["rpc-write public.runs_increment_children tenant"],
  "R4 small amount first": ["rpc-write public.consume_daily_credits tenant"],
  "C3 a cached number the caller picks is a real write": ["rpc-write public.set_studio_usage tenant"],
  "E1 rows behind a trigger with its own error code": ["cross-tenant-read public.studio_bills tenant"],
  "J1 JSON keys pinned by a check rule": ["cross-tenant-read public.studio_layouts tenant"],
  "K1 a column a trigger copies elsewhere": ["cross-tenant-read public.studio_job_results tenant"],
  "D3 a count only a later id reveals (rpc-leak/derived-value)": ["rpc-leak public.job_result_count tenant"],
  "W1 a write found by an id and a text key of one row": ["rpc-write public.add_studio_minutes tenant"],
  "N1 a total that includes the victim's rows (rpc-leak/derived-value)": ["rpc-leak public.all_studio_session_total tenant"],
  "L1 tables linked both ways, parents built first": ["cross-tenant-read public.studio_offers tenant", "rpc-write public.recalc_offer_total tenant"],
  "P1 a write that waits for a row state (args/row-state)": ["rpc-write public.settle_studio_payout tenant", "rpc-write public.use_studio_credit tenant"],
  "K1 a text link to the parent survives short markers": ["cross-tenant-read public.studio_builds tenant"],
  "U1 arguments inserted straight into a table (args/insert-columns)": ["rpc-write public.bump_studio_usage tenant"],
  "R1 arguments from a row and its parent (args/row-parents)": ["rpc-write public.close_event_round tenant"],
  "W11 a row state checked in a SELECT before the write": ["rpc-write public.vote_studio_poll tenant"],
  "A1 a user makes themselves admin on their own row (self-escalation)": ["self-escalation public.member_profiles tenant", "self-escalation public.member_settings tenant"],
  "A2 an owner steps down to member and climbs back (self-escalation)": ["self-escalation public.studio_crew tenant"],
  "C1 a cycle through the profile table, built in order": ["cross-tenant-read public.crew_tasks tenant"],
  "O1 a circle of optional links over several tables, built in order": ["cross-tenant-read public.deck_cards tenant"],
  "T2 permission checked in the wrong organization": ["rpc-leak public.list_company_invitations_v1 tenant"],
};
const mustBeClean = ["public.org_reports", "public.svc_receipts", "public.studio_roster", "public.studio_chat", "public.settle_studio_flags", "public.delegate_studio_operator", "public.cast_round_vote", "public.bump_my_studio_usage", "public.cancel_studio_payout", "public.my_studio_total", "public.my_org_headcount", "public.org_seat_limit", "public.org_sample_size", "public.promote_to_admin", "public.unblock_user", "public.blocks", "public.register_device_token", "public.device_tokens", "public.close_account", "public.lookup_invite", "public.make_code", "public.shop_public_get", "public.shops", "public.invites", "public.brands", "public.list_company_invitations", "public.rename_note", "public.redeem_note_code", "public.get_note", "public.notes", "public.time_entry_start", "public.deactivate_note_member"];
const mustBeFilled = ["public.location_events", "public.agent_runs", "public.audit_schedules", "public.user_prefs", "public.period_reports", "public.member_brands", "public.location_events_2026_q1", "public.location_events_2026_q2", "ledger.accounts", "public.cheques", "public.email_receipts", "public.brand_facts", "public.asks", "public.brand_access", "acct.invitations", "public.note_suggestions", "public.studios", "public.studio_sessions", "public.studio_rates", "public.studio_hours", "public.studio_usage_cache", "public.studio_bills", "public.studio_strikes", "public.studio_layouts", "public.studio_jobs", "public.studio_job_results", "public.gl_accounts", "public.gl_entries", "public.metric_snapshots", "public.cash_entries", "public.cash_entry_notes", "public.addon_orders", "public.addon_grants", "public.studio_gigs", "public.studio_drafts", "public.studio_offers", "public.studio_payouts", "public.studio_credits", "public.studio_apps", "public.studio_builds", "public.studio_keys", "public.studio_usage", "public.studio_events", "public.event_rounds", "public.studio_polls", "public.member_settings", "public.member_profiles", "public.studio_flags", "public.studio_crew", "public.studio_roster", "public.studio_chat", "public.crew_teams", "public.crew_members", "public.crew_tasks", "public.crew_boards", "public.crew_notes", "public.crew_bindings", "public.crew_runs", "public.deck_cards", "public.deck_columns", "public.deck_stats", "public.deck_stat_logs", "public.label_tags", "public.label_links", "public.direct_chats", "public.svc_members", "public.svc_firms", "public.svc_firm_members", "public.svc_invoices", "public.svc_receipts", "public.svc_inbox", "public.orgs2", "public.org_memberships2", "public.org_events", "public.org_reports"];

const report = loadReport(process.argv[2]);
const g = gate();
const r = standardChecks(g, report, { expected, mustBeClean, mustBeFilled });
const proven = provenOf(report);
const findingsOn = (target) => proven.filter((f) => f.target === target);

// H6: the API (PostgREST) serves a partitioned table only as its parent, so the partitions' missing
// RLS cannot be reached from a browser: each leaf's warning is labelled "not served by the API"
// (verdict no-api) and its reason names the parent to fix, not the partition.
const partitions = ["public.location_events_2026_q1", "public.location_events_2026_q2"];
g.check(
  partitions.every((p) => triageRows(report, p).length && triageRows(report, p).every((x) => x.verdict === "no-api" && /partition of public\.location_events\b/.test(x.reason))),
  "H6 quarterly partitions labelled as partitions of their parent",
  partitions.map((p) => `${p} ${triageRows(report, p).map((x) => `${x.verdict}:${x.reason.slice(0, 40)}`).join("/") || "no warning"}`).join("; "),
);

// Found, but only as low: a recount, an id-only answer, seeding defaults, scheduled jobs. From R8 on
// the case must also be found, so a scan that misses it cannot pass.
for (const [name, target, mustFind] of [
  ["R3 recount stays low", "public.compute_analytics_snapshot", false],
  ["R6 id-only answer stays low", "public.member_id_if_allowed", false],
  ["R7 seeding defaults stays low", "public.seed_core_workflow_templates", false],
  ["R8 expired cleanup stays low", "public.cleanup_expired_platform_sessions", true],
  ["R9 scheduled reminder job stays low", "public.notify_due_cheques", true],
  ["R10 demo bootstrap stays low", "public.bootstrap_demonstration_org", true],
  ["C1 a cache refreshed from the owner's own data stays low", "public.studio_usage_fits", true],
  ["C2 a cache entry dropped stays low", "public.forget_studio_usage", true],
]) {
  const fs = findingsOn(target);
  const bad = fs.filter((f) => f.severity !== "low");
  g.check(!bad.length && (!mustFind || fs.length > 0), name, bad.length ? `reported ${bad.map((f) => f.severity).join("/")}` : "not found at all");
}
// Q1 to Q3: SQL text from the caller, run as the owner. Found by the schema alone, critical, and
// flagged in the linter rows; never for a statement whose caller values are quoted or bound.
const staticOn = (target, rule) => (report.findings ?? []).filter((f) => f.target === target && f.rule === rule);
for (const [name, target] of [["Q1 the caller's text runs as SQL", "public.run_admin_sql"], ["Q2 the caller's text glued into SQL", "public.count_where"]]) {
  const fs = staticOn(target, "static/definer-exec-arg");
  const rows = triageRows(report, target);
  g.check(fs.length > 0 && fs.every((f) => f.severity === "critical") && rows.length > 0 && rows.every((x) => x.verdict === "flagged" && x.rule === "triage/function-schema-risk"), name, `${fs.map((f) => f.severity).join("/") || "no finding"}; ${rows.map((x) => x.verdict).join("/")}`);
}
g.check(!staticOn("public.count_rows_in", "static/definer-exec-arg").length, "Q3 quoted and bound values are not SQL from the caller", "reported");
// Q4 to Q6: switching isolation off for any caller; never behind a caller check.
for (const [name, target] of [["Q4 any caller turns row level security off", "public.toggle_rls_for_tests"], ["Q5 any caller drops a policy", "public.reset_policy_for_tests"]]) {
  const fs = staticOn(target, "static/definer-security-ddl");
  const rows = triageRows(report, target);
  g.check(fs.length > 0 && fs.every((f) => f.severity === "critical") && rows.length > 0 && rows.every((x) => x.verdict === "flagged" && x.rule === "triage/function-schema-risk"), name, `${fs.map((f) => f.severity).join("/") || "no finding"}; ${rows.map((x) => x.verdict).join("/")}`);
}
g.check(!staticOn("public.operator_toggle_rls", "static/definer-security-ddl").length, "Q6 the same switch behind a caller check is not flagged", "reported");
// R11: an amount the caller picks on a shared daily quota is not a scheduled job: never low.
const r11 = findingsOn("public.consume_api_credit");
g.check(r11.length > 0 && r11.every((f) => f.severity !== "low"), "R11 shared quota amount stays medium or high", r11.map((f) => f.severity).join("/") || "not found");
const c3 = findingsOn("public.set_studio_usage");
g.check(c3.length > 0 && c3.every((f) => f.severity !== "low"), "C3 a cached number the caller picks stays high", c3.map((f) => f.severity).join("/") || "not found");

// T1, T2 and O1 to O4: what the linter warning ends up as. Settled ones must be "tested", with the
// owner control in the reason where it settled them; O2 needs a code nobody can guess, so even the
// owner's call does nothing and the honest answer is "not-tested", saying why.
for (const [name, target, ok] of [
  ["T1 binary key does not stop the calls", "public.time_entry_start", (x) => x.verdict !== "not-tested"],
  ["T2 permission model: the owner's call works", "public.list_company_invitations", (x) => x.verdict === "tested"],
  ["O1 guarded write settled by the owner's call", "public.rename_note", (x) => x.verdict === "tested" && /owner/i.test(x.reason)],
  ["O2 values nobody can guess: honest not-tested", "public.redeem_note_code", (x) => x.verdict === "not-tested" && /owner/i.test(x.reason)],
  ["O3 guarded read settled by the owner's call", "public.get_note", (x) => x.verdict === "tested" && /owner/i.test(x.reason)],
  ["O4 the owner gets past the check, the attacker does not", "public.deactivate_note_member", (x) => x.verdict === "tested" && /owner/i.test(x.reason)],
  ["A2 a definite schema risk is flagged even when no call shows it", "public.create_login", (x) => x.verdict === "flagged" && x.rule === "triage/function-schema-risk"],
  ["M1 maintenance by age, no arguments", "public.cleanup_expired_access_keys", (x) => x.verdict === "tested" && x.rule === "triage/function-time-maintenance"],
  ["M2 maintenance by age, retention arguments", "public.reap_stale_access_keys", (x) => x.verdict === "tested" && x.rule === "triage/function-time-maintenance"],
  ["S1 share link by slug", "public.get_shared_doc", (x) => x.verdict === "tested" && x.rule === "triage/function-secret-gated"],
  ["S2 invite by code", "public.check_invite_value", (x) => x.verdict === "tested" && x.rule === "triage/function-secret-gated"],
  ["N2 an answer that never depends on other users' rows is tested", "public.my_studio_total", (x) => x.verdict === "tested" && x.rule === "triage/function-victim-independent"],
  ["P2 a guarded write that waits for a row state is tested", "public.cancel_studio_payout", (x) => x.verdict === "tested" && /owner/i.test(x.reason)],
  ["U2 a guarded upsert is tested", "public.bump_my_studio_usage", (x) => x.verdict === "tested" && /owner/i.test(x.reason)],
  ["R2 a vote by join code, with ids from the round, is settled as secret-gated", "public.cast_round_vote", (x) => x.verdict === "tested" && x.rule === "triage/function-secret-gated"],
  ["G1 an operator-only function behind a delegation gate is tested", "public.settle_studio_flags", (x) => x.verdict === "tested" || x.verdict === "locked"],
  ["B1 a function whose table was dropped is settled as broken", "public.crew_archive_counts", (x) => x.verdict === "not-callable" && x.rule === "triage/function-broken"],
  ["X1 HTTP with a service role key is flagged", "public.remove_stored_file", (x) => x.verdict === "flagged" && x.rule === "triage/function-schema-risk"],
  ["X2 a vault secret handed out is flagged", "public.app_base_url", (x) => x.verdict === "flagged" && x.rule === "triage/function-schema-risk"],
]) {
  const rows = triageRows(report, target);
  g.check(rows.length > 0 && rows.every(ok), name, rows.map((x) => `${x.verdict} (${x.reason.slice(0, 90)})`).join("; ") || "no linter warning");
}
// Solved, not forced: these rows must satisfy the app's rules, never be written with them paused.
const paused = new Set((report.trace ?? []).find((t) => t.id === "row/rules-paused")?.examples ?? []);
for (const t of ["public.metric_snapshots", "public.gl_accounts", "public.studios", "public.cash_entries", "public.studio_layouts", "public.studio_job_results", "public.studio_offers"]) g.check(!paused.has(t), `${t} built within the app's rules`, "written with the rules paused");
for (const t of ["public.studio_delegates", "public.platform_operators"]) {
  const rows = triageRows(report, t);
  const cov = (report.coverage ?? []).find((c) => c.relation === t);
  g.check((cov && cov.staffList === true) || rows.some((x) => x.rule === "triage/table-staff-list"), `ST1 ${t} is reported as an app-wide staff list, not a gap`, JSON.stringify(cov ?? rows.map((x)=>x.rule)));
}
const skipped = (report.notes ?? []).filter((n) => /rpc probe skipped/.test(n));
g.check(!skipped.length, "no function probe stopped on an error", skipped.map((n) => n.slice(0, 140)).join("; "));

// Spec 03: a table/function in a schema the API does not expose is "not exposed", not a gap.
const cov = (t) => report.coverage.find((c) => c.relation === t);
g.check(cov("hidden_vault.secrets")?.notExposed === true, "NE1 a table in a non-exposed schema is marked not-exposed", JSON.stringify(cov("hidden_vault.secrets") ?? "no row"));
g.check(triageRows(report, "public.my_secret_count").some((x) => x.verdict === "no-api" || x.verdict === "tested"), "NE2 the wrapping function is served (public)", triageRows(report, "public.my_secret_count").map((x) => x.verdict).join("/") || "none");
// Spec 15: a unique text default does not block the second tenant; the child is filled for both.
const unique = new Set((report.trace ?? []).find((t) => t.id === "value/unique-default-filled")?.examples ?? []);
g.check(provenOf(report).some((f) => f.kind === "cross-tenant-read" && f.target === "public.svc_invoices"), "PF1 a table under a no-FK user table is attacked (policy profile)", provenOf(report).filter((f)=>f.target==="public.svc_invoices").map((f)=>f.kind).join(",")||"none");
g.check(provenOf(report).some((f) => f.kind === "cross-tenant-read" && f.target === "public.org_events"), "PL1 a no-FK tenant column scoped via a membership subquery is owned and attacked", provenOf(report).filter((f)=>f.target==="public.org_events").map((f)=>f.kind).join(",")||"none");
g.check((report.notes ?? []).some((n) => /org_events\.org_id has no foreign key; it was linked to/.test(n)), "PL2 the inferred policy link is noted", "no link note");
{
  const f = report.findings ?? [];
  g.check(f.some((x) => x.rule === "static/shared-open-write" && x.target === "public.shared_contacts" && x.severity === "medium"), "SO1 a shared table open to every signed-in writer gets a line", f.filter((x)=>x.target==="public.shared_contacts").map((x)=>x.rule+"/"+x.severity).join(",")||"none");
  g.check(f.some((x) => x.rule === "static/shared-anon-read" && x.target === "public.shared_leads"), "SO2 a shared table a visitor can read, with contact columns, gets a line", f.filter((x)=>x.target==="public.shared_leads").map((x)=>x.rule).join(",")||"none");
  g.check(f.some((x) => x.rule === "static/shared-open-write" && x.target === "public.shared_guestbook" && x.severity === "high"), "SO4 a shared table a visitor can write gets a high line", f.filter((x)=>x.target==="public.shared_guestbook").map((x)=>x.rule+"/"+x.severity).join(",")||"none");
  g.check(!f.some((x) => /shared-open|shared-anon/.test(x.rule ?? "") && x.target === "public.shared_regions"), "SO3 a read-only public catalog with no personal columns gets no shared line", f.filter((x)=>x.target==="public.shared_regions"&&/shared-/.test(x.rule||"")).map((x)=>x.rule).join(","));
}
g.check(provenOf(report).some((f) => f.kind === "cross-tenant-read" && f.target === "public.svc_inbox"), "PF2 a no-FK person column makes the row owned, so the other tenant reading it is a leak", provenOf(report).filter((f)=>f.target==="public.svc_inbox").map((f)=>f.kind).join(",")||"none");
g.check(provenOf(report).some((f) => f.kind === "cross-tenant-read" && f.target === "public.direct_chats"), "TP1 a two-party chat built with a bystander is attacked by the other tenant", provenOf(report).filter((f)=>f.target==="public.direct_chats").map((f)=>f.kind).join(",")||"none");
g.check(unique.has("public.label_tags"), "UD1 a unique text default column is filled per tenant", "value/unique-default-filled not traced on label_tags");

const solved = g.total - (g.failed - r.falsePositives - r.unfilled);
g.done(`hard cases: ${solved} of ${g.total} solved, ${r.falsePositives} false positives, ${r.unfilled} tables without test data`);
