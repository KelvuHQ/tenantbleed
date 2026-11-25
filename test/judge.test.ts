import assert from "node:assert/strict";
import { test } from "node:test";
import type { JudgeInput } from "../src/core/judge-input.js";
import { judge } from "../src/judge/index.js";
import { plantedInput } from "./helpers.js";

test("linter warnings on extension objects are labelled as the extension's, not as untested", () => {
  const input = JSON.parse(plantedInput) as JudgeInput;
  input.lint = {
    rows: [
      { name: "anon_security_definer_function_executable", title: "t", level: "WARN", metadata: { schema: "public", name: "st_estimatedextent" } },
      { name: "rls_disabled_in_public", title: "t", level: "ERROR", metadata: { schema: "public", name: "spatial_ref_sys" } },
      { name: "rls_disabled_in_public", title: "t", level: "ERROR", metadata: { schema: "public", name: "not_an_extension_table" } },
    ],
    triggerFunctions: [],
    extensionObjects: { "public.st_estimatedextent": "postgis", "public.spatial_ref_sys": "postgis" },
  };
  const rows = judge(input).triage!.rows;
  const by = Object.fromEntries(rows.map((r) => [r.target, r]));
  assert.equal(by["public.st_estimatedextent"].verdict, "extension");
  assert.match(by["public.spatial_ref_sys"].reason, /postgis extension/);
  assert.equal(by["public.not_an_extension_table"].verdict, "not-tested");
});

import { staticChecks } from "../src/judge/static.js";
import type { RpcFunction, Schema } from "../src/supabase/introspect.js";

const definer = (name: string, body: string, extra: Partial<RpcFunction> = {}): RpcFunction => ({
  schema: "public", name, args: [{ name: "p_org", type: "uuid" }], defaultedArgs: 0, body, volatile: true,
  securityDefiner: true, returnsSet: false, returnType: "jsonb", execAnon: false, execAuthenticated: true, ...extra,
});
const callerCheck = (fns: RpcFunction[], helpers: Record<string, string> = {}) => {
  const s: Schema = { relations: [], policies: [], functions: fns, helpers };
  return Object.fromEntries(staticChecks(s, new Set(["public"])).map((f) => [f.target, f.severity]));
};

test("caller checks are found through helpers, role settings and JWT claims", () => {
  const sev = callerCheck(
    [
      definer("via_helper", "perform private.require_admin(); update orgs set name = 'x' where id = p_org;"),
      definer("via_two_levels", "perform check_org(p_org); delete from things where org = p_org;"),
      definer("check_org", "perform private.require_admin();", { execAuthenticated: false }),
      definer("via_role", "if current_setting('role') <> 'service_role' then raise exception 'no'; end if;"),
      definer("via_claims", "select current_setting('request.jwt.claims', true)::jsonb ->> 'sub';"),
      definer("no_check", "update orgs set plan = 'free' where id = p_org;"),
      definer("count_behind_login", "select count(*) from orders where org = p_org;", { volatile: false, returnType: "bigint" }),
      definer("no_args_read", "select json_agg(x) from plans x;", { volatile: false, args: [] }),
      definer("no_args_write", "delete from sessions;", { args: [] }),
    ],
    { "private.require_admin": "if not exists (select 1 from admins where user_id = auth.uid()) then raise exception 'no'; end if;" },
  );
  assert.equal(sev["public.via_helper"], "info");
  assert.equal(sev["public.via_two_levels"], "info");
  assert.equal(sev["public.via_role"], "info");
  assert.equal(sev["public.via_claims"], "info");
  assert.equal(sev["public.no_check"], "low");
  assert.equal(sev["public.count_behind_login"], "info");
  assert.equal(sev["public.no_args_read"], "info");
  assert.equal(sev["public.no_args_write"], "low", "a write with no arguments still needs a decision");
});

test("definer functions that cannot hand out anyone's data are cleared from their body", () => {
  const sev = callerCheck([
    definer("make_code", "select substr(md5(random()::text), 1, 8);", { args: [], returnType: "text" }),
    definer("assert_owner_left", "if not exists (select 1 from members where org = p_org and role = 'owner') then raise exception 'no owner'; end if;", { returnType: "void" }),
    definer("touch_alias", "update public.todos t set visibility = 'workspace' where t.org = p_org;", { returnType: "void" }),
    definer("lookup_invite", "select json_build_object('org', org) from invites where token = p_token;", { args: [{ name: "p_token", type: "text" }] }),
    definer("store_secret", "update config set value = secret where key = 'webhook_secret';", { args: [{ name: "secret", type: "text" }], returnType: "void" }),
    definer("null_check_only", "if p_token is null then return null; end if; return (select json_agg(x) from invites x);", { args: [{ name: "p_token", type: "text" }] }),
  ]);
  assert.equal(sev["public.make_code"], "info", "touches no table");
  assert.equal(sev["public.assert_owner_left"], "info", "returns nothing and writes nothing");
  assert.equal(sev["public.touch_alias"], "low", "an UPDATE with a table alias is still a write");
  assert.equal(sev["public.lookup_invite"], "info", "acts only on a matching secret");
  assert.equal(sev["public.store_secret"], "low", "storing a secret the caller passes is not a secret check");
  assert.equal(sev["public.null_check_only"], "low", "a null check is not a secret check");
});

test("a function that deletes shared rows is reported as a shared-data write", () => {
  const input = JSON.parse(plantedInput) as JudgeInput;
  input.schema.functions.push(definer("cleanup_audit_logs", "delete from public.audit_logs where created_at < now() - (retention_days || ' days')::interval;", { args: [{ name: "retention_days", type: "integer" }], execAnon: true }));
  input.observations.push({
    probe: "rpc-write", target: "public.cleanup_audit_logs", actor: "anon", victim: "tenant B",
    facts: { changed: ["public.audit_logs 1: row deleted", "public.audit_logs 2: row deleted"], shared: true },
    evidence: { actor: "anon", victim: "tenant B", request: { method: "POST", path: "/rest/v1/rpc/cleanup_audit_logs" }, status: 200 },
  });
  const f = judge(input).findings.find((x) => x.target === "public.cleanup_audit_logs" && x.kind === "rpc-write")!;
  assert.equal(f.severity, "high");
  assert.match(f.title, /delete or change shared data in public\.audit_logs/);
});

test("a function that only creates rows in the victim's space is a create, not a change", () => {
  const input = JSON.parse(plantedInput) as JudgeInput;
  input.schema.functions.push(definer("create_org_with_admin", "insert into org_members(org_id, user_id, role) values (o, creator_id, 'admin');", { args: [{ name: "creator_id", type: "uuid" }], execAnon: true }));
  input.observations.push({
    probe: "rpc-write", target: "public.create_org_with_admin", actor: "anon", victim: "tenant A",
    facts: { changed: ["public.org_members 7: row appeared"] },
    evidence: { actor: "anon", victim: "tenant A", request: { method: "POST", path: "/rest/v1/rpc/create_org_with_admin" }, status: 200 },
  });
  const f = judge(input).findings.find((x) => x.target === "public.create_org_with_admin" && x.kind === "rpc-write")!;
  assert.equal(f.severity, "high");
  assert.match(f.title, /can create records in tenant A's data/);
});

test("warnings the scan cannot settle carry a check-it-yourself prompt naming the object", () => {
  const input = JSON.parse(plantedInput) as JudgeInput;
  input.schema.functions.push(definer("grant_credits", "update wallets set credits = credits + p_amount where org = p_org;", { args: [{ name: "p_org", type: "uuid" }], execAnon: true }));
  input.coverage.push({ relation: "public.grant_credits", kind: "function", reached: 2, unreachable: 0, populated: true });
  input.lint = { rows: [{ name: "anon_security_definer_function_executable", title: "t", level: "WARN", metadata: { schema: "public", name: "grant_credits" } }], triggerFunctions: [] };
  const result = judge(input);
  const row = result.triage!.rows.find((r) => r.target === "public.grant_credits")!;
  assert.equal(row.verdict, "flagged");
  assert.match(row.checkPrompt!, /public\.grant_credits/);
  assert.match(row.checkPrompt!, /even without an account/);
  assert.match(row.checkPrompt!, /Answer yes or no first/);
  assert.doesNotMatch(row.checkPrompt!, /[–—]/, "no dashes");
  const proven = result.triage!.rows.filter((r) => r.verdict === "proven");
  assert.ok(proven.every((r) => !r.checkPrompt), "proven warnings get a fix prompt instead");
});

// Triage branches no planted app can reach (scripts/rules.json "untestable"): a linter warning on an
// object the scan never saw, and on a function the API answered 404 or 406 for.
test("warnings on objects the scan never reached say so, and an unserved function is not served", () => {
  const input = JSON.parse(plantedInput) as JudgeInput;
  input.lint = {
    rows: [
      { name: "anon_security_definer_function_executable", title: "t", level: "WARN", metadata: { schema: "other", name: "elsewhere" } },
      { name: "rls_disabled_in_public", title: "t", level: "ERROR", metadata: { schema: "public", name: "never_seen" } },
      { name: "rls_policy_always_true", title: "t", level: "WARN", metadata: { schema: "public", name: "never_seen_open" } },
      { name: "authenticated_security_definer_function_executable", title: "t", level: "WARN", metadata: { schema: "public", name: "gone_from_cache" } },
    ],
    triggerFunctions: [],
    extensionObjects: {},
  };
  input.schema.functions.push({ schema: "public", name: "gone_from_cache", args: [{ name: "p_id", type: "uuid" }], defaultedArgs: 0, body: "select 1", volatile: false, securityDefiner: true, returnsSet: false, returnType: "integer", execAnon: false, execAuthenticated: true });
  input.coverage.push({ relation: "public.gone_from_cache", kind: "function", reached: 0, unreachable: 2, populated: true });
  input.schema.policies.push({ schema: "public", table: "never_seen_open", name: "open", cmd: "UPDATE", roles: ["authenticated"], using: "true", withCheck: null } as never);
  const rows = judge(input).triage!.rows;
  const by = Object.fromEntries(rows.map((r) => [r.target, r]));
  assert.equal(by["other.elsewhere"].rule, "triage/function-outside-scan");
  assert.equal(by["public.never_seen"].rule, "triage/table-not-reached");
  assert.equal(by["public.gone_from_cache"].rule, "triage/function-not-served");
  assert.equal(by["public.gone_from_cache"].verdict, "no-api");
  assert.equal(by["public.never_seen_open"].rule, "triage/table-flagged-not-reached");
});

test("report fields: stable ids, data classes from column names, and where each object is defined", async () => {
  const { columnsInProof, dataClasses, fingerprint, fingerprints } = await import("../src/core/report-context.js");
  const base = { kind: "cross-tenant-read" as const, target: "public.notes", rule: "read", confidence: "proven" as const };
  const a = fingerprint({ ...base, evidence: { actor: "tenant A" } as never });
  // Same failure from either tenant, in any run: same id. Anon, or another rule: a different one.
  assert.equal(a, fingerprint({ ...base, evidence: { actor: "tenant B" } as never }));
  assert.notEqual(a, fingerprint({ ...base, evidence: { actor: "anon" } as never }));
  assert.notEqual(a, fingerprint({ ...base, rule: "read/open-policy", evidence: { actor: "tenant A" } as never }));
  assert.deepEqual(fingerprints([base, base] as never).map((x) => x.replace(a, "")), ["", "-2"]);
  assert.deepEqual(dataClasses(["id", "billingEmail", "phone_number", "date_of_birth", "amount_cents", "name", "api_key", "notes"]), ["credentials", "email", "phone", "financial", "birth-date", "free-text"]);
  assert.deepEqual(columnsInProof('{"id":"1","email":"x@y"}'), ["id", "email"]);
  assert.deepEqual(columnsInProof('[{"id":"1","body":"cut sh'), ["id", "body"]);

  const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { sourceIndex } = await import("../src/supabase/repo-hints.js");
  const dir = mkdtempSync(join(tmpdir(), "tp-src-"));
  mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(dir, "supabase", "migrations", "1_a.sql"), 'create table public.notes (id int);\n-- create policy fake on public.notes\ncreate policy "Owners read" on public.notes for select using (true);\ncreate policy Old on notes for delete using (true);\n');
  writeFileSync(join(dir, "supabase", "migrations", "2_b.sql"), "drop policy old on public.notes;\n\ncreate or replace function public.f() returns int language sql as $$ select 1 $$;\n");
  const src = sourceIndex(dir).map((s) => `${s.kind} ${s.object} ${s.name ?? ""} ${s.file}:${s.line}`.replace(/ +/g, " "));
  assert.deepEqual(src.sort(), [
    "function public.f supabase/migrations/2_b.sql:3",
    "policy public.notes Owners read supabase/migrations/1_a.sql:3",
    "table public.notes supabase/migrations/1_a.sql:1",
  ]);
});

test("a CASE check is solved as one alternative per branch", async () => {
  const { caseToOr } = await import("../src/supabase/world.js");
  const e = "CASE WHEN (kind = ANY (ARRAY['a'::text, 'b'::text])) THEN ((amount IS NOT NULL) AND (unit IS NULL)) ELSE ((amount IS NULL) AND (unit IS NOT NULL)) END";
  assert.equal(
    caseToOr(e),
    "((kind = ANY (ARRAY['a'::text, 'b'::text])) AND ((amount IS NOT NULL) AND (unit IS NULL))) OR ((kind <> ALL (ARRAY['a'::text, 'b'::text])) AND ((amount IS NULL) AND (unit IS NOT NULL)))",
  );
  assert.equal(caseToOr("(a IS NULL) OR (b IS NULL)"), undefined);
  assert.equal(caseToOr("CASE kind WHEN 'a' THEN true ELSE false END"), undefined);
});

test("caller SQL: the argument run raw is found; quoted names, quoted or bound values are not", async () => {
  const { callerSql } = await import("../src/judge/static.js");
  const fn = (body: string) => ({ body, args: [{ name: "q", type: "text" }, { name: "id", type: "uuid" }] });
  assert.equal(callerSql(fn("begin execute q; end")), "q");
  assert.equal(callerSql(fn("begin return query execute 'select * from t where ' || q; end")), "q");
  assert.equal(callerSql(fn("begin execute format('select %s', q) into n; end")), "q");
  assert.equal(callerSql(fn("begin execute format('select * from %I', q) into n using id; end")), undefined);
  assert.equal(callerSql(fn("begin execute 'select * from t where name = ' || quote_literal(q); end")), undefined);
  assert.equal(callerSql(fn("begin execute 'select * from t where name = $1' into n using q; end")), undefined);
  assert.equal(callerSql(fn("begin -- execute q;\n select 1; end")), undefined);
});
