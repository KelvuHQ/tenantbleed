import assert from "node:assert/strict";
import { test } from "node:test";
import type pg from "pg";
import { http } from "../src/exec/http.js";
import { sql, sqlOne } from "../src/exec/sql.js";
import type { SupabaseApi } from "../src/supabase/api.js";

// A connection that records what it is sent and fails on statements containing "boom".
function fakeDb() {
  const sent: string[] = [];
  const db = {
    async query(text: string, params?: unknown[]) {
      sent.push(params?.length ? `${text} ${JSON.stringify(params)}` : text);
      if (text.includes("boom")) throw Object.assign(new Error("boom failed"), { code: "23505", constraint: "k" });
      if (text === "multi") return [{ fields: [{ name: "a" }], rows: [{ a: 1 }], rowCount: 1 }, { fields: [], rows: [], rowCount: null }];
      return { rows: [{ text }], rowCount: 1, fields: [] };
    },
  };
  return { db: db as unknown as pg.Client, sent };
}

test("a single committed statement runs without a transaction", async () => {
  const { db, sent } = fakeDb();
  const [r] = await sql(db, [{ statements: [{ text: "select 1" }] }]);
  assert.deepEqual(sent, ["select 1"]);
  assert.equal(r.results[0].rowCount, 1);
});

test("setup order: begin, replica, role, claims, statements, then commit or rollback", async () => {
  const { db, sent } = fakeDb();
  await sql(db, [{ replica: true, role: "authenticated", claims: { sub: "u1", role: "authenticated" }, rollback: true, statements: [{ text: "s1" }, { text: "s2", params: [7] }] }]);
  assert.deepEqual(sent, [
    "begin",
    "set local session_replication_role = replica",
    "set local role authenticated",
    `select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true) ${JSON.stringify(['{"sub":"u1","role":"authenticated"}', "u1"])}`,
    "s1",
    's2 [7]',
    "rollback",
  ]);
});

test("a failed statement stops the operation, rolls back and says which one failed", async () => {
  const { db, sent } = fakeDb();
  const [r, next] = await sql(db, [{ statements: [{ text: "ok" }, { text: "boom" }, { text: "never" }] }, { statements: [{ text: "after" }] }]);
  assert.deepEqual(r.error, { code: "23505", message: "boom failed", constraint: "k", at: 1 });
  assert.equal(r.results.length, 1);
  assert.deepEqual(sent, ["begin", "ok", "boom", "rollback", "after"]);
  assert.equal(next.error, undefined, "the next operation still runs");
  await assert.rejects(sqlOne(db, { statements: [{ text: "boom" }] }), (e: { code?: string }) => e.code === "23505");
});

test("a multi-statement text yields the rows of its last statement with columns", async () => {
  const { db } = fakeDb();
  const [r] = await sql(db, [{ statements: [{ text: "multi" }] }]);
  assert.deepEqual(r.results[0].rows, [{ a: 1 }]);
});

test("http: users by label, unknown labels are a result, bodies capped when asked", async () => {
  const calls: string[] = [];
  const api = {
    async request(actor: { label: string; token?: string }, method: string, path: string) {
      calls.push(`${actor.label} ${method} ${path}`);
      return { status: 200, body: null, text: "x".repeat(10) };
    },
  } as unknown as SupabaseApi;
  const actors = new Map([["tenant A", { label: "tenant A", token: "t" }]]);
  const out = await http(api, actors, [{ as: "anon", method: "GET", path: "/a" }, { as: "tenant A", method: "GET", path: "/b" }, { as: "nobody", method: "GET", path: "/c" }], { maxBody: 4 });
  assert.deepEqual(calls, ["anon GET /a", "tenant A GET /b"]);
  assert.equal(out[1].text, "xxxx");
  assert.equal(out[1].truncated, true);
  assert.equal(out[2].status, 0);
});

test("staff gate: a privilege gate over a user-only row marks the table; flags, roles and own-row lookups do not", async () => {
  const { staffGate } = await import("../src/supabase/world.js");
  const rel = (name: string, refs: string[] = []) =>
    ({ schema: "public", name, kind: "table", columns: [], primaryKey: ["user_id"], foreignKeys: [{ columns: ["user_id"], refSchema: "auth", refTable: "users", refColumns: ["id"] }, ...refs.map((r) => ({ columns: ["x"], refSchema: "public", refTable: r, refColumns: ["user_id"] }))] }) as never;
  const fn = (name: string, body: string) => ({ schema: "public", name, body }) as never;
  const caller = fn("settle_all", "begin if not public.is_site_operator() then raise exception 'no'; end if; end;");
  const schema = (gate: string, extra: never[] = []) =>
    ({ relations: [rel("site_delegates"), ...extra], policies: [], functions: [fn("is_site_operator", gate), caller] }) as never;
  const t = rel("site_delegates");
  const none = new Set<string>();
  assert.equal(staffGate(schema("select exists (select 1 from public.site_delegates where user_id = (select auth.uid()) and status = 'active')"), t, none), true);
  assert.equal(staffGate(schema("select exists (select 1 from public.site_delegates d where d.user_id = auth.uid() and d.is_admin)"), t, none), false, "a flag is left to the value fill");
  assert.equal(staffGate(schema("select exists (select 1 from public.site_delegates where user_id = auth.uid() and role = 'admin')"), t, none), false, "a role value is left to the value fill");
  assert.equal(staffGate(schema("select exists (select 1 from public.site_delegates where user_id = auth.uid() and org_id = p_org)"), t, none), false, "a scoped membership");
  assert.equal(staffGate(schema("select exists (select 1 from public.site_delegates where user_id = auth.uid())", [rel("orders", ["site_delegates"])]), t, none), false, "other rows hang off it");
  const pin = { relations: [t], policies: [], functions: [fn("has_badge_pin", "select exists (select 1 from public.site_delegates where user_id = auth.uid())"), fn("set_badge", "begin if not public.has_badge_pin() then raise exception 'x'; end if; end;")] } as never;
  assert.equal(staffGate(pin, t, none), false, "a gate not named for a privilege");
});

test("buildRow: an optional person column into a profile table waits for the profile row; auth.users never waits", async () => {
  const { buildRow } = await import("../src/supabase/world.js");
  const col = (name: string, type: string, notNull: boolean) => ({ name, type, notNull, hasDefault: false, isIdentity: false, isGenerated: false, enumLabels: [] });
  const team = {
    schema: "public", name: "teams", kind: "table", primaryKey: ["id"], checks: [],
    columns: [col("id", "uuid", true), col("name", "text", true), col("reminder_id", "uuid", false), col("created_by", "uuid", false)],
    foreignKeys: [
      { columns: ["reminder_id"], refSchema: "public", refTable: "members", refColumns: ["id"] },
      { columns: ["created_by"], refSchema: "auth", refTable: "users", refColumns: ["id"] },
    ],
  } as never;
  const profiles = new Set(["public.members"]);
  const none = () => undefined;
  const waiting = buildRow(team, profiles, none, "tp", () => "u1", () => false) as { row: Record<string, unknown>; deferred?: unknown[] };
  assert.equal(waiting.row.reminder_id, undefined);
  assert.equal(waiting.row.created_by, "u1", "auth.users always exists");
  assert.deepEqual(waiting.deferred, [{ column: "reminder_id", profile: "public.members" }]);
  const ready = buildRow(team, profiles, none, "tp", () => "u1", () => true) as { row: Record<string, unknown>; deferred?: unknown[] };
  assert.equal(ready.row.reminder_id, "u1");
  assert.equal(ready.deferred, undefined);
});

test("topoOrder: every table comes after every table it requires, around circles of optional links", async () => {
  const { topoOrder } = await import("../src/supabase/world.js");
  const col = (name: string, notNull: boolean) => ({ name, type: "uuid", notNull, hasDefault: false, isIdentity: false, isGenerated: false, enumLabels: [] });
  const fk = (c: string, to: string) => ({ columns: [c], refSchema: "public", refTable: to, refColumns: ["id"] });
  const rel = (name: string, links: [string, string, boolean][]) =>
    ({ schema: "public", name, kind: "table", primaryKey: ["id"], checks: [], columns: [col("id", true), ...links.map(([c, , req]) => col(c, req))], foreignKeys: links.map(([c, to]) => fk(c, to)) }) as never;
  // The fixture: boards -> files -> cards -> columns are optional; cards and columns need boards.
  const deck = [
    rel("boards", [["cover_file_id", "files", false]]),
    rel("files", [["card_id", "cards", false]]),
    rel("cards", [["board_id", "boards", true], ["column_id", "columns", false]]),
    rel("columns", [["board_id", "boards", true]]),
  ];
  // Three optional hops, then a required link back: a -> b -> c optional, c needs a.
  const loop = [rel("c", [["a_id", "a", true]]), rel("b", [["c_id", "c", false]]), rel("a", [["b_id", "b", false]])];
  for (const tables of [deck, loop]) {
    const order = topoOrder(tables).map((t: { name: string }) => t.name);
    for (const t of tables as { name: string; foreignKeys: { refTable: string; columns: string[] }[]; columns: { name: string; notNull: boolean }[] }[]) {
      for (const f of t.foreignKeys.filter((k) => t.columns.find((c) => c.name === k.columns[0])!.notNull)) {
        assert.ok(order.indexOf(f.refTable) < order.indexOf(t.name), `${t.name} before ${f.refTable} it requires: ${order.join(", ")}`);
      }
    }
  }
});

test("jwtClaimScope: tenancy from a JWT claim compared to a column is read; a role-to-literal check is not", async () => {
  const { jwtClaimScope } = await import("../src/supabase/world.js");
  const col = (name: string) => ({ name, type: "uuid", notNull: true, hasDefault: false, isIdentity: false, isGenerated: false, enumLabels: [] });
  const rel = { schema: "public", name: "t", kind: "table", primaryKey: ["id"], checks: [], columns: [col("id"), col("org_id"), col("tenant_id")], foreignKeys: [] } as never;
  const withUsing = (using: string) => ({ relations: [rel], policies: [{ schema: "public", table: "t", name: "p", cmd: "ALL", roles: ["authenticated"], using, withCheck: null }], functions: [] }) as never;
  // The common stored forms (extra parens, ::text on the key, a trailing ::uuid) all resolve to the claim.
  assert.equal(jwtClaimScope(withUsing("((auth.jwt() ->> 'org_id'::text))::uuid = org_id)"), rel), "org_id");
  assert.equal(jwtClaimScope(withUsing("(tenant_id = ((auth.jwt() ->> 'org_id'::text))::uuid)"), rel), "org_id");
  assert.equal(jwtClaimScope(withUsing("(((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'org_id'::text))::uuid = org_id)"), rel), "org_id");
  // Not tenancy: a claim compared to a literal (a role gate), or no claim at all.
  assert.equal(jwtClaimScope(withUsing("((auth.jwt() ->> 'role'::text) = 'admin'::text)"), rel), undefined);
  assert.equal(jwtClaimScope(withUsing("(org_id = auth.uid())"), rel), undefined);
});
