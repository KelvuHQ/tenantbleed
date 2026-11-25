import pg from "pg";
import { mark, marksOf, trace } from "../core/trace.js";
import type { Observation, WorldSummary } from "../core/observation.js";
import type { CoverageRow } from "../core/scan-result.js";
import type { ScanProgress } from "../core/progress.js";
import type { Actor, ApiResponse, SupabaseApi } from "./api.js";
import { qualified, type Relation, type RpcFunction, type Schema } from "./introspect.js";
import { timeMaintenance } from "../core/job-shape.js";
import { asUserClaims, query, sql, sqlOne, type SqlStatement } from "../exec/sql.js";
import {
  buildRow,
  findTokens,
  ident,
  isUserRef,
  jwtClaimScope,
  pkFilter,
  profileHeaders,
  qident,
  tenantTables,
  toParam,
  type OwnedRow,
  type Row,
  type World,
  wellKnownValue,
} from "./world.js";

/** Coverage rows are the shared ScanResult shape (src/core/scan-result.ts), one definition. */
export type Coverage = CoverageRow;

interface Ctx {
  api: SupabaseApi;
  db: pg.Client;
  schema: Schema;
  world: World;
  observations: Observation[];
  notes: string[];
  coverage: Map<string, Coverage>;
  /** Enum labels by type name, for function arguments. */
  enums: Map<string, string[]>;
  /** Dimensions of vector columns by base type (vector, halfvec), for embedding arguments. */
  vectorDims: Map<string, number>;
}

const short = (v: unknown, max = 300) => {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > max ? s.slice(0, max) + "..." : s;
};

function track(ctx: Ctx, target: string, kind: Coverage["kind"], res: ApiResponse) {
  // Relations first seen here (views, functions, tables without a primary key) need no test data of their own.
  const c = ctx.coverage.get(target) ?? { relation: target, kind, reached: 0, unreachable: 0, populated: true };
  // PostgREST answers 406 (PGRST106) for a schema it does not serve, 404 for an unknown relation/function.
  // (A function whose body fails on a missing object is recorded where it is called, which knows
  // whether the missing name was the caller's own argument.)
  // Only PostgREST's own codes mean "not served": PGRST106 (schema not exposed), PGRST202 (no such
  // function in the schema cache), PGRST205 (no such relation), or no code at all. Any other 404 came
  // from inside (a function that raised one): the call was served.
  const code = /"code"\s*:\s*"([^"]+)"/.exec(res.text ?? "")?.[1];
  if ((res.status === 406 || res.status === 404) && (!code || code.startsWith("PGRST"))) {
    c.unreachable++;
    // The answer names another schema than the object's: the request went to the wrong one.
    const other = /Searched for the (?:function|table|relation) ([\w"]+)\./i.exec(res.text ?? "")?.[1]?.replace(/"/g, "");
    const own = target.split(".")[0];
    if (other && other !== own && !ctx.notes.some((n) => n.startsWith(`Requests for ${own}`))) {
      ctx.notes.push(`Requests for ${own} reached the ${other} schema: check the order of [api] schemas in config.toml.`);
    }
  } else c.reached++;
  ctx.coverage.set(target, c);
}

/** Record what a probe saw. The judge (src/judge/) decides whether and how badly it matters. */
function observe(ctx: Ctx, o: Observation) {
  // A table probe's proof rests on the victim's test row: say how that row was built.
  if (o.evidence && !o.evidence.via?.length) {
    const row = ctx.world.owned.find((w) => w.owner === o.victim && w.table === o.target);
    if (row?.via?.length) o.evidence.via = row.via;
  }
  for (const v of o.evidence?.via ?? []) if (v.startsWith("args/")) trace(v, o.target);
  ctx.observations.push(o);
}

const victimsOf = (ctx: Ctx, actor: Actor) => (actor.token ? ctx.world.tenants.filter((t) => t.label !== actor.label) : ctx.world.tenants);
const victimRows = (ctx: Ctx, victim: Actor, table: string) => ctx.world.owned.filter((o) => o.owner === victim.label && o.table === table);
const roleOf = (a: Actor) => (a.token ? "authenticated" : "anon");

/** 1. Read everything every actor can see and look for another tenant's data in it. */
async function readSweep(ctx: Ctx, actors: Actor[], only?: Set<string>) {
  for (const rel of ctx.schema.relations) {
    const q = qualified(rel);
    if (only && !only.has(q)) continue;
    // A managed-schema table (auth.users) the app exposed is never "safely shared": sweep it even when
    // it has no owner path, so a real exposure leak is still caught.
    if (rel.kind === "table" && ctx.world.unscoped.has(q) && !rel.managed) continue;
    for (const actor of actors) {
      if (!rel.grants[roleOf(actor)].select) continue;
      const path = `/rest/v1/${rel.name}?select=*&limit=1000`;
      const res = await ctx.api.request(actor, "GET", path, undefined, profileHeaders(rel));
      track(ctx, q, rel.kind, res);
      if (res.status !== 200 || !Array.isArray(res.body)) continue;
      // The attacker's own rows are never evidence, even when they mention the victim (a notification
      // about a trade on the victim's listing, a reference to the victim's record).
      const pkOf = (r: Row) => (rel.primaryKey.length ? rel.primaryKey.map((c) => String(r[c])).join("\u001f") : undefined);
      const own = new Set(ctx.world.owned.filter((o) => o.owner === actor.label && o.table === q).map((o) => rel.primaryKey.map((c) => String(o.pk[c])).join("\u001f")));
      for (const victim of victimsOf(ctx, actor)) {
        const leaked = (res.body as Row[]).filter((r) => !own.has(pkOf(r) ?? "") && findTokens(JSON.stringify(r), ctx.world.tokens.get(victim.label)!).length);
        if (!leaked.length) continue;
        observe(ctx, {
          probe: "read",
          target: q,
          actor: actor.label,
          victim: victim.label,
          facts: { relKind: rel.kind, leaked, hits: leaked.flatMap((r) => findTokens(JSON.stringify(r), ctx.world.tokens.get(victim.label)!)) },
          evidence: {
            actor: actor.label,
            victim: victim.label,
            request: { method: "GET", path },
            status: res.status,
            proof: short(leaked[0]),
            curl: ctx.api.curl(actor, "GET", path, undefined, profileHeaders(rel)),
          },
        });
      }
    }
  }
}

/** A privilege value is not a row state: role = 'admin' is self-escalation, not "published". */
const STATE_PRIVILEGE = /admin|owner|super|staff|moderator|operator|root/i;
const STATE_SENSITIVE = /(^|_)(e?mail|phone|address|order|tax|iban|card|token|secret|balance|ssn|dob|birth|name)($|_)/i;

/**
 * A read a policy opens once a parent (or the row itself) is in a normal state: a booking is
 * readable while its listing is live, an enrollment while its course is published. The world leaves
 * the parent in its default state (draft), so the branch never fires and the leak is missed. This
 * sets the victim's parent to the state the policy checks, rereads the child as every other actor,
 * then restores it.
 */
async function policyStateRead(ctx: Ctx, actors: Actor[]) {
  // `from [schema.]P [alias]` (pg_get_expr wraps the WHERE in extra parens, so the state atom is
  // found by scanning the policy for `<alias>.<col> = 'lit'` rather than parsing the WHERE).
  const fromRe = /\bfrom\s+(?:(\w+)\.)?"?(\w+)"?(?:\s+(?:as\s+)?(\w+))?/gi;
  const value = (eq?: string, inList?: string, isWord?: string): unknown =>
    isWord ? (isWord.toLowerCase() === "null" ? null : isWord.toLowerCase() === "true") : (eq ?? inList);
  const atomFor = (text: string, qualifier: string | undefined) => {
    const re = new RegExp(String.raw`(?:(\w+)\.)?"?(\w+)"?\s*(?:=\s*'([^']*)'(?:::[\w". ]+)?|\bin\s*\(\s*'([^']*)'|\bis\s+(true|false|null))`, "gi");
    for (const m of text.matchAll(re)) {
      const [, qual, col, eq, inList, isWord] = m;
      if (qualifier !== undefined && qual !== qualifier) continue;
      const v = value(eq, inList, isWord);
      if (v === undefined || (typeof v === "string" && STATE_PRIVILEGE.test(v))) continue;
      return { col, v, at: m.index ?? 0 };
    }
    return undefined;
  };
  for (const t of tenantTables(ctx.schema)) {
    for (const p of ctx.schema.policies) {
      if (p.schema !== t.schema || p.table !== t.name || !p.using || (p.cmd !== "SELECT" && p.cmd !== "ALL")) continue;
      // Parent-state: exists(select .. from P [alias] where .. P.col = lit ..).
      for (const m of p.using.matchAll(fromRe)) {
        const [, pschema, ptable, aliasRaw] = m;
        const parent = ctx.schema.relations.find((r) => r.name === ptable && (!pschema || r.schema === pschema));
        const fk = t.foreignKeys.find((f) => f.refTable === ptable && f.columns.length === 1);
        if (!parent || !fk) continue;
        const alias = aliasRaw && !/^(where|on|as)$/i.test(aliasRaw) ? aliasRaw : ptable;
        const atom = atomFor(p.using.slice(m.index ?? 0), alias);
        if (!atom || !parent.columns.some((c) => c.name === atom.col)) continue;
        await tryState(ctx, t, parent, atom.col, atom.v, actors, p.name);
      }
      // Self-state: the row's own column (status = 'published') on T, not inside a subquery.
      const head = p.using.split(/\bexists\s*\(|\bselect\b/i)[0];
      const atom = atomFor(head, undefined);
      if (atom && t.columns.some((c) => c.name === atom.col) && !t.foreignKeys.some((f) => f.columns.includes(atom.col)) && !/auth\.(uid|role)/i.test(head.slice(Math.max(0, atom.at - 14), atom.at))) {
        await tryState(ctx, t, t, atom.col, atom.v, actors, p.name);
      }
    }
  }
}

/** Put the victim's `parent` into `col = value`, reread `t` as every other actor, then restore. */
async function tryState(ctx: Ctx, t: Relation, parent: Relation, col: string, value: unknown, actors: Actor[], policy: string) {
  const pq = qualified(parent);
  for (const victim of ctx.world.tenants) {
    const prow = ctx.world.owned.find((o) => o.owner === victim.label && o.table === pq);
    if (!prow) continue;
    const before = await fetchRow(ctx, parent, prow.pk);
    if (!before || String(before[col]) === String(value)) continue;
    const set = await sqlOne(ctx.db, { ...asUserClaims(victim.userId), statements: [{ text: `update ${qident(parent)} set ${ident(col)} = $1 where ${parent.primaryKey.map((c, i) => `${ident(c)}::text = $${i + 2}`).join(" and ")}`, params: [value, ...parent.primaryKey.map((c) => String(prow.pk[c]))] }] }).then(() => true).catch(() => false);
    if (!set) continue;
    for (const actor of actors) {
      if (actor.label === victim.label || !t.grants[roleOf(actor)].select) continue;
      const res = await ctx.api.request(actor, "GET", `/rest/v1/${t.name}?select=*&limit=1000`, undefined, profileHeaders(t));
      if (res.status !== 200 || !Array.isArray(res.body)) continue;
      const own = new Set(ctx.world.owned.filter((o) => o.owner === actor.label && o.table === qualified(t)).map((o) => t.primaryKey.map((c) => String(o.pk[c])).join("\u001f")));
      const leaked = (res.body as Row[]).filter((r) => !own.has(t.primaryKey.map((c) => String(r[c])).join("\u001f")) && findTokens(JSON.stringify(r), ctx.world.tokens.get(victim.label)!).length);
      if (!leaked.length) continue;
      const sensitive = [...new Set(leaked.flatMap((r) => Object.keys(r).filter((c) => STATE_SENSITIVE.test(c) && r[c] != null && r[c] !== "")))];
      observe(ctx, {
        probe: "read-state",
        target: qualified(t),
        actor: actor.label,
        victim: victim.label,
        facts: { leaked, precondition: parent === t ? `${t.name}.${col} = ${String(value)}` : `${parent.name}.${col} = ${String(value)}`, sensitive },
        evidence: {
          actor: actor.label,
          victim: victim.label,
          request: { method: "GET", path: `/rest/v1/${t.name}?select=*` },
          status: res.status,
          proof: `after ${parent === t ? "" : `${parent.name} `}${col} = ${String(value)} (policy "${policy}"): ${short(leaked[0], 160)}`,
          curl: ctx.api.curl(actor, "GET", `/rest/v1/${t.name}?select=*`, undefined, profileHeaders(t)),
        },
      });
    }
    await restoreColumns(ctx, parent, before, [col], victim.userId);
  }
}

function mutableColumn(t: Relation): string | undefined {
  const fkCols = new Set(t.foreignKeys.flatMap((f) => f.columns));
  const candidates = t.columns.filter((c) => !t.primaryKey.includes(c.name) && !fkCols.has(c.name) && !c.isGenerated && !c.isIdentity && !c.enumLabels.length);
  const checked = (c: string) => t.checks.some((d) => d.includes(c));
  return (
    candidates.find((c) => /text|character/.test(c.type) && !checked(c.name)) ??
    candidates.find((c) => /integer|numeric/.test(c.type) && !checked(c.name)) ??
    candidates.find((c) => /text|character|integer|numeric/.test(c.type))
  )?.name;
}

async function fetchRow(ctx: Ctx, t: Relation, pk: Row): Promise<Row | undefined> {
  const res = await query(ctx.db, 
    `select * from ${qident(t)} where ${t.primaryKey.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")}`,
    t.primaryKey.map((c) => String(pk[c])),
  );
  return res.rows[0];
}

/** Put changed columns back with a plain UPDATE (no INSERT triggers fire). */
async function restoreColumns(ctx: Ctx, t: Relation, before: Row, cols: string[], ownerId?: string) {
  try {
    await sqlOne(ctx.db, {
      ...asUserClaims(ownerId),
      statements: [
        {
          text: `update ${qident(t)} set ${cols.map((c, i) => `${ident(c)} = $${i + 1}`).join(", ")}
          where ${t.primaryKey.map((c, i) => `${ident(c)}::text = $${cols.length + i + 1}`).join(" and ")}`,
          params: [...cols.map((c) => toParam(before[c])), ...t.primaryKey.map((c) => String(before[c]))],
        },
      ],
    });
  } catch (e) {
    ctx.notes.push(`could not restore ${qualified(t)} after a probe: ${(e as Error).message}`);
  }
}

/** Re-insert a deleted row as its owner (so auth.uid() in triggers matches). */
async function restoreDeleted(ctx: Ctx, t: Relation, row: Row, ownerId?: string) {
  const cols = Object.keys(row).filter((c) => !t.columns.find((x) => x.name === c)?.isGenerated);
  const overriding = t.columns.some((c) => c.isIdentity) ? " overriding system value" : "";
  try {
    await sqlOne(ctx.db, {
      ...asUserClaims(ownerId),
      statements: [
        {
          text: `insert into ${qident(t)} (${cols.map(ident).join(", ")})${overriding} values (${cols.map((_, i) => `$${i + 1}`).join(", ")}) on conflict do nothing`,
          params: cols.map((c) => toParam(row[c])),
        },
      ],
    });
  } catch (e) {
    ctx.notes.push(`could not restore a deleted ${qualified(t)} row: ${(e as Error).message}`);
  }
}

const ownerIdOf = (ctx: Ctx, label: string) => ctx.world.tenants.find((t) => t.label === label)?.userId;

/** 2. Try to overwrite another tenant's row; check the database to see whether it really changed. */
async function updateProbe(ctx: Ctx, actors: Actor[]) {
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    const col = mutableColumn(t);
    if (!col) continue;
    for (const actor of actors) {
      if (!t.grants[roleOf(actor)].update) continue;
      for (const victim of victimsOf(ctx, actor)) {
        const target = victimRows(ctx, victim, q)[0];
        if (!target) continue;
        const before = await fetchRow(ctx, t, target.pk);
        if (!before) continue;
        const isText = /text|character/.test(t.columns.find((c) => c.name === col)!.type);
        const newValue = isText ? `tp_overwritten_by_${actor.label.replace(/\W+/g, "")}`.slice(0, 20) : Number(before[col] ?? 0) + 1;
        const path = `/rest/v1/${t.name}?${pkFilter(t, target.pk)}`;
        const body = { [col]: newValue };
        const res = await ctx.api.request(actor, "PATCH", path, body, { Prefer: "return=minimal", ...profileHeaders(t) });
        track(ctx, q, "table", res);
        const after = await fetchRow(ctx, t, target.pk);
        if (!after || String(after[col]) === String(before[col])) continue;
        observe(ctx, {
          probe: "update",
          target: q,
          actor: actor.label,
          victim: victim.label,
          facts: { column: col },
          evidence: {
            actor: actor.label,
            victim: victim.label,
            request: { method: "PATCH", path, body },
            status: res.status,
            proof: `${col}: ${short(before[col], 80)} -> ${short(after[col], 80)}`,
            curl: ctx.api.curl(actor, "PATCH", path, body, profileHeaders(t)),
          },
        });
        await restoreColumns(ctx, t, before, [col], ownerIdOf(ctx, victim.label));
      }
    }
  }
}

/** Tenant foreign keys (not person columns, not part of the primary key). */
const tenantFks = (ctx: Ctx, t: Relation) => t.foreignKeys.filter((f) => !isUserRef(f, ctx.world.profileTables));

/**
 * Whether the victim can see a row (their API role and JWT claims, read-only, rolled back). An injected
 * row the victim can see lands in their data; one they cannot see is only the attacker's own row
 * pointing at the victim's record.
 */
async function victimCanSee(ctx: Ctx, t: Relation, match: Row, victim: Actor): Promise<boolean> {
  const cols = Object.keys(match);
  if (!cols.length || !victim.userId) return true;
  const where = cols.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ");
  const [r] = await sql(ctx.db, [
    {
      role: "authenticated",
      ...asUserClaims(victim.userId, { email: victim.email }),
      rollback: true,
      statements: [{ text: `select 1 from ${qident(t)} where ${where} limit 1`, params: cols.map((c) => String(match[c])) }],
    },
  ]);
  if (r.error) return true; // unknown: keep the stricter reading
  return !!r.results[0].rowCount;
}

/** 2b. Move your OWN row into another tenant by rewriting its foreign key (missing WITH CHECK). */
async function reparentProbe(ctx: Ctx) {
  for (const t of tenantTables(ctx.schema)) {
    if (!t.grants.authenticated.update) continue;
    const q = qualified(t);
    for (const fk of tenantFks(ctx, t).filter((f) => !f.columns.some((c) => t.primaryKey.includes(c)))) {
      const refQ = `${fk.refSchema}.${fk.refTable}`;
      if (ctx.world.unscoped.has(refQ)) continue; // moving to another catalog row is not a tenant boundary
      for (const attacker of ctx.world.tenants) {
        const mine = victimRows(ctx, attacker, q)[0];
        if (!mine) continue;
        for (const victim of victimsOf(ctx, attacker)) {
          const parent = ctx.world.owned.find((o) => o.owner === victim.label && o.table === refQ);
          if (!parent) continue;
          const before = await fetchRow(ctx, t, mine.pk);
          if (!before) continue;
          const body = Object.fromEntries(fk.columns.map((c, i) => [c, parent.row[fk.refColumns[i]]]));
          const path = `/rest/v1/${t.name}?${pkFilter(t, mine.pk)}`;
          const res = await ctx.api.request(attacker, "PATCH", path, body, { Prefer: "return=minimal", ...profileHeaders(t) });
          track(ctx, q, "table", res);
          const after = await fetchRow(ctx, t, mine.pk);
          const moved = after && fk.columns.every((c) => String(after[c]) === String(body[c]));
          if (!moved) continue;
          observe(ctx, {
            probe: "reparent",
            target: q,
            actor: attacker.label,
            victim: victim.label,
            facts: { refTable: refQ, columns: fk.columns, victimCanSee: await victimCanSee(ctx, t, mine.pk, victim) },
            evidence: {
              actor: attacker.label,
              victim: victim.label,
              request: { method: "PATCH", path, body },
              status: res.status,
              proof: fk.columns.map((c) => `${c}: ${before[c]} -> ${after![c]}`).join(", "),
              curl: ctx.api.curl(attacker, "PATCH", path, body, profileHeaders(t)),
            },
          });
          await restoreColumns(ctx, t, before, fk.columns, attacker.userId);
        }
      }
    }
  }
}

/** 3. Try to create rows inside another tenant (tenant FKs at the victim, person FKs stay the attacker's). */
async function insertProbe(ctx: Ctx, actors: Actor[]) {
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    const tfks = tenantFks(ctx, t).filter((f) => !ctx.world.unscoped.has(`${f.refSchema}.${f.refTable}`));
    if (!tfks.length) continue;
    for (const actor of actors) {
      if (!t.grants[roleOf(actor)].insert) continue;
      for (const victim of victimsOf(ctx, actor)) {
        // Try each of the victim's parent rows for the first tenant FK (a policy may reject one parent for an unrelated reason).
        const first = tfks[0];
        const candidates = ctx.world.owned.filter((o) => o.owner === victim.label && o.table === `${first.refSchema}.${first.refTable}`).slice(0, 5);
        for (const pinned of candidates) {
          const source = (ref: string) =>
            ref === pinned.table
              ? pinned
              : ctx.world.owned.find((o) => o.owner === victim.label && o.table === ref) ??
                (ctx.world.unscoped.has(ref) ? ctx.world.owned.find((o) => o.table === ref) : undefined);
          const built = buildRow(t, ctx.world.profileTables, (ref) => source(ref) ?? sharedRow(ctx, ref), `tp_intruder_${actor.label.replace(/\W+/g, "").toLowerCase()}_${t.name}`, () => actor.userId ?? victim.userId);
          if ("error" in built) continue;
          const row = built.row;
          const path = `/rest/v1/${t.name}`;
          const res = await ctx.api.request(actor, "POST", path, row, { Prefer: "return=minimal", ...profileHeaders(t) });
          track(ctx, q, "table", res);
          if (res.status !== 201) continue;
          const markerCol0 = Object.keys(row).find((c) => typeof row[c] === "string" && String(row[c]).startsWith("tp_intruder"));
          const match: Row = markerCol0 ? { [markerCol0]: row[markerCol0] } : t.primaryKey.every((c) => row[c] !== undefined) ? Object.fromEntries(t.primaryKey.map((c) => [c, row[c]])) : {};
          observe(ctx, {
            probe: "insert",
            target: q,
            actor: actor.label,
            victim: victim.label,
            facts: { parentTable: pinned.table, columns: first.columns, victimCanSee: await victimCanSee(ctx, t, match, victim) },
            evidence: {
              actor: actor.label,
              victim: victim.label,
              request: { method: "POST", path, body: row },
              status: res.status,
              proof: `201 Created: ${short(row, 200)}`,
              curl: ctx.api.curl(actor, "POST", path, row, profileHeaders(t)),
            },
          });
          const markerCol = Object.keys(row).find((c) => typeof row[c] === "string" && String(row[c]).startsWith("tp_intruder"));
          if (markerCol) await query(ctx.db, `delete from ${qident(t)} where ${ident(markerCol)} = $1`, [row[markerCol]]).catch(() => {});
          else if (t.primaryKey.every((c) => row[c] !== undefined))
            await query(ctx.db, `delete from ${qident(t)} where ${t.primaryKey.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")}`, t.primaryKey.map((c) => String(row[c]))).catch(() => {});
          break;
        }
      }
    }
  }
}

/** Remove a row a probe managed to create, by its marker column or full primary key. */
async function cleanupInserted(ctx: Ctx, t: Relation, row: Row, markerPrefix: string) {
  const markerCol = Object.keys(row).find((c) => typeof row[c] === "string" && String(row[c]).startsWith(markerPrefix));
  const cols = markerCol ? [markerCol] : t.primaryKey.every((c) => row[c] !== undefined) ? t.primaryKey : [];
  if (!cols.length) return;
  const where = cols.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ");
  await query(ctx.db, `delete from ${qident(t)} where ${where}`, cols.map((c) => String(row[c]))).catch(() => {});
}

/** 3b. Create a row that names ANOTHER user in its person column (owner, author, primary_owner_user_id). */
async function impersonationProbe(ctx: Ctx) {
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    if (!t.grants.authenticated.insert || ctx.world.unscoped.has(q)) continue;
    // Profile tables are keyed by the user id and normally insert-once; skip them.
    if (ctx.world.profileTables.has(q)) continue;
    const personFks = t.foreignKeys.filter((f) => isUserRef(f, ctx.world.profileTables));
    if (!personFks.length) continue;
    const cols = personFks.flatMap((f) => f.columns);
    for (const attacker of ctx.world.tenants) {
      for (const victim of victimsOf(ctx, attacker)) {
        // Tenant FKs stay on the attacker's own rows, so only the person column crosses the boundary.
        const own = (ref: string) => ctx.world.owned.find((o) => o.owner === attacker.label && o.table === ref) ?? sharedRow(ctx, ref);
        const built = buildRow(t, ctx.world.profileTables, own, `tp_impersonate_${t.name}`, () => victim.userId);
        if ("error" in built) continue;
        const row = built.row;
        const path = `/rest/v1/${t.name}`;
        const res = await ctx.api.request(attacker, "POST", path, row, { Prefer: "return=minimal", ...profileHeaders(t) });
        track(ctx, q, "table", res);
        if (res.status !== 201) continue;
        // A 201 is not proof: a BEFORE INSERT trigger may have rewritten the person column to the
        // caller. Read the stored row back and require the victim's id in it.
        const markerCol = Object.keys(row).find((c) => typeof row[c] === "string" && String(row[c]).startsWith("tp_impersonate"));
        const stored = markerCol
          ? (await query(ctx.db, `select ${cols.map(ident).join(", ")} from ${qident(t)} where ${ident(markerCol)} = $1 limit 1`, [row[markerCol]]).catch(() => ({ rows: [] }))).rows[0]
          : undefined;
        if (stored && !cols.some((c) => String(stored[c]) === victim.userId)) {
          await cleanupInserted(ctx, t, row, "tp_impersonate");
          continue;
        }
        observe(ctx, {
          probe: "impersonate",
          target: q,
          actor: attacker.label,
          victim: victim.label,
          facts: { columns: cols, personAndTenantInKey: cols.some((c) => t.primaryKey.includes(c)) && tenantFks(ctx, t).some((f) => f.columns.some((c) => t.primaryKey.includes(c))) },
          evidence: {
            actor: attacker.label,
            victim: victim.label,
            request: { method: "POST", path, body: row },
            status: res.status,
            proof: `201 Created with ${cols.map((c) => `${c} = ${victim.label}'s user id`).join(", ")}`,
            curl: ctx.api.curl(attacker, "POST", path, row, profileHeaders(t)),
          },
        });
        await cleanupInserted(ctx, t, row, "tp_impersonate");
      }
    }
  }
}

const sharedRow = (ctx: Ctx, ref: string): OwnedRow | undefined => (ctx.world.unscoped.has(ref) ? ctx.world.owned.find((o) => o.table === ref) : undefined);

/** Candidate argument values from the victim's data, by Postgres type. */
const SECRET_COLUMN = /token|secret|password|passcode|passphrase|hash|otp|nonce|api_?key|private_?key|signature/i;
/** Codes a user hands out to others (a join code, an invite code, a share slug): the caller must know them. */
const SHARED_CODE_COLUMN = /(^|_)(code|slug|invite|share|join)(_|$)/i;

function victimValues(ctx: Ctx, victim: Actor, type: string): unknown[] {
  const rows = ctx.world.owned.filter((o) => o.owner === victim.label);
  if (type === "uuid") return [...new Set(rows.flatMap((o) => Object.values(o.pk)).filter((v) => typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v)))].concat(victim.userId ?? []);
  if (/^(integer|bigint|smallint)$/.test(type)) {
    // Keys first, then any other whole number in the victim's rows (an order or payment code).
    const keys = rows.flatMap((o) => Object.values(o.pk));
    const others = rows.flatMap((o) => Object.entries(o.row).filter(([c]) => !(c in o.pk)).map(([, v]) => v));
    return [...new Set([...keys, ...others].filter((v) => /^\d{1,18}$/.test(String(v))).map(Number))];
  }
  if (/^(text|character varying)$/.test(type))
    // Never a secret the attacker could not know (an invite token, a password hash): passing it
    // would "prove" a leak that needs the secret in the first place.
    return [
      ...new Set(
        rows.flatMap((o) => Object.entries(o.row).filter(([c]) => !SECRET_COLUMN.test(c)).map(([, v]) => v)).filter((v): v is string => typeof v === "string" && v.length < 80 && !/^[0-9a-f-]{36}$/i.test(v)),
      ),
    ];
  return [];
}

/** A fixed embedding; test rows get the same one, so similarity searches match the victim's rows. */
export const vectorLiteral = (dims: number) => `[${Array.from({ length: dims }, () => "0.1").join(",")}]`;

/** Values for a function argument: the victim's own values first, then a sensible default by type. */
/** The table whose row type `type` names (team_members, public.team_members), if any. */
function rowTypeOf(ctx: Ctx, type: string): Relation | undefined {
  const bare = type.replace(/"/g, "");
  return ctx.schema.relations.find((r) => qualified(r) === bare || (r.schema === "public" && r.name === bare));
}

/** Columns whose values anyone can learn (a URL slug, a handle, a month): fair to hand an attacker. */
const PUBLIC_TEXT = /(^|_)(slug|handle|username|month|period|scope)$/i;

/**
 * The victim's ids, best guesses first: rows of a table the argument is named after (p_workspace_id,
 * workspace), then rows of tables the function body mentions, then the rest. Calls are capped, so the
 * order decides whether the right record is tried at all.
 */
/** Where each argument value came from (trace ids, "args/parent-column"); the first source wins. */
type Sources = Map<unknown, string>;
const source = (src: Sources | undefined, values: unknown[], via: string, override = false) => {
  for (const v of values) if (src && (override || !src.has(v))) src.set(v, via);
};

function targetedIds(ctx: Ctx, victim: Actor, f: RpcFunction | undefined, name: string, src?: Sources): string[] {
  const all = victimValues(ctx, victim, "uuid") as string[];
  if (!f) return source(src, all, "args/victim-id"), all;
  const stem = name.replace(/^(p|in|_)_?/i, "").replace(/_?id$/i, "").toLowerCase();
  const body = f.body.toLowerCase();
  const rank = (table: string) => {
    const bare = table.split(".").pop()!.toLowerCase();
    if (stem && (bare === stem || bare === `${stem}s` || bare === `${stem}es` || bare.replace(/ies$/, "y") === stem)) return 0;
    return new RegExp(`\\b${bare}\\b`).test(body) ? 1 : 2;
  };
  const rankedPairs = ctx.world.owned
    .filter((o) => o.owner === victim.label)
    .flatMap((o) => Object.values(o.pk).filter((v): v is string => typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v)).map((v) => ({ v, r: rank(o.table) })))
    .sort((a, b) => a.r - b.r);
  const ranked = rankedPairs.map((x) => x.v);
  const userFirst = /user|owner|member|profile|account|author|creator/i.test(name) && victim.userId ? [victim.userId] : [];
  // The victim's own rows that carry a column named like the argument (p_organization_id and a
  // membership row's organization_id): the parent they belong to, even when that parent table is
  // shared and none of its rows count as theirs.
  const col = name.replace(/^(p|in|_)_?/i, "").toLowerCase();
  const byColumn = /_id$/.test(col)
    ? ctx.world.owned.filter((o) => o.owner === victim.label).map((o) => o.row[col]).filter((v): v is string => typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v))
    : [];
  // The column the body compares the argument to (where job_id = p_ref): the victim's values in that
  // column, whatever the argument is called. Plain "id" is left to the table ranking above.
  const compared = new Set([...comparedColumns(f, name)].filter((c) => c !== col && c !== "id"));
  const byCompared = compared.size
    ? ctx.world.owned
        .filter((o) => o.owner === victim.label)
        .flatMap((o) => Object.entries(o.row).filter(([k, v]) => compared.has(k.toLowerCase()) && typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v)).map(([, v]) => v as string))
    : [];
  source(src, userFirst, "args/user-id");
  source(src, byColumn, "args/parent-column");
  source(src, byCompared, "args/compared-column");
  for (const x of rankedPairs) source(src, [x.v], x.r === 0 ? "args/named-table" : x.r === 1 ? "args/table-in-body" : "args/victim-id");
  source(src, all, "args/victim-id");
  return [...new Set([...userFirst, ...byColumn, ...byCompared, ...ranked, ...all])];
}

/**
 * Calls built from one of the victim's rows, so arguments that must agree do: p_account_id is the
 * row's key when the table is named after the argument, p_org_id is the row's own org_id. Rows of
 * tables the body mentions only; other arguments take their first candidate.
 */
function rowTries(ctx: Ctx, victim: Actor, f: RpcFunction, required: { name: string; type: string }[], pools: unknown[][]): Row[] {
  if (required.length < 2) return [];
  const body = f.body.toLowerCase();
  const plain = (n: string) => n.replace(/^(p|in|_)_/i, "").toLowerCase();
  const stemOf = (n: string) => plain(n).replace(/_?id$/, "");
  const own = ctx.world.owned.filter((o) => o.owner === victim.label);
  // The row's parents (one and two links up) that belong to the victim too: a function often finds the
  // parent by one value and the row by its id (an event by its code, then the round by id and revision).
  const parentsOf = (o: OwnedRow, depth: number): OwnedRow[] => {
    if (depth === 0) return [];
    const t = ctx.schema.relations.find((r) => `${r.schema}.${r.name}` === o.table);
    const out: OwnedRow[] = [];
    for (const fk of t?.foreignKeys ?? []) {
      if (fk.columns.length !== 1 || o.row[fk.columns[0]] == null) continue;
      const p = own.find((x) => x.table === `${fk.refSchema}.${fk.refTable}` && String(x.row[fk.refColumns[0]]) === String(o.row[fk.columns[0]]));
      if (p && p !== o && !out.includes(p)) out.push(p, ...parentsOf(p, depth - 1));
    }
    return out;
  };
  const out: Row[] = [];
  for (const o of own) {
    const bare = o.table.split(".").pop()!.toLowerCase();
    if (!new RegExp(`\\b${bare}\\b`).test(body)) continue;
    const pk = Object.values(o.pk);
    const parents = parentsOf(o, 2);
    let matched = 0;
    let textKey = false;
    let valueKey = false;
    let fromParent = false;
    const call = Object.fromEntries(
      required.map((a, j) => {
        const st = stemOf(a.name);
        if (a.type === "uuid" && pk.length === 1 && (bare === st || bare === `${st}s` || bare === `${st}es` || bare.replace(/ies$/, "y") === st)) return matched++, [a.name, pk[0]];
        // Only ids come from the row; a name or note copied from it would make a write a no-op.
        const col = a.type === "uuid" ? Object.keys(o.row).find((c) => !SECRET_COLUMN.test(c) && (c.toLowerCase() === plain(a.name) || c.toLowerCase() === `${plain(a.name)}_id`)) : undefined;
        if (col && o.row[col] !== null && o.row[col] !== undefined) return matched++, [a.name, o.row[col]];
        const compared = comparedColumns(f, a.name);
        // A text argument the body looks rows up by (month = p_month) is a key, not content: the
        // row's own value, so the call reaches that row.
        const key = /^(text|character varying|citext)/.test(a.type) ? Object.keys(o.row).find((c) => !SECRET_COLUMN.test(c) && compared.has(c.toLowerCase())) : undefined;
        if (key && typeof o.row[key] === "string" && o.row[key]) return matched++, (textKey = true), [a.name, o.row[key]];
        // An id, a date or a number the body compares to a column of the row (r.id = p_round,
        // r.revision = p_revision): the row's own value.
        const scalar = /^(uuid|date|timestamp|time|integer|bigint|smallint|numeric|real|double)/.test(a.type) ? Object.keys(o.row).find((c) => compared.has(c.toLowerCase()) && o.row[c] != null) : undefined;
        if (scalar) return matched++, a.type !== "uuid" && (valueKey = true), [a.name, o.row[scalar]];
        // The same, from one of the row's own parents (e.studio_id = p_studio). A code, slug or token
        // found there is never sent as found: that is a secret the caller must know, settled by the
        // secret gate with this same call.
        for (const p of parents) {
          const pc = Object.keys(p.row).find((c) => compared.has(c.toLowerCase()) && p.row[c] != null && p.row[c] !== "");
          if (!pc) continue;
          const isText = /^(text|character varying|citext)/.test(a.type);
          if (isText && (SECRET_COLUMN.test(pc) || SHARED_CODE_COLUMN.test(pc))) break;
          return matched++, (fromParent = true), isText ? (textKey = true) : a.type !== "uuid" && (valueKey = true), [a.name, p.row[pc]];
        }
        if (f.volatile && /^(text|character varying)$/.test(a.type) && !comparedLiterals(f, a.name).length) return [a.name, `tp_write_${a.name.replace(/\W+/g, "")}_${victim.label.replace(/\W+/g, "").toLowerCase()}`];
        return [a.name, pools[j][0]];
      }),
    );
    mark(call, "args/row-tries");
    if (textKey) mark(call, "args/row-text-key");
    if (valueKey) mark(call, "args/row-value-key");
    if (fromParent) mark(call, "args/row-parents");
    if (Object.values(call).some((v) => typeof v === "string" && v.startsWith("tp_write_"))) mark(call, "args/write-marker");
    if (matched >= 2) out.push(call);
    if (out.length >= 4) break;
  }
  return out;
}

/**
 * Arguments a function inserts straight into a table (INSERT INTO usage (project_id, period_start, n)
 * VALUES (p_project_id, p_period_start, p_n) ON CONFLICT ... DO UPDATE): each takes the victim's value
 * for its column. A link column gets the victim's parent row; any other column, dates and numbers
 * included, the value in one of the victim's rows of that table, so a conflict update lands on it.
 */
function insertTries(ctx: Ctx, victim: Actor, f: RpcFunction, required: { name: string; type: string }[], pools: unknown[][]): Row[] {
  const body = f.body.replace(/--[^\n]*/g, "");
  const out: Row[] = [];
  const argAt = (expr: string) => {
    const e = expr.trim().replace(/::[\w ]+$/, "").replace(/^\(|\)$/g, "").split(".").pop()!.toLowerCase();
    return required.findIndex((a) => a.name.toLowerCase() === e);
  };
  for (const m of body.matchAll(/insert\s+into\s+([\w".]+)\s*\(([^)]*)\)\s*values\s*\(([^;]*?)\)\s*(?:on\s+conflict\s*(?:\(([^)]*)\))?|returning|;|$)/gi)) {
    const [schemaName, tableName] = m[1].includes(".") ? m[1].replace(/"/g, "").split(".") : ["public", m[1].replace(/"/g, "")];
    const t = ctx.schema.relations.find((r) => r.schema === schemaName && r.name === tableName);
    if (!t) continue;
    const cols = m[2].split(",").map((c) => c.trim().replace(/"/g, ""));
    const vals = splitTop(m[3]);
    if (cols.length !== vals.length) continue;
    const mapped = cols.map((c, i) => ({ col: c, arg: argAt(vals[i]) })).filter((x) => x.arg >= 0);
    // Only keys come from the victim's row (links, the conflict target, the primary key): an amount
    // copied from it (a count of 0) would make the write a no-op.
    const conflict = (m[4] ?? "").split(",").map((c) => c.trim().replace(/"/g, "")).filter(Boolean);
    const isKey = (c: string) => conflict.includes(c) || t.primaryKey.includes(c) || t.foreignKeys.some((k) => k.columns.includes(c));
    if (mapped.length < 2) continue;
    const own = ctx.world.owned.filter((o) => o.owner === victim.label);
    const rows = own.filter((o) => o.table === `${t.schema}.${t.name}`);
    for (const base of rows.length ? rows.slice(0, 3) : [undefined]) {
      const call: Row = Object.fromEntries(required.map((a, j) => [a.name, pools[j][0]]));
      let filled = 0;
      for (const { col, arg } of mapped) {
        const fk = t.foreignKeys.find((k) => k.columns.length === 1 && k.columns[0] === col);
        if (!isKey(col)) continue;
        let v = base?.row[col];
        if ((v === null || v === undefined) && fk) v = own.find((o) => o.table === `${fk.refSchema}.${fk.refTable}`)?.row[fk.refColumns[0]];
        if (v === null || v === undefined) continue;
        call[required[arg].name] = v;
        filled++;
      }
      if (filled < 2) continue;
      mark(call, "args/insert-columns");
      out.push(call);
    }
    if (out.length) break;
  }
  return out;
}

/** Comma-separated items at the top level of a list (commas inside calls or quotes do not split). */
function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0, quote = false, cur = "";
  for (const ch of s) {
    if (ch === "'") quote = !quote;
    if (!quote && ch === "(") depth++;
    if (!quote && ch === ")") depth--;
    if (!quote && depth === 0 && ch === ",") (out.push(cur), (cur = ""));
    else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/** Text values the function body compares an argument with (resource = 'voice', kind in ('a', 'b')). */
function comparedLiterals(f: RpcFunction | undefined, name: string): string[] {
  if (!f || !name) return [];
  const n = name.replace(/[^\w]/g, "");
  const out = new Set<string>();
  for (const m of f.body.matchAll(new RegExp(`\\b${n}\\s*(?:=|<>|!=)\\s*'([^']{1,60})'|'([^']{1,60})'\\s*(?:=|<>|!=)\\s*${n}\\b`, "gi"))) out.add(m[1] ?? m[2]);
  for (const m of f.body.matchAll(new RegExp(`\\b${n}\\s+in\\s*\\(([^)]{1,300})\\)`, "gi"))) for (const l of m[1].matchAll(/'([^']{1,60})'/g)) out.add(l[1]);
  for (const m of f.body.matchAll(new RegExp(`\\bcase\\s+${n}\\b([\\s\\S]{0,600}?)\\bend\\b`, "gi"))) for (const l of m[1].matchAll(/\bwhen\s+'([^']{1,60})'/gi)) out.add(l[1]);
  return [...out].slice(0, 6);
}

function argValues(ctx: Ctx, victim: Actor, type: string, volatile: boolean, name = "", f?: RpcFunction, src?: Sources): unknown[] {
  let vals = type === "uuid" ? targetedIds(ctx, victim, f, name, src) : victimValues(ctx, victim, type);
  if (type !== "uuid") source(src, vals, "args/victim-value");
  // A user to leave out (p_exclude_user_id): the victim's own id would leave out exactly the victim,
  // so first an id that belongs to nobody.
  if (/^uuid(\[\])?$/.test(type) && /(^|_)(exclude|excluded|excluding|except|skip|ignore|without|omit)(_|$)/i.test(name)) {
    const nobody = type === "uuid" ? crypto.randomUUID() : [crypto.randomUUID()];
    vals = [nobody, ...vals];
    source(src, [nobody], "args/excluded-id", true);
  }
  if (/^(text|character varying)$/.test(type)) {
    // A write probe must not hand the attacker secrets they could not know (invite tokens): text
    // arguments get the scan's own marker strings and values from columns anyone can learn.
    if (volatile) {
      const known = new Set(ctx.world.owned.filter((o) => o.owner === victim.label).flatMap((o) => Object.entries(o.row).filter(([c, v]) => PUBLIC_TEXT.test(c) && typeof v === "string").map(([, v]) => v as string)));
      vals = vals.filter((v) => String(v).startsWith("tp_") || known.has(String(v)));
    }
    // Named for a standard list (p_timezone, currency): a real value, or the call fails before it acts.
    const known = wellKnownValue(name);
    if (known !== undefined) (vals = [known, ...vals]), source(src, [known], "args/well-known-format", true);
    // Arguments that pick a range of data: the widest common words, and the current month.
    if (/scope|mode|level|visibility/i.test(name)) (vals = ["global", "all", ...vals]), source(src, ["global", "all"], "args/scope-word", true);
    if (/month|period/i.test(name)) (vals = [new Date().toISOString().slice(0, 7), ...vals]), source(src, [vals[0]], "args/month", true);
    // Words the function branches on (if resource = 'voice'): without one, its write never runs.
    const literals = comparedLiterals(f, name);
    if (literals.length) (vals = [...literals, ...vals]), source(src, literals, "args/compared-literal", true);
  }
  // Amounts for a write (credit_cost, quantity): a small one first, so a limit check does not refuse the call.
  // A ceiling the caller passes in (p_monthly_limit, max_items, quota): a large one, so it lets the write through.
  if (volatile && /^(integer|bigint|smallint|numeric|real|double precision)/.test(type) && /(limit|max|cap|quota|threshold|allowance|ceiling)/i.test(name)) (vals = [1000000, ...vals]), source(src, [1000000], "args/large-ceiling", true);
  else if (volatile && /^(integer|bigint|smallint|numeric|real|double precision)/.test(type) && !/(^|_)id$/i.test(name)) (vals = [1, ...vals.filter((v) => v !== 1)]), source(src, [1], "args/small-amount", true);
  if (vals.length) return vals.slice(0, 12);
  return typeDefault(ctx, victim, type, src);
}

/** A value of the argument's type when none of the victim's data fits (a range, an enum, a row). */
function typeDefault(ctx: Ctx, victim: Actor, type: string, src?: Sources): unknown[] {
  const out = typeDefaultValues(ctx, victim, type);
  source(src, out, "args/type-default");
  return out;
}

function typeDefaultValues(ctx: Ctx, victim: Actor, type: string): unknown[] {
  if (type === "uuid[]") return [victimValues(ctx, victim, "uuid").slice(0, 5)];
  if (type.endsWith("[]")) {
    const labels = ctx.enums.get(type.slice(0, -2));
    return [labels ? [labels[0]] : []];
  }
  if (/^jsonb?$/.test(type)) return [{}];
  if (ctx.enums.has(type)) return ctx.enums.get(type)!.slice(0, 4);
  if (/^(numeric|real|double precision)/.test(type)) return [1];
  if (/^(integer|bigint|smallint)$/.test(type)) return [1];
  if (type === "boolean") return [false];
  if (/^(timestamp|date)/.test(type)) return [new Date().toISOString()];
  if (/^time\b/.test(type)) return ["09:00:00"];
  const vec = /^(?:\w+\.)?(vector|halfvec)\b/.exec(type);
  if (vec && ctx.vectorDims.get(vec[1])) return [vectorLiteral(ctx.vectorDims.get(vec[1])!)];
  if (/^(text|character varying)$/.test(type)) return [`tp_arg_${victim.label.replace(/\W+/g, "").toLowerCase()}`];
  // A row of a table: hand the function the victim's own record.
  const rel = rowTypeOf(ctx, type);
  if (rel) return ctx.world.owned.filter((o) => o.owner === victim.label && o.table === qualified(rel)).map((o) => o.row).slice(0, 3);
  if (type === "interval") return ["1 hour"];
  if (/^(tstzrange|tsrange)$/.test(type)) {
    const now = Date.now();
    return [`[${new Date(now).toISOString()},${new Date(now + 3600_000).toISOString()})`];
  }
  if (type === "daterange") return [`[${new Date().toISOString().slice(0, 10)},${new Date(Date.now() + 86400_000).toISOString().slice(0, 10)})`];
  if (/^(int4range|int8range|numrange)$/.test(type)) return ["[1,10)"];
  if (type === "bytea") return ["\\x00"];
  return [];
}

/** The victim's rows as text, keyed by table and primary key. Used to see whether a call changed them. */
const SHARED = "\u0000shared ";
const SHARED_ROW_CAP = 500;

/** Tables a function body inserts into, updates or deletes from, resolved against the schema. */
function writtenTables(ctx: Ctx, f: RpcFunction): Relation[] {
  const names = [...f.body.matchAll(/\b(?:insert\s+into|update|delete\s+from)\s+(?:only\s+)?((?:"?\w+"?\.)?"?\w+"?)/gi)].map((m) => m[1].replace(/"/g, ""));
  const rels = names.map((n) => ctx.schema.relations.find((r) => qualified(r) === n || (!n.includes(".") && r.schema === "public" && r.name === n)));
  return [...new Set(rels.filter((r): r is Relation => !!r && r.kind === "table" && r.primaryKey.length > 0))];
}

/**
 * What a call could change, read as plain statements so the snapshot can run inside the call's own
 * rolled-back operation. Three parts: the victim's own rows; rows anywhere that point at the victim
 * (their user id, or one of their records), so new rows created in their name show up; and, for
 * tables the function writes that belong to no tenant, every row, so deletes and edits of shared
 * data show up.
 */
function snapshotStatements(ctx: Ctx, victim: Actor, f?: RpcFunction) {
  const owned = new Map<string, OwnedRow[]>();
  for (const o of ctx.world.owned) if (o.owner === victim.label) owned.set(o.table, [...(owned.get(o.table) ?? []), o]);
  const keyOf = (rel: Relation) => `concat_ws(chr(31), ${rel.primaryKey.map((c) => `${ident(c)}::text`).join(", ")})`;
  const parts: { table: string; keys: string[]; shared: boolean; statement: SqlStatement }[] = [];
  // Tables with no path to a user (config, counters, logs) are shared, not anyone's tenant data.
  const tenant = new Set(tenantTables(ctx.schema).map(qualified).filter((t) => !ctx.world.unscoped.has(t)));
  for (const rel of ctx.schema.relations) {
    const table = qualified(rel);
    if (rel.kind !== "table" || !rel.primaryKey.length || !tenant.has(table)) continue;
    const keys = (owned.get(table) ?? []).map((o) => rel.primaryKey.map((c) => String(o.pk[c])).join("\u001f"));
    const params: unknown[] = [keys];
    const conds = [`${keyOf(rel)} = any($1::text[])`];
    for (const fk of rel.foreignKeys) {
      if (fk.columns.length !== 1) continue;
      const ids = isUserRef(fk, ctx.world.profileTables)
        ? victim.userId
          ? [victim.userId]
          : []
        : (owned.get(`${fk.refSchema}.${fk.refTable}`) ?? []).map((o) => String(o.row[fk.refColumns[0]]));
      if (!ids.length) continue;
      params.push(ids);
      conds.push(`${ident(fk.columns[0])}::text = any($${params.length}::text[])`);
    }
    if (!keys.length && conds.length === 1) continue;
    parts.push({ table, keys, shared: false, statement: { text: `select ${keyOf(rel)} as k, to_jsonb(x)::text as j from ${qident(rel)} x where ${conds.join(" or ")} limit 200`, params } });
  }
  for (const rel of f ? writtenTables(ctx, f) : []) {
    const table = qualified(rel);
    if (tenant.has(table)) continue;
    parts.push({ table, keys: [], shared: true, statement: { text: `select ${keyOf(rel)} as k, left(to_jsonb(x)::text, 4000) as j from ${qident(rel)} x order by 1 limit ${SHARED_ROW_CAP}` } });
  }
  return {
    statements: parts.map((p) => p.statement),
    /** Keys of the victim's own rows; every other victim-side key was pulled in because it points at them. */
    owned: new Set(parts.filter((p) => !p.shared).flatMap((p) => p.keys.map((k) => `${p.table} ${k}`))),
    read(results: { rows: Row[] }[]): Map<string, string> {
      const out = new Map<string, string>();
      parts.forEach((p, i) => {
        const prefix = p.shared ? SHARED : "";
        for (const k of p.keys) out.set(`${prefix}${p.table} ${k}`, "(missing)");
        for (const r of results[i].rows) out.set(`${prefix}${p.table} ${r.k}`, r.j as string);
      });
      return out;
    },
  };
}

async function snapshotVictim(ctx: Ctx, victim: Actor, f?: RpcFunction): Promise<Map<string, string>> {
  const snap = snapshotStatements(ctx, victim, f);
  // One client runs one query at a time.
  const results = [];
  for (const st of snap.statements) results.push(await query(ctx.db, st.text, st.params));
  return snap.read(results);
}

/**
 * What a call changed. `victim`: the victim's rows that changed or disappeared, and rows that point
 * at the victim and appeared, changed or disappeared. A row that points at the victim but also carries
 * the caller's own id belongs to both of them (the caller's block of the victim, their friendship, a
 * message between them), so the caller changing it is a normal action between users, not counted. `shared`: existing rows of shared tables the call deleted
 * or edited; new shared rows (a log entry) are normal and not counted.
 */
function safeJson(t: string): Row | undefined {
  try {
    return JSON.parse(t) as Row;
  } catch {
    return undefined;
  }
}

function diffSnapshots(before: Map<string, string>, after: Map<string, string>, actorId?: string, owned = new Set<string>()): { victim: string[]; shared: string[] } {
  const joint = (k: string, ...json: string[]) => !!actorId && !owned.has(k) && json.some((j) => j.includes(actorId));
  const victim: string[] = [];
  const shared: string[] = [];
  for (const [k, v] of before) {
    const now = after.get(k) ?? "(missing)";
    if (now === v) continue;
    if (k.startsWith(SHARED)) {
      // A shared row that carries the caller's own id (their block of someone, a friendship) is theirs too.
      if (actorId && (v.includes(actorId) || now.includes(actorId))) continue;
      const [table, key] = k.slice(SHARED.length).split(" ");
      if (now === "(missing)") {
        shared.push(`${table} ${key.replace(/\u001f/g, ",")}: row deleted`);
        continue;
      }
      const a = safeJson(v);
      const b = safeJson(now);
      const cols = a && b ? Object.keys({ ...a, ...b }).filter((c) => JSON.stringify(a[c]) !== JSON.stringify(b[c])) : [];
      shared.push(`${table} ${key.replace(/\u001f/g, ",")}: ${cols.length ? cols.map((c) => `${c} ${short(a![c], 60)} -> ${short(b![c], 60)}`).join("; ") : "row changed"}`);
      continue;
    }
    const where = k.replace(/\u001f/g, ",");
    if (joint(k, v, now)) continue;
    if (now === "(missing)" || v === "(missing)") {
      victim.push(`${where}: ${now === "(missing)" ? "row deleted" : "row appeared"}`);
      continue;
    }
    const a = JSON.parse(v) as Row;
    const b = JSON.parse(now) as Row;
    const cols = Object.keys({ ...a, ...b }).filter((c) => JSON.stringify(a[c]) !== JSON.stringify(b[c]));
    victim.push(`${where}: ${cols.map((c) => `${c} ${short(a[c], 60)} -> ${short(b[c], 60)}`).join("; ")}`);
  }
  for (const [k, now] of after) {
    if (before.has(k) || k.startsWith(SHARED)) continue;
    if (joint(k, now)) continue;
    victim.push(`${k.replace(/\u001f/g, ",")}: row appeared`);
  }
  return { victim, shared };
}

/**
 * Run a function exactly the way PostgREST does (API role, the caller's JWT claims), inside a
 * transaction that is always rolled back. Reports what it returned and which victim rows it changed.
 */
async function callRolledBack(
  ctx: Ctx,
  f: RpcFunction,
  actor: Actor,
  args: Row,
  before: Map<string, string>,
  victim: Actor,
  ownCall = false,
  prime: SqlStatement[] = [],
): Promise<{ ok: boolean; output: string; changed: string[]; sharedChanged: string[]; error?: string }> {
  const names = Object.keys(args);
  const types = new Map(f.args.map((a) => [a.name, a.type]));
  const param = (n: string, i: number) => (rowTypeOf(ctx, types.get(n)!) ? `json_populate_record(null::${types.get(n)}, $${i + 1}::json)` : `$${i + 1}::${types.get(n)}`);
  const call = `${qident(f)}(${names.map((n, i) => `${ident(n)} => ${param(n, i)}`).join(", ")})`;
  const callSql = f.returnsSet ? `select coalesce(json_agg(r)::text, '') as out from ${call} r` : `select (${call})::text as out`;
  const claims = actor.token ? { sub: actor.userId, role: "authenticated", email: actor.email } : { role: "anon" };
  const snap = snapshotStatements(ctx, victim, f);
  // Rows put in a given state first (status = 'pending'), as the service connection with triggers
  // paused, then the "before" picture is taken inside the same transaction, so only the call counts.
  const head: SqlStatement[] = prime.length
    ? [{ text: "reset role" }, { text: "set local session_replication_role = replica" }, ...prime, { text: "set local session_replication_role = origin" }, ...snap.statements, { text: `set local role ${roleOf(actor) === "anon" ? "anon" : "authenticated"}` }]
    : [];
  const at = head.length;
  const [r] = await sql(ctx.db, [
    {
      role: roleOf(actor),
      claims,
      rollback: true,
      statements: [...head, { text: callSql, params: names.map((n) => toParam(args[n])) }, { text: "reset role" }, ...snap.statements],
    },
  ]);
  if (r.error && r.error.at !== undefined && r.error.at < at) return { ok: false, output: "", changed: [], sharedChanged: [], error: `row state not set: ${r.error.message}` };
  if (r.error?.at === at) return { ok: false, output: "", changed: [], sharedChanged: [], error: r.error.message };
  if (r.error) throw Object.assign(new Error(r.error.message), { code: r.error.code });
  const output = (r.results[at].rows[0]?.out as string | undefined) ?? "";
  const start = prime.length ? snap.read(r.results.slice(prime.length + 3, prime.length + 3 + snap.statements.length)) : before;
  // The owner calling on their own data: new rows that name them are theirs, not "joint" rows.
  const d = diffSnapshots(start, snap.read(r.results.slice(at + 2)), ownCall ? undefined : actor.userId, snap.owned);
  return { ok: true, output, changed: d.victim, sharedChanged: d.shared };
}

/**
 * 4. Call exposed functions with another tenant's ids (required args only). Read-only functions
 * go through the API. Functions that can write run in a rolled-back transaction, so nothing they
 * do survives the scan, and the victim's rows are compared before and after the call.
 */
/** Lab only (TENANTBLEED_DEBUG_RPC): one stderr line per function call, to see why calls settle nothing. */
function debugRpc(target: string, actor: Actor, victim: Actor, body: Row, outcome: string) {
  if (process.env.TENANTBLEED_DEBUG_RPC) process.stderr.write(`RPC ${target} ${actor.label}->${victim.label} ${short(JSON.stringify(body), 200)} => ${outcome}\n`);
}

async function rpcProbe(ctx: Ctx, actors: Actor[]) {
  const unnamed: string[] = [];
  for (const f of ctx.schema.functions) {
    if (["trigger", "event_trigger"].includes(f.returnType)) continue;
    if (!f.volatile && ["boolean", "void"].includes(f.returnType)) continue;
    // PostgREST calls functions by argument name; one with unnamed arguments (slugify(text)) cannot
    // be called with arguments through the API at all.
    if (f.args.some((a) => !a.name || /^arg\d+$/.test(a.name))) {
      unnamed.push(`${f.schema}.${f.name}`);
      continue;
    }
    // One function the database refuses to run (a value it cannot take) must not stop the others.
    try {
      await rpcProbeFunction(ctx, actors, f);
    } catch (e) {
      ctx.notes.push(`rpc probe skipped ${f.schema}.${f.name}: ${(e as Error).message}`);
    }
  }
  if (unnamed.length) ctx.notes.push(`Not callable through the API because their arguments have no names, so not tested: ${unnamed.join(", ")}.`);
}

/** What one function call did. */
interface CallResult {
  /** The call ran (200 from the API, or no error in the rolled-back transaction). */
  ok: boolean;
  status: number;
  output: string;
  /** The victim's rows it changed, and shared rows it changed. */
  changed: string[];
  sharedChanged: string[];
  /** The victim's values in what came back; values sent in are an echo, not a leak. */
  hits: string[];
  error?: string;
  /** The API's answer, for functions called over the API. */
  res?: ApiResponse;
}

/**
 * One function call, made as `actor` and aimed at `victim`'s data, the way the API runs it. Functions
 * that can write run inside a transaction that is rolled back, compared with the victim's snapshot
 * `before`; read-only ones go through the API. `ownCall` is the victim calling on their own data.
 * The one call primitive for the attack and the owner control.
 */
async function callAs(ctx: Ctx, f: RpcFunction, actor: Actor, victim: Actor, body: Row, before: Map<string, string>, label = "", ownCall = false, prime: SqlStatement[] = []): Promise<CallResult> {
  const target = `${f.schema}.${f.name}`;
  const sent = JSON.stringify(body);
  const hitsIn = (output: string) => findTokens(output, ctx.world.tokens.get(victim.label)!).filter((h) => !sent.includes(h));
  if (f.volatile) {
    const r = await callRolledBack(ctx, f, actor, body, before, victim, ownCall, prime);
    debugRpc(target, actor, victim, body, `${label}${r.ok ? `ran, ${r.changed.length} victim and ${r.sharedChanged.length} shared change(s)` : `error: ${r.error}`}`);
    return { ok: r.ok, status: r.ok ? 200 : 0, output: r.output, changed: r.changed, sharedChanged: r.sharedChanged, hits: r.ok ? hitsIn(r.output) : [], error: r.error };
  }
  const path = `/rest/v1/rpc/${f.name}`;
  const res = await ctx.api.request(actor, "POST", path, body, profileHeaders(f));
  debugRpc(target, actor, victim, body, `${label}${res.status} ${short(res.text, 160)}`);
  const ok = res.status === 200;
  return { ok, status: res.status, output: res.text, changed: [], sharedChanged: [], hits: ok ? hitsIn(res.text) : [], error: ok ? undefined : `${res.status} ${short(res.text, 80)}`, res };
}

async function rpcProbeFunction(ctx: Ctx, actors: Actor[], f: RpcFunction) {
  const required = f.args.slice(0, f.args.length - f.defaultedArgs);
  const target = `${f.schema}.${f.name}`;
  const path = `/rest/v1/rpc/${f.name}`;
  for (const actor of actors) {
    if (!(actor.token ? f.execAuthenticated : f.execAnon)) continue;
    for (const victim of victimsOf(ctx, actor)) {
      let tries: Row[];
      if (!required.length) tries = [{}];
      else {
        const srcs = required.map((): Sources => new Map());
        const pools = required.map((a, j) => argValues(ctx, victim, a.type, f.volatile, a.name, f, srcs[j]));
        if (pools.some((p) => !p.length)) {
          debugRpc(target, actor, victim, {}, `skipped: no value for ${required.filter((_, i) => !pools[i].length).map((a) => `${a.name} ${a.type}`).join(", ")}`);
          continue;
        }
        // Same candidate index for every argument keeps the number of calls small.
        const n = Math.max(...pools.map((p) => p.length));
        tries = Array.from({ length: n }, (_, i) => {
          const body = Object.fromEntries(required.map((a, j) => [a.name, pools[j][i % pools[j].length]]));
          required.forEach((a, j) => {
            const via = srcs[j].get(body[a.name]);
            if (via) mark(body, via);
          });
          return body;
        });
        // Arguments that must agree (an account and its own org) come from one real row first.
        tries = [...insertTries(ctx, victim, f, required, pools), ...rowTries(ctx, victim, f, required, pools), ...tries];
      }
      // Functions that can write are run in the database, so first make sure the API serves them at
      // all. GET runs in a read-only transaction: a served volatile function answers 405/4xx without
      // writing anything, an unserved one answers 404 (PGRST202) or 406 (schema not exposed).
      if (f.volatile) {
        const qs = new URLSearchParams(Object.entries(tries[0]).map(([k, v]) => [k, String(v)])).toString();
        const probe = await ctx.api.request(actor, "GET", `${path}${qs ? `?${qs}` : ""}`, undefined, profileHeaders(f));
        if (probe.status === 404 || probe.status === 406) {
          track(ctx, target, "function", probe);
          continue;
        }
      }
      const before = f.volatile ? await snapshotVictim(ctx, victim, f) : new Map<string, string>();
      let leaked = false;
      let wrote = false;
      let wroteShared = false;
      // Bodies the attacker's call was refused for: the owner control compares them.
      const refusedBodies = new Map<string, string>();
      let derivedChecked = false;
      for (const body of tries) {
        const r = await callAs(ctx, f, actor, victim, body, before);
        // The whole message: cut short, two identical refusals would compare as different.
        if (r.error) refusedBodies.set(JSON.stringify(body), r.error);
        if (f.volatile && r.error && /permission denied/i.test(r.error)) {
          const c = ctx.coverage.get(target) ?? { relation: target, kind: "function" as const, reached: 0, unreachable: 0, populated: true };
          c.refused = (c.refused ?? 0) + 1;
          c.refusedMessage ??= short(r.error, 120);
          ctx.coverage.set(target, c);
          continue;
        }
        // The body uses something the schema does not have (a table a later migration dropped): the
        // call reached the function and failed inside it. Not a reached call, and not "not served".
        // A name the caller passed in (EXECUTE format('drop table %I', p_table)) is the test value
        // missing, not the function broken.
        const missing = /\b(?:relation|column|function|type|schema) "?([^"\s]+)"? does not exist\b/i.exec(r.error ?? "")?.[1];
        const passedIn = !!missing && Object.values(body ?? {}).some((v) => {
          const t = typeof v === "string" ? v : JSON.stringify(v ?? "");
          const bare = missing.replace(/^.*\./, "").replace(/\(.*$/, "");
          return (t.length >= 3 && (t.includes(bare) || bare.includes(t))) || /^tp_/i.test(bare);
        });
        if (r.error && missing && !passedIn && !/could not find the function/i.test(r.error)) {
          const c = ctx.coverage.get(target) ?? { relation: target, kind: "function" as const, reached: 0, unreachable: 0, populated: true };
          c.unreachable++;
          c.broken ??= short(r.error, 160);
          ctx.coverage.set(target, c);
          continue;
        }
        track(ctx, target, "function", r.res ?? { status: 200, body: null, text: "" });
        if (!r.ok) continue;
        const via = marksOf(body);
        const ev = { actor: actor.label, victim: victim.label, request: { method: "POST", path, body }, status: r.status, curl: ctx.api.curl(actor, "POST", path, body, profileHeaders(f)), ...(via.length ? { via } : {}) };
        // Functions listed under "shared" in tenantbleed.json return other users' data by design
        // (a public profile, a storefront). Writes through them are still checked.
        if (!leaked && r.hits.length && !ctx.world.unscoped.has(target)) {
          leaked = true;
          observe(ctx, { probe: "rpc-leak", target, actor: actor.label, victim: victim.label, facts: { output: r.output, hits: r.hits }, evidence: { ...ev, proof: short(r.output) } });
        }
        if (!wrote && r.changed.length) {
          wrote = true;
          observe(ctx, { probe: "rpc-write", target, actor: actor.label, victim: victim.label, facts: { changed: r.changed }, evidence: { ...ev, proof: r.changed.slice(0, 3).join("\n") } });
        }
        if (!wroteShared && r.sharedChanged.length) {
          wroteShared = true;
          observe(ctx, { probe: "rpc-write", target, actor: actor.label, victim: victim.label, facts: { changed: r.sharedChanged, shared: true }, evidence: { ...ev, proof: r.sharedChanged.slice(0, 3).join("\n") } });
        }
        if (!leaked && !derivedChecked && !r.changed.length && !r.sharedChanged.length && !ctx.world.unscoped.has(target)) {
          derivedChecked = true;
          const d = await derivedValue(ctx, f, actor, victim, body, before, r.output);
          if (d) {
            leaked = true;
            trace("args/blank-id-compare", target);
            observe(ctx, { probe: "rpc-leak", target, actor: actor.label, victim: victim.label, facts: { output: r.output, hits: [], derived: { blank: d } }, evidence: { ...ev, proof: `${short(r.output, 120)} for ${victim.label}'s id; ${short(d, 120)} for an id that does not exist` } });
          }
        }
        if (leaked && (wrote || !f.volatile)) break;
      }
      if (!leaked && !wrote && !wroteShared && victim.token) {
        await ownerControl(ctx, f, victim, tries, before, refusedBodies);
        if (ctx.coverage.get(target)?.ownerControl === "no-effect") await secretGate(ctx, f, actor, victim, tries, before);
        if (ctx.coverage.get(target)?.ownerControl === "no-effect") await victimRemoval(ctx, f, actor, victim, tries);
        // Maintenance by age acts on old rows by design; making a row old first would prove nothing.
        if (ctx.coverage.get(target)?.ownerControl === "no-effect" && !timeMaintenance(f)) await rowState(ctx, f, actor, victim, tries, before);
      }
    }
  }
}

/** Text matched literally inside a RegExp. */
const escapeRe = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Columns the function body compares an argument to (where job_id = p_ref, d.slug = p_slug), lowercase. */
const comparedCache = new WeakMap<RpcFunction, Map<string, Set<string>>>();
function comparedColumns(f: RpcFunction, argName: string): Set<string> {
  const perFn = comparedCache.get(f) ?? new Map<string, Set<string>>();
  comparedCache.set(f, perFn);
  const hit = perFn.get(argName);
  if (hit) return hit;
  const body = f.body.replace(/--[^\n]*/g, "").toLowerCase();
  const arg = `(?:${escapeRe(f.name.toLowerCase())}\\.)?${escapeRe(argName.toLowerCase())}`;
  // "set name = p_name" assigns, it does not look anything up: the nearest keyword before it decides.
  const keywords = [...body.matchAll(/\b(set|where|and|or|on|when|if|returning|values|select)\b/g)].map((m) => ({ at: m.index, word: m[1] }));
  const assigns = (at: number) => keywords.filter((k) => k.at < at).at(-1)?.word === "set";
  const cols = new Set<string>();
  for (const m of body.matchAll(new RegExp(`([\\w"]+(?:\\.[\\w"]+)?)\\s*=\\s*${arg}\\b`, "g"))) if (!assigns(m.index)) cols.add(m[1].split(".").pop()!.replace(/"/g, ""));
  for (const m of body.matchAll(new RegExp(`(?<![\\w.])${arg}\\s*=\\s*([\\w"]+(?:\\.[\\w"]+)?)`, "g"))) if (!assigns(m.index)) cols.add(m[1].split(".").pop()!.replace(/"/g, ""));
  cols.delete(argName.toLowerCase());
  perFn.set(argName, cols);
  return cols;
}
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** An answer that is a refusal or a "not found", whatever its status: never evidence of a leak. */
const REFUSAL_TEXT = /error|denied|not allowed|forbidden|unauthori|not a member|not found|no access|invalid|exception/i;

/**
 * A number or a word about the victim (a member count, a plan name) carries none of the scan's
 * markers, so "it returned their data" cannot be seen in it. Ask the same question about an id that
 * exists nowhere: a different, stable answer means the function looked at the victim's records for
 * the caller. Each answer is asked twice (a random or time-based answer is never a leak), and the
 * ids sent in are blanked in both, so an echo of the argument does not count.
 */
async function derivedValue(ctx: Ctx, f: RpcFunction, actor: Actor, victim: Actor, body: Row, before: Map<string, string>, answer: string): Promise<string | undefined> {
  if (f.returnType === "void" || !answer || REFUSAL_TEXT.test(answer)) return undefined;
  const theirs = ctx.world.tokens.get(victim.label)!;
  const sent: string[] = [];
  const swap = (v: unknown): unknown => {
    if (typeof v === "string" && UUID_RE.test(v) && theirs.has(v)) {
      sent.push(v);
      return crypto.randomUUID();
    }
    return Array.isArray(v) ? v.map(swap) : v;
  };
  const blankBody = Object.fromEntries(Object.entries(body).map(([k, v]) => [k, swap(v)]));
  if (!sent.length) return undefined;
  const ids = [...sent, ...Object.values(blankBody).flat().filter((v): v is string => typeof v === "string" && UUID_RE.test(v))];
  const norm = (out: string) => ids.reduce((o, id) => o.split(id).join("<id>"), out);
  const ask = async (b: Row) => {
    const r = await callAs(ctx, f, actor, victim, b, before, "blank-id compare: ");
    return r.ok && !r.changed.length && !r.sharedChanged.length ? norm(r.output) : undefined;
  };
  const blank = await ask(blankBody);
  if (blank === undefined || blank === norm(answer) || REFUSAL_TEXT.test(blank)) return undefined;
  // Twice each: an answer that changes by itself (random, the clock) is not about the victim.
  if ((await ask(body)) !== norm(answer) || (await ask(blankBody)) !== blank) return undefined;
  return blank;
}

/**
 * Lookups by a secret value (a share slug, an invite code, a token): without the exact value they
 * return nothing, which is the design, and the owner control cannot tell that apart from test values
 * that missed. The body says which column the argument is compared to (d.public_slug = p_slug); the
 * scan calls as another user with the victim's own value from that column. An answer with it, and
 * none with the wrong value, shows the value is the only gate. Never a finding: a share link answers
 * whoever holds it.
 */
async function secretGate(ctx: Ctx, f: RpcFunction, actor: Actor, victim: Actor, tries: Row[], before: Map<string, string>) {
  const target = `${f.schema}.${f.name}`;
  const c = ctx.coverage.get(target);
  if (!c || c.ownerControl !== "no-effect" || !tries.length) return;
  const required = f.args.slice(0, f.args.length - f.defaultedArgs);
  const empty = (out: string) => !out.trim() || /^(null|\[\]|\{\}|""|false)$/i.test(out.trim());
  let wrong: string | undefined;
  for (const a of required.filter((x) => /^(text|character varying|citext)/.test(x.type))) {
    const cols = comparedColumns(f, a.name);
    if (!cols.size) continue;
    const values = new Map<string, string>();
    for (const o of ctx.world.owned.filter((x) => x.owner === victim.label))
      for (const [col, v] of Object.entries(o.row)) if (cols.has(col.toLowerCase()) && typeof v === "string" && v) values.set(v, `${o.table}.${col}`);
    for (const [value, where] of [...values].slice(0, 3)) {
      wrong ??= (await callAs(ctx, f, actor, victim, tries[0], before, "secret gate (wrong value): ")).output;
      const r = await callAs(ctx, f, actor, victim, { ...tries[0], [a.name]: value }, before, "secret gate: ");
      if (!r.ok) continue;
      if (r.hits.length || r.changed.length || (!empty(r.output) && r.output !== wrong && !REFUSAL_TEXT.test(r.output))) {
        c.ownerControl = "secret-gated";
        c.ownerDetail = `answered another user who sent ${victim.label}'s ${where} value, and nothing for any other value`;
        ctx.coverage.set(target, c);
        trace("owner-control/secret-gated", target);
        return;
      }
    }
  }
}

/**
 * A function that takes nothing aimed at the victim (no arguments, or none of their values) cannot be
 * pointed at them, and a total or a status carries none of the scan's markers, so neither "their data
 * came back" nor the blank-id compare can tell. Ask the database instead: the attacker's answer, in a
 * transaction that is rolled back, with and without the victim's rows in the tables the body reads.
 * A different answer means it tells any caller something about the victim (a derived value); the same
 * answer, twice, means it does not depend on them at all, which settles it.
 */
async function victimRemoval(ctx: Ctx, f: RpcFunction, actor: Actor, victim: Actor, tries: Row[]) {
  const target = `${f.schema}.${f.name}`;
  const c = ctx.coverage.get(target);
  if (!c || f.returnType === "void" || f.returnType === "trigger") return;
  const body = tries[0] ?? {};
  const theirs = ctx.world.tokens.get(victim.label) ?? new Set<string>();
  const aimed = (v: unknown): boolean => (Array.isArray(v) ? v.some(aimed) : typeof v === "string" && theirs.has(v));
  if (Object.values(body).some(aimed)) return;
  const text = f.body.toLowerCase();
  const rows = ctx.world.owned.filter((o) => o.owner === victim.label && new RegExp(`\\b${escapeRe(o.table.split(".").pop()!.toLowerCase())}\\b`).test(text));
  if (!rows.length) return;
  const args = Object.keys(body);
  const call: SqlStatement = {
    text: `select coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb)::text as out from ${ident(f.schema)}.${ident(f.name)}(${args.map((a, i) => `${ident(a)} => $${i + 1}`).join(", ")}) as x`,
    params: args.map((a) => (typeof body[a] === "object" && body[a] !== null ? JSON.stringify(body[a]) : body[a])),
  };
  const asCaller: SqlStatement[] = actor.token
    ? [
        { text: "select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true)", params: [JSON.stringify({ sub: actor.userId, role: "authenticated" }), actor.userId ?? ""] },
        { text: "set local role authenticated" },
      ]
    : [{ text: "set local role anon" }];
  const without: SqlStatement[] = rows.map((o) => {
    const [schema, name] = o.table.split(".");
    const keys = Object.keys(o.pk);
    return { text: `DELETE FROM ${ident(schema)}.${ident(name)} WHERE ${keys.map((k, i) => `${ident(k)}::text = $${i + 1}`).join(" and ")}`, params: keys.map((k) => String(o.pk[k])) };
  });
  const answer = async (removed: boolean) => {
    // Rules paused for taking the rows out (no cascades or triggers firing elsewhere); always rolled back.
    const [r] = await sql(ctx.db, [{ replica: true, rollback: true, statements: [...(removed ? without : []), ...asCaller, call] }]);
    return r.error ? undefined : String(r.results.at(-1)?.rows[0]?.out ?? "");
  };
  const base = await answer(false);
  if (base === undefined || (await answer(false)) !== base) return;
  const other = await answer(true);
  if (other === undefined) return;
  if (other !== base) {
    trace("owner-control/victim-removal", target);
    // A single plain value reads as itself ([2] is how one row of one number comes back).
    const shown = (out: string) => (/^\[[^[\]{},]*\]$/.test(out) ? out.slice(1, -1) : out);
    const path = `/rest/v1/rpc/${f.name}`;
    observe(ctx, {
      probe: "rpc-leak",
      target,
      actor: actor.label,
      victim: victim.label,
      facts: { output: shown(base), hits: [], derived: { blank: shown(other), by: "removal" } },
      evidence: { actor: actor.label, victim: victim.label, request: { method: "POST", path, body }, status: 200, curl: ctx.api.curl(actor, "POST", path, body, profileHeaders(f)), proof: `${short(shown(base), 120)} for ${actor.label}; ${short(shown(other), 120)} once ${victim.label}'s ${rows.length} row(s) are left out` },
    });
    return;
  }
  // A function that writes can still reach the victim's rows later (a cleanup once they are old):
  // the same answer settles only functions that only read.
  if (/\b(insert\s+into|update\s+[\w".]+\s+set|delete\s+from|truncate)\b/i.test(f.body)) return;
  if ((await answer(true)) !== other) return;
  c.ownerControl = "victim-independent";
  c.ownerDetail = `gave ${actor.label} the same answer with and without ${victim.label}'s rows in ${[...new Set(rows.map((o) => o.table))].slice(0, 4).join(", ")}`;
  ctx.coverage.set(target, c);
  trace("owner-control/victim-independent", target);
}

/**
 * The state a write waits for: in UPDATE and DELETE statements, WHERE conditions that compare a
 * column of the written table with a constant (status = 'pending', delivered_at is null,
 * message_count > 0, starts_at < now()). Freshly made test rows rarely sit in that state, so the
 * write matches nothing for anyone. Returns the statements that put the owner's rows of those tables
 * in that state, and a short description of it.
 */
function rowStatePrime(ctx: Ctx, f: RpcFunction, owner: Actor): { statements: SqlStatement[]; desc: string } {
  const body = f.body.replace(/--[^\n]*/g, "").replace(/\s+/g, " ");
  const statements: SqlStatement[] = [];
  const said: string[] = [];
  const lit = String.raw`(-?\d+(?:\.\d+)?|true|false|'(?:[^']|'')*'|now\(\)|current_timestamp)`;
  // UPDATE and DELETE act only on rows in the state their WHERE names; a SELECT ... INTO that finds
  // the row first (then raises when not found) gates the write the same way.
  for (const m of body.matchAll(/\b(?:update\s+(?:only\s+)?([\w".]+)(?:\s+(?:as\s+)?(?!set\b)(\w+))?\s+set\b|delete\s+from\s+(?:only\s+)?([\w".]+)(?:\s+(?:as\s+)?(?!where\b)(\w+))?|select\b[^;]*?\binto\b[^;]*?\bfrom\s+(?:only\s+)?([\w".]+)(?:\s+(?:as\s+)?(?!where\b|join\b|left\b|inner\b|on\b|for\b)(\w+))?)([\s\S]*?)(?:;|\breturning\b|$)/gi)) {
    const name = (m[1] ?? m[3] ?? m[5]).replace(/"/g, "");
    const alias = (m[2] ?? m[4] ?? m[6] ?? "").toLowerCase();
    const where = /\bwhere\b([\s\S]*)$/i.exec(m[7])?.[1];
    if (!where) continue;
    const rel = ctx.schema.relations.find((r) => r.kind === "table" && (qualified(r) === name || (!name.includes(".") && r.name === name)));
    if (!rel) continue;
    const keyCols = new Set([...rel.primaryKey, ...rel.foreignKeys.flatMap((k) => k.columns)]);
    const set = new Map<string, { sql: string; param?: string; say: string }>();
    const atomRe = new RegExp(String.raw`(?:\b(\w+)\.)?"?(\w+)"?\s*(>=|<=|<>|!=|=|>|<|\bis\s+not\b|\bis\b)\s*(null|${lit})`, "gi");
    for (const a of where.matchAll(atomRe)) {
      const [, qual, colName, opRaw, value] = a;
      // A column of another table (s.status inside an exists (...)) is not this row's state.
      if (qual && qual.toLowerCase() !== alias && qual.toLowerCase() !== rel.name.toLowerCase()) continue;
      const col = rel.columns.find((c) => c.name.toLowerCase() === colName.toLowerCase());
      if (!col || keyCols.has(col.name) || col.isGenerated || set.has(col.name)) continue;
      const op = opRaw.toLowerCase().replace(/\s+/g, " ");
      const v = value.toLowerCase();
      const time = /^(now\(\)|current_timestamp)$/.test(v);
      const num = /^-?\d/.test(v) ? Number(v) : undefined;
      const cast = `::${col.type}`;
      if (op === "is" && v === "null") {
        if (!col.notNull) set.set(col.name, { sql: "null", say: `${col.name} empty` });
      } else if (op === "is not" && v === "null") {
        if (/^(timestamp|date)/.test(col.type)) set.set(col.name, { sql: `coalesce(${ident(col.name)}, now())${cast}`, say: `${col.name} set` });
      } else if (time && /^(timestamp|date)/.test(col.type) && op !== "=" && op !== "<>" && op !== "!=") {
        set.set(col.name, { sql: `(now() ${op.startsWith("<") ? "-" : "+"} interval '1 day')${cast}`, say: `${col.name} ${op.startsWith("<") ? "in the past" : "in the future"}` });
      } else if (num !== undefined && /^(smallint|integer|bigint|numeric|real|double)/.test(col.type)) {
        const want = op === ">" ? num + 1 : op === "<" ? num - 1 : op === "=" || op === ">=" || op === "<=" ? num : undefined;
        if (want !== undefined) set.set(col.name, { sql: `$P${cast}`, param: String(want), say: `${col.name} = ${want}` });
      } else if (op === "=" && !time) {
        const text = v.startsWith("'") ? value.slice(1, -1).replace(/''/g, "'") : value;
        set.set(col.name, { sql: `$P${cast}`, param: text, say: `${col.name} = '${text}'` });
      }
    }
    // col in ('a', 'b'): the first word of the list.
    for (const a of where.matchAll(/(?:\b(\w+)\.)?"?(\w+)"?\s+in\s*\(\s*'((?:[^']|'')*)'/gi)) {
      const [, qual, colName, first] = a;
      if (qual && qual.toLowerCase() !== alias && qual.toLowerCase() !== rel.name.toLowerCase()) continue;
      const col = rel.columns.find((c) => c.name.toLowerCase() === colName.toLowerCase());
      if (!col || keyCols.has(col.name) || col.isGenerated || set.has(col.name)) continue;
      const text = first.replace(/''/g, "'");
      set.set(col.name, { sql: `$P::${col.type}`, param: text, say: `${col.name} = '${text}'` });
    }
    if (!set.size) continue;
    const rows = ctx.world.owned.filter((o) => o.owner === owner.label && o.table === qualified(rel)).slice(0, 4);
    for (const o of rows) {
      const params: unknown[] = [];
      const assigns = [...set].map(([c, s]) => {
        if (s.param === undefined) return `${ident(c)} = ${s.sql}`;
        params.push(s.param);
        return `${ident(c)} = ${s.sql.replace("$P", `$${params.length}`)}`;
      });
      const keys = Object.keys(o.pk);
      const where2 = keys.map((k) => (params.push(String(o.pk[k])), `${ident(k)}::text = $${params.length}`)).join(" and ");
      statements.push({ text: `update ${qident(rel)} set ${assigns.join(", ")} where ${where2}`, params });
    }
    if (rows.length) said.push(`${qualified(rel)}: ${[...set.values()].map((s) => s.say).join(", ")}`);
  }
  return { statements, desc: said.join("; ") };
}

/**
 * A write that waits for a row state (an order still pending, a counter above zero) changes nothing
 * on fresh test rows, for the owner as much as for anyone. Put the rows in that state inside the
 * rolled-back transaction and ask again: the owner's call now changes their row, and another user's
 * identical call either does too (a finding) or does not (it checks the caller).
 */
async function rowState(ctx: Ctx, f: RpcFunction, actor: Actor, victim: Actor, tries: Row[], before: Map<string, string>) {
  const target = `${f.schema}.${f.name}`;
  const c = ctx.coverage.get(target);
  if (!c || !f.volatile || !tries.length) return;
  const prime = rowStatePrime(ctx, f, victim);
  if (!prime.statements.length) return;
  for (const body of tries.slice(0, 4)) {
    const own = await callAs(ctx, f, victim, victim, body, before, "row state, owner: ", true, prime.statements);
    if (!own.ok || !own.changed.length) continue;
    const r = await callAs(ctx, f, actor, victim, body, before, "row state: ", false, prime.statements);
    trace("args/row-state", target);
    if (r.ok && r.changed.length) {
      const path = `/rest/v1/rpc/${f.name}`;
      mark(body, "args/row-state");
      observe(ctx, {
        probe: "rpc-write",
        target,
        actor: actor.label,
        victim: victim.label,
        facts: { changed: r.changed, primed: prime.desc },
        evidence: { actor: actor.label, victim: victim.label, request: { method: "POST", path, body }, status: 200, curl: ctx.api.curl(actor, "POST", path, body, profileHeaders(f)), via: marksOf(body), proof: `${victim.label}'s row first set to ${prime.desc}; then:\n${r.changed.slice(0, 3).join("\n")}` },
      });
      return;
    }
    c.ownerControl = "guarded";
    c.ownerDetail = `with the row first set to ${short(prime.desc, 100)}, changed ${own.changed.length} of the owner's own row(s), while the same call by another user changed nothing`;
    ctx.coverage.set(target, c);
    trace("owner-control/row-state", target);
    return;
  }
}

/** Two refusals with the same message, ids and quoted values aside. */
const sameRefusal = (a: string, b: string) => {
  const norm = (x: string) => x.replace(/[0-9a-f]{8}-[0-9a-f-]{27}/gi, "<id>").replace(/"[^"]*"|'[^']*'/g, "<v>").replace(/\d+/g, "<n>").slice(0, 60);
  return norm(a) === norm(b);
};

/**
 * The owner control call: an attack call that found nothing proves little on its own, because the
 * test values may simply reach nothing. Make the same calls as the rightful owner. If the owner's
 * call changes or returns their data, or gets further than the attacker's identical call, the
 * function tells callers apart; if it does nothing for the owner either, the test values missed.
 */
async function ownerControl(ctx: Ctx, f: RpcFunction, owner: Actor, tries: Row[], before: Map<string, string>, refusedBodies = new Map<string, string>()) {
  const target = `${f.schema}.${f.name}`;
  const c = ctx.coverage.get(target) ?? { relation: target, kind: "function" as const, reached: 0, unreachable: 0, populated: true };
  if (c.ownerControl === "guarded" || c.ownerControl === "secret-gated" || !f.execAuthenticated) return;
  for (const body of tries.slice(0, 4)) {
    const r = await callAs(ctx, f, owner, owner, body, before, "owner control: ", true);
    const theirs = refusedBodies.get(JSON.stringify(body));
    // How the owner's identical call differed from the attacker's, strongest first.
    const how: [string, string] | undefined = r.changed.length
      ? ["owner-control/changed", `changed ${r.changed.length} of their own row(s) (${short(r.changed[0], 100)})`]
      : r.hits.length
        ? ["owner-control/returned", "returned their own data"]
        : r.ok && theirs
          ? ["owner-control/accepted", `was accepted, while the same call by another user was refused (${short(theirs, 80)})`]
          : !r.ok && theirs && !sameRefusal(theirs, r.error ?? "")
            ? ["owner-control/got-further", `got past the caller check and stopped later ("${short(r.error ?? "", 60)}"), while the same call by another user was refused ("${short(theirs, 60)}")`]
            : undefined;
    if (how) {
      c.ownerControl = "guarded";
      c.ownerDetail = how[1];
      ctx.coverage.set(target, c);
      trace(how[0], target);
      for (const m of marksOf(body)) trace(m, target);
      return;
    }
  }
  c.ownerControl = "no-effect";
  ctx.coverage.set(target, c);
  trace("owner-control/no-effect", target);
}

/** 5. Policies that read user_metadata: set our own metadata to the victim's ids and read again. */
async function metadataProbe(ctx: Ctx) {
  // Deparsed policies look like: ((auth.jwt() -> 'user_metadata'::text) ->> 'org_id'::text)
  const keyRe = /user_metadata'(?:::\w+)?\s*\)*\s*->>?\s*'([^']+)'/gi;
  for (const p of ctx.schema.policies) {
    const keys = [...`${p.using ?? ""} ${p.withCheck ?? ""}`.matchAll(keyRe)].map((m) => m[1]);
    if (!keys.length) continue;
    const q = `${p.schema}.${p.table}`;
    const rel = ctx.schema.relations.find((r) => qualified(r) === q);
    if (!rel) continue;
    for (const attacker of ctx.world.tenants) {
      for (const victim of victimsOf(ctx, attacker)) {
        const ids = victimValues(ctx, victim, "uuid") as string[];
        for (const id of ids) {
          const data = Object.fromEntries(keys.map((k) => [k, id]));
          await ctx.api.setOwnMetadata(attacker, data);
          const path = `/rest/v1/${rel.name}?select=*`;
          const res = await ctx.api.request(attacker, "GET", path, undefined, profileHeaders(rel));
          track(ctx, q, rel.kind, res);
          if (res.status !== 200 || !findTokens(res.text, ctx.world.tokens.get(victim.label)!).length) continue;
          observe(ctx, {
            probe: "metadata",
            target: q,
            actor: attacker.label,
            victim: victim.label,
            facts: { policy: p.name, keys },
            evidence: {
              actor: attacker.label,
              victim: victim.label,
              request: { method: "PUT", path: "/auth/v1/user", body: { data } },
              status: res.status,
              proof: short(res.body),
              curl: `${ctx.api.curl(attacker, "PUT", "/auth/v1/user", { data })}  # then: ${ctx.api.curl(attacker, "GET", path)}`,
            },
          });
          break;
        }
        await ctx.api.setOwnMetadata(attacker, Object.fromEntries(keys.map((k) => [k, null])));
      }
    }
  }
}

/** The relations where the attacker now reads another tenant's rows, not already proven readable. */
async function newlyReadable(ctx: Ctx, attacker: Actor): Promise<string[]> {
  const out: string[] = [];
  for (const victim of victimsOf(ctx, attacker)) {
    for (const rel of ctx.schema.relations) {
      const rq = qualified(rel);
      if (out.includes(rq) || !rel.grants.authenticated.select || (rel.kind === "table" && ctx.world.unscoped.has(rq))) continue;
      const r = await ctx.api.request(attacker, "GET", `/rest/v1/${rel.name}?select=*&limit=1000`, undefined, profileHeaders(rel));
      if (r.status === 200 && findTokens(r.text, ctx.world.tokens.get(victim.label)!).length && !ctx.observations.some((o) => o.target === rq && o.actor === attacker.label && /read/.test(o.probe))) out.push(rq);
    }
  }
  return out;
}

/**
 * Self-enrollment: an insert policy with a branch "the caller adds themselves with a privileged
 * role" (user_id = auth.uid() and role = 'admin') that never ties the row to a parent the caller
 * owns. Anyone can then add themselves as admin to another tenant's workspace, and every admin check
 * passes. Distinct from self-escalation (an UPDATE of a row the user already owns): here the row is
 * new, in the victim's tenant.
 */
async function selfEnrollmentProbe(ctx: Ctx) {
  const norm = (x: string) => x.replace(/\(\s*select\s+auth\.uid\(\)(?:\s+as\s+\w+)?\s*\)|auth\.uid\(\)/gi, "AUTHUID");
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    if (!t.grants.authenticated.insert) continue;
    const personFks = t.foreignKeys.filter((f) => isUserRef(f, ctx.world.profileTables) && f.columns.length === 1);
    const tfks = tenantFks(ctx, t).filter((f) => !ctx.world.unscoped.has(`${f.refSchema}.${f.refTable}`));
    const privCols = t.columns.filter((c) => !c.isGenerated && ((c.type === "boolean" && PRIVILEGE_FLAG.test(c.name)) || PRIVILEGE_ROLE.test(c.name)));
    if (!personFks.length || !tfks.length || !privCols.length) continue;
    // An INSERT or ALL policy whose check lets the caller insert their own row (person = auth.uid()).
    const selfBranch = ctx.schema.policies.find(
      (p) =>
        p.schema === t.schema &&
        p.table === t.name &&
        (p.cmd === "INSERT" || p.cmd === "ALL") &&
        p.withCheck &&
        personFks.some((f) => new RegExp(String.raw`(?:^|[^\w.])(?:\w+\.)?${f.columns[0]}\s*=\s*AUTHUID|AUTHUID\s*=\s*(?:\w+\.)?${f.columns[0]}\b`, "i").test(norm(p.withCheck ?? ""))),
    );
    if (!selfBranch) continue;
    const check = norm(selfBranch.withCheck ?? "");
    for (const attacker of ctx.world.tenants) {
      if (!attacker.userId) continue;
      for (const victim of victimsOf(ctx, attacker)) {
        const first = tfks[0];
        const pinned = ctx.world.owned.find((o) => o.owner === victim.label && o.table === `${first.refSchema}.${first.refTable}`);
        if (!pinned) continue;
        const source = (ref: string) => (ref === pinned.table ? pinned : ctx.world.owned.find((o) => o.owner === victim.label && o.table === ref) ?? sharedRow(ctx, ref));
        const built = buildRow(t, ctx.world.profileTables, (ref) => source(ref), `tp_enroll_${t.name}`, () => attacker.userId);
        if ("error" in built) continue;
        const col = privCols.find((c) => new RegExp(String.raw`\b${c.name}\b`, "i").test(check)) ?? privCols[0];
        const said = [...check.matchAll(new RegExp(String.raw`\b${col.name}\b\s*=\s*'([^']*)'`, "gi"))].map((m) => m[1]).filter((v) => PRIVILEGED_VALUE.test(v));
        const value = col.type === "boolean" ? true : (said[0] ?? privilegedValue(ctx, t, col));
        if (value === undefined) continue;
        const row = { ...built.row, [col.name]: value };
        // A creator bootstrapping their own first admin row has the same shape: only flag when the
        // parent is the victim's and the attacker holds no row there yet.
        const keyCols = [...first.columns, personFks[0].columns[0]];
        const vals = [...first.columns.map((c) => row[c]), attacker.userId];
        const had = await query(ctx.db, `select 1 from ${qident(t)} where ${keyCols.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")} limit 1`, vals.map(String)).catch(() => ({ rowCount: 1 }));
        if (had.rowCount) continue;
        const path = `/rest/v1/${t.name}`;
        const res = await ctx.api.request(attacker, "POST", path, row, { Prefer: "return=minimal", ...profileHeaders(t) });
        track(ctx, q, "table", res);
        if (process.env.TENANTBLEED_DEBUG_RPC) process.stderr.write(`SELF-ENROLLMENT ${q}.${col.name}=${String(value)} ${attacker.label} into ${victim.label}: ${res.status} ${short(res.text, 120)}\n`);
        if (res.status !== 201) continue;
        const unlocked = await newlyReadable(ctx, attacker);
        observe(ctx, {
          probe: "self-enrollment",
          target: q,
          actor: attacker.label,
          victim: victim.label,
          facts: { column: col.name, value: String(value), parentTable: pinned.table, policy: selfBranch.name, unlocked },
          evidence: {
            actor: attacker.label,
            victim: victim.label,
            request: { method: "POST", path, body: row },
            status: res.status,
            proof: `201 Created: ${attacker.label} added a ${col.name} = ${String(value)} row in ${victim.label}'s ${pinned.table}${unlocked.length ? `; then readable: ${unlocked.join(", ")}` : ""}`,
            curl: ctx.api.curl(attacker, "POST", path, row, profileHeaders(t)),
          },
        });
        await cleanupInserted(ctx, t, row, "tp_enroll");
        break;
      }
    }
  }
}

/** A flag or role column that grants more rights: is_admin, is_staff, role, app_role. */
const PRIVILEGE_FLAG = /^(is_)?(admin|super_?admin|superuser|staff|moderator|operator)$/i;
const PRIVILEGE_ROLE = /^(role|user_role|app_role|account_role|access_level)$/i;
const PRIVILEGED_WORD = ["super_admin", "superadmin", "admin", "owner", "staff", "moderator"];
const PRIVILEGED_VALUE = /admin|owner|super|staff|moderator|operator/i;

/**
 * Self-escalation: a user rewrites a privilege column on their own row (is_admin, role) through the
 * API, because the self-update policy covers every column. It counts only when the app trusts that
 * column (a policy or a function reads it). Proven when the stored row keeps the new value; the read
 * sweep is then repeated to show what it unlocks. The row is put back.
 */
async function selfEscalationProbe(ctx: Ctx) {
  // Trusted: a policy on the table reads the column, or a policy or function names both the table and
  // the column (exists (select 1 from profiles p where p.id = auth.uid() and p.is_admin)).
  const trusted = (t: Relation, col: string) => {
    const c = new RegExp(`\\b${col}\\b`, "i");
    const tn = new RegExp(`\\b${t.name}\\b`, "i");
    return (
      ctx.schema.policies.some((p) => {
        const text = `${p.using ?? ""} ${p.withCheck ?? ""}`;
        return c.test(text) && (`${p.schema}.${p.table}` === qualified(t) || tn.test(text));
      }) || ctx.schema.functions.some((f) => c.test(f.body) && tn.test(f.body))
    );
  };
  for (const t of tenantTables(ctx.schema)) {
    if (!t.grants.authenticated.update || !t.primaryKey.length) continue;
    const q = qualified(t);
    const cols = t.columns.filter((c) => !c.isGenerated && ((c.type === "boolean" && PRIVILEGE_FLAG.test(c.name)) || PRIVILEGE_ROLE.test(c.name)) && trusted(t, c.name));
    if (!cols.length) continue;
    for (const attacker of ctx.world.tenants) {
      // The attacker's own row: one that names the attacker's user id.
      const mine = ctx.world.owned.find((o) => o.table === q && o.owner === attacker.label && Object.values(o.row).some((v) => v === attacker.userId));
      if (!mine) continue;
      // The edit must be allowed because the row is the user's own (user_id = auth.uid() in an update
      // policy), not because the user already runs the workspace or project it belongs to: an owner
      // or project admin editing members is by design, whatever role their own row says.
      const idCols = Object.keys(mine.row).filter((c) => mine.row[c] === attacker.userId);
      const selfPolicy = ctx.schema.policies.some((p) => {
        if (p.schema !== t.schema || p.table !== t.name || (p.cmd !== "UPDATE" && p.cmd !== "ALL")) return false;
        const using = (p.using ?? "").replace(/\(\s*select\s+auth\.uid\(\)(?:\s+as\s+\w+)?\s*\)|auth\.uid\(\)/gi, "AUTHUID");
        return idCols.some((c) => new RegExp(String.raw`(?:^|[^\w.])(?:\w+\.)?${c}\s*=\s*AUTHUID|AUTHUID\s*=\s*(?:\w+\.)?${c}\b`, "i").test(using));
      });
      if (t.rlsEnabled && !selfPolicy) continue;
      for (const col of cols) {
        const value = privilegedValue(ctx, t, col);
        if (value === undefined) continue;
        const before = await fetchRow(ctx, t, mine.pk);
        if (!before) continue;
        const path = `/rest/v1/${t.name}?${pkFilter(t, mine.pk)}`;
        const patch = async (v: unknown) => {
          const res = await ctx.api.request(attacker, "PATCH", path, { [col.name]: v }, { Prefer: "return=minimal", ...profileHeaders(t) });
          track(ctx, q, "table", res);
          const now = await fetchRow(ctx, t, mine.pk);
          return { res, stored: !!now && String(now[col.name]) === String(v), now };
        };
        // Already privileged (the test user owns what they created): moving to admin proves nothing.
        // Step down to the plainest value first, then try to climb back as that plain member.
        const already = String(before[col.name]) === String(value) || (col.type !== "boolean" && PRIVILEGED_VALUE.test(String(before[col.name] ?? "")));
        let target: unknown = value;
        let from: unknown = before[col.name];
        if (already) {
          const low = plainValue(ctx, t, col);
          if (low === undefined || String(low) === String(before[col.name])) continue;
          const down = await patch(low);
          if (!down.stored) {
            await restoreColumns(ctx, t, before, [col.name], attacker.userId);
            continue;
          }
          target = before[col.name];
          from = low;
        }
        const { res, stored, now: after } = await patch(target);
        if (process.env.TENANTBLEED_DEBUG_RPC) process.stderr.write(`SELF-ESCALATION ${q}.${col.name} ${attacker.label}: ${res.status} ${short(from, 20)} -> ${short(after?.[col.name], 20)} ${short(res.text, 160)}\n`);
        if (!stored || !after) {
          await restoreColumns(ctx, t, before, [col.name], attacker.userId);
          continue;
        }
        // What it unlocks: the victim's rows the attacker can now read.
        const unlocked = await newlyReadable(ctx, attacker);
        await restoreColumns(ctx, t, before, [col.name], attacker.userId);
        observe(ctx, {
          probe: "self-escalation",
          target: q,
          actor: attacker.label,
          victim: victimsOf(ctx, attacker)[0]?.label ?? "",
          facts: { column: col.name, value: String(target), unlocked, ...(already ? { steppedDown: String(from) } : {}) },
          evidence: {
            actor: attacker.label,
            victim: victimsOf(ctx, attacker)[0]?.label,
            request: { method: "PATCH", path, body: { [col.name]: target } },
            status: res.status,
            proof: `${q} own row: ${already ? `${col.name} set to ${short(from, 40)} first (a plain member), then ` : ""}${col.name} ${short(from, 40)} -> ${short(after[col.name], 40)}${unlocked.length ? `; then readable: ${unlocked.join(", ")}` : ""}`,
            curl: ctx.api.curl(attacker, "PATCH", path, { [col.name]: target }, profileHeaders(t)),
          },
        });
        break;
      }
    }
  }
}

/** The most privileged value a column accepts: true for a flag, the top word of its enum or CHECK list for a role. */
function privilegedValue(ctx: Ctx, t: Relation, col: Relation["columns"][number]): unknown {
  if (col.type === "boolean") return true;
  let labels = ctx.enums.get(col.type);
  if (!labels) {
    // CHECK (role = ANY (ARRAY['member'::text, 'admin'::text])) or CHECK (role in ('member', 'admin')).
    const listRe = new RegExp(String.raw`\b${col.name}\b[^)]*?(?:array\s*\[([^\]]*)\]|\bin\s*\(([^)]*)\))`, "i");
    const m = t.checks.map((c) => listRe.exec(c)).find(Boolean);
    const list = m ? (m[1] ?? m[2] ?? "") : "";
    labels = [...list.matchAll(/'((?:[^']|'')*)'/g)].map((x) => x[1]);
  }
  if (labels.length) return PRIVILEGED_WORD.find((w) => labels!.includes(w)) ?? labels.find((l) => /admin|owner|super/i.test(l));
  if (!/^(text|character varying|citext)/.test(col.type)) return undefined;
  // Free text: only a privileged value the app's own rules compare the column to (role = 'admin').
  // A column no rule compares to such a value (a chat message's role) grants nothing.
  const said = comparedValues(ctx, t, col.name).filter((v) => PRIVILEGED_VALUE.test(v));
  return said[0];
}

/** The least privileged value a role column accepts (member, viewer), for stepping down first. */
function plainValue(ctx: Ctx, t: Relation, col: Relation["columns"][number]): unknown {
  if (col.type === "boolean") return false;
  const labels = ctx.enums.get(col.type) ?? (() => {
    const listRe = new RegExp(String.raw`\b${col.name}\b[^)]*?(?:array\s*\[([^\]]*)\]|\bin\s*\(([^)]*)\))`, "i");
    const m = t.checks.map((c) => listRe.exec(c)).find(Boolean);
    return [...(m ? (m[1] ?? m[2] ?? "") : "").matchAll(/'((?:[^']|'')*)'/g)].map((x) => x[1]);
  })();
  const pool = labels.length ? labels : comparedValues(ctx, t, col.name);
  return pool.find((l) => /^(member|viewer|user|guest|basic|reader|readonly|read_only|employee|staff_member)$/i.test(l)) ?? pool.find((l) => !PRIVILEGED_VALUE.test(l));
}

/**
 * Literal values the rules about one table compare a column to (role = 'admin', role in ('owner',
 * 'admin')): its own policies, and policies or functions that name the table.
 */
function comparedValues(ctx: Ctx, t: Relation, column: string): string[] {
  const named = new RegExp(String.raw`\b${t.name}\b`, "i");
  const texts = [
    ...ctx.schema.policies.map((p) => ({ own: p.schema === t.schema && p.table === t.name, text: `${p.using ?? ""} ${p.withCheck ?? ""}` })),
    ...ctx.schema.functions.map((f) => ({ own: false, text: f.body })),
  ].flatMap((x) => (x.own || named.test(x.text) ? [x.text] : []));
  const re = new RegExp(String.raw`\b${column}\b\s*(?:=|<>|!=|in\s*\(|=\s*any\s*\(\s*array\s*\[)\s*((?:'[^']*'(?:::\w+)?\s*,?\s*)+)`, "gi");
  // Most compared first: the value the app trusts in most places.
  const count = new Map<string, number>();
  for (const t of texts) for (const m of t.matchAll(re)) for (const v of m[1].matchAll(/'([^']*)'/g)) count.set(v[1], (count.get(v[1]) ?? 0) + 1);
  return [...count].sort((a, b) => b[1] - a[1]).map(([v]) => v);
}

/** 6. Destructive, so it runs last: delete another tenant's row, check, then put it back. */
async function deleteProbe(ctx: Ctx, actors: Actor[]) {
  for (const t of [...tenantTables(ctx.schema)].reverse()) {
    const q = qualified(t);
    for (const actor of actors) {
      if (!t.grants[roleOf(actor)].delete) continue;
      for (const victim of victimsOf(ctx, actor)) {
        const target: OwnedRow | undefined = victimRows(ctx, victim, q)[0];
        if (!target) continue;
        const before = await fetchRow(ctx, t, target.pk);
        if (!before) continue;
        const path = `/rest/v1/${t.name}?${pkFilter(t, target.pk)}`;
        const res = await ctx.api.request(actor, "DELETE", path, undefined, { Prefer: "return=minimal", ...profileHeaders(t) });
        track(ctx, q, "table", res);
        if (await fetchRow(ctx, t, target.pk)) continue;
        observe(ctx, {
          probe: "delete",
          target: q,
          actor: actor.label,
          victim: victim.label,
          facts: {},
          evidence: {
            actor: actor.label,
            victim: victim.label,
            request: { method: "DELETE", path },
            status: res.status,
            proof: `row gone: ${short(target.pk)}`,
            curl: ctx.api.curl(actor, "DELETE", path, undefined, profileHeaders(t)),
          },
        });
        await restoreDeleted(ctx, t, before, ownerIdOf(ctx, victim.label));
      }
    }
  }
}

interface PlacedFile {
  path: string;
  /** A content type the bucket accepts (allowed_mime_types), sent with every upload. */
  mime: string;
  content: string;
  /** Folder that identifies the owner (user id, org id...), when the file is not at the bucket root. */
  folder?: string;
  via: "api" | "service";
}

const enc = (p: string) => p.split("/").map(encodeURIComponent).join("/");

/** Give the file back to its owner after a service-role upload (which leaves the owner empty). */
async function setStorageOwner(ctx: Ctx, bucket: string, path: string, userId?: string) {
  if (!userId) return;
  await query(ctx.db, "update storage.objects set owner = $1::uuid, owner_id = $1::text where bucket_id = $2 and name = $3", [userId, bucket, path]).catch(() =>
    query(ctx.db, "update storage.objects set owner = $1::uuid where bucket_id = $2 and name = $3", [userId, bucket, path]).catch(() => {}),
  );
}

/**
 * Put one file per tenant in the bucket the way the app would: upload as the tenant into a folder
 * named after something they own (their user id first, then their org/record ids, then the root).
 * If no convention is accepted, the service role places it under the user id and assigns the owner.
 */
async function placeFile(ctx: Ctx, bucket: string, tenant: Actor, mime: string): Promise<PlacedFile | undefined> {
  const content = `tp_${tenant.label.replace(/\W+/g, "").toLowerCase()}_file_${crypto.randomUUID().slice(0, 8)}`;
  const ct = { "Content-Type": mime };
  const folders = [tenant.userId!, ...(victimValues(ctx, tenant, "uuid") as string[]).filter((v) => v !== tenant.userId).slice(0, 8), ""];
  for (const folder of folders) {
    const path = `${folder ? folder + "/" : ""}${content}.txt`;
    const res = await ctx.api.storage(tenant, "POST", `/storage/v1/object/${bucket}/${enc(path)}`, content, ct);
    if (res.status === 200) return { path, content, mime, folder: folder || undefined, via: "api" };
  }
  const path = `${tenant.userId}/${content}.txt`;
  const res = await ctx.api.storage("service", "POST", `/storage/v1/object/${bucket}/${enc(path)}`, content, ct);
  if (res.status !== 200) return undefined;
  await setStorageOwner(ctx, bucket, path, tenant.userId);
  return { path, content, mime, folder: tenant.userId, via: "service" };
}

async function fileContent(ctx: Ctx, bucket: string, path: string): Promise<string | undefined> {
  const res = await ctx.api.storage("service", "GET", `/storage/v1/object/authenticated/${bucket}/${enc(path)}`);
  return res.status === 200 ? res.text : undefined;
}

async function restoreFile(ctx: Ctx, bucket: string, f: PlacedFile, userId?: string) {
  await ctx.api.storage("service", "POST", `/storage/v1/object/${bucket}/${enc(f.path)}`, f.content, { "x-upsert": "true", "Content-Type": f.mime });
  await setStorageOwner(ctx, bucket, f.path, userId);
}

/**
 * 7. Storage buckets: with each tenant owning a file, try to download, list, overwrite, delete and
 * upload into another tenant's files. Every result is checked with the service role, and files are
 * put back afterwards.
 */
async function storageProbe(ctx: Ctx, actors: Actor[]) {
  const exists = await query(ctx.db, "select to_regclass('storage.buckets') is not null as ok");
  if (!exists.rows[0].ok) return;
  const buckets = (await query(ctx.db, "select id, public, allowed_mime_types from storage.buckets order by id")).rows as { id: string; public: boolean; allowed_mime_types: string[] | null }[];
  for (const b of buckets) {
    const target = `bucket:${b.id}`;
    const cov: Coverage = { relation: target, kind: "bucket", reached: 0, unreachable: 0, populated: true };
    ctx.coverage.set(target, cov);
    const files = new Map<string, PlacedFile>();
    for (const t of ctx.world.tenants) {
      // A type the bucket accepts: plain text when allowed (or unrestricted), else the first allowed type.
      const allowed = b.allowed_mime_types ?? [];
      const mime = !allowed.length || allowed.includes("text/plain") ? "text/plain" : allowed.find((m) => !m.includes("*")) ?? allowed[0].replace("*", "png");
      const f = await placeFile(ctx, b.id, t, mime);
      if (f) files.set(t.label, f);
    }
    if (files.size < ctx.world.tenants.length) {
      cov.populated = false;
      cov.reason = "could not upload a test file, even with the service role";
      continue;
    }
    for (const [label, f] of files) ctx.world.tokens.get(label)!.add(f.content);
    const seededByService = [...files.values()].some((f) => f.via === "service");
    const reach = (res: ApiResponse) => (res.status === 404 && /bucket not found/i.test(res.text) ? cov.unreachable++ : cov.reached++);

    for (const actor of actors) {
      for (const victim of victimsOf(ctx, actor)) {
        const v = files.get(victim.label)!;
        const objPath = `/storage/v1/object/${b.id}/${enc(v.path)}`;
        const base = { actor: actor.label, victim: victim.label };
        const who2 = { target, actor: actor.label, victim: victim.label };

        // Download (public buckets are readable by URL on purpose).
        if (!b.public) {
          const path = `/storage/v1/object/authenticated/${b.id}/${enc(v.path)}`;
          const res = await ctx.api.storage(actor, "GET", path);
          reach(res);
          if (res.status === 200 && res.text.includes(v.content))
            observe(ctx, {
              probe: "file-download",
              ...who2,
              facts: { bucket: b.id, path: v.path, seededByService },
              evidence: { ...base, request: { method: "GET", path }, status: res.status, proof: short(res.text), curl: ctx.api.curl(actor, "GET", path) },
            });
        }

        // List the victim's folder.
        {
          const path = `/storage/v1/object/list/${b.id}`;
          const name = v.path.split("/").pop()!;
          const body = { prefix: v.folder ?? "", limit: 1000, offset: 0, search: name };
          const res = await ctx.api.storage(actor, "POST", path, body);
          reach(res);
          if (res.status === 200 && Array.isArray(res.body) && (res.body as { name?: string }[]).some((o) => o.name === name))
            observe(ctx, {
              probe: "file-list",
              ...who2,
              facts: { bucket: b.id, path: v.path, folder: v.folder, public: b.public, seededByService },
              evidence: { ...base, request: { method: "POST", path, body }, status: res.status, proof: short(res.body), curl: ctx.api.curl(actor, "POST", path, body) },
            });
        }

        // Overwrite the victim's file.
        {
          const evil = `tp_overwritten_${crypto.randomUUID().slice(0, 8)}`;
          const res = await ctx.api.storage(actor, "POST", objPath, evil, { "x-upsert": "true", "Content-Type": v.mime });
          reach(res);
          const now = await fileContent(ctx, b.id, v.path);
          if (now !== v.content) {
            if (now === evil)
              observe(ctx, {
                probe: "file-overwrite",
                ...who2,
                facts: { bucket: b.id, path: v.path, seededByService },
                evidence: {
                  ...base,
                  request: { method: "POST", path: objPath },
                  status: res.status,
                  proof: `content before: ${v.content}\ncontent after:  ${now}`,
                  curl: ctx.api.curl(actor, "POST", objPath, evil, { "x-upsert": "true" }),
                },
              });
            await restoreFile(ctx, b.id, v, victim.userId);
          }
        }

        // Upload into the victim's folder.
        if (v.folder) {
          const path = `${v.folder}/tp_intruder_${crypto.randomUUID().slice(0, 8)}.txt`;
          const req = `/storage/v1/object/${b.id}/${enc(path)}`;
          const res = await ctx.api.storage(actor, "POST", req, "tp_intruder", { "Content-Type": v.mime });
          reach(res);
          if (res.status === 200) {
            const name = path.split("/").pop()!;
            const listed = await ctx.api.storage(victim, "POST", `/storage/v1/object/list/${b.id}`, { prefix: v.folder, limit: 1000, offset: 0, search: name });
            const seen = Array.isArray(listed.body) && (listed.body as { name?: string }[]).some((o) => o.name === name);
            observe(ctx, {
              probe: "file-upload",
              ...who2,
              facts: { bucket: b.id, path, folder: v.folder, victimCanSee: seen, seededByService },
              evidence: { ...base, request: { method: "POST", path: req }, status: res.status, proof: short(res.body), curl: ctx.api.curl(actor, "POST", req, "tp_intruder") },
            });
            await ctx.api.storage("service", "DELETE", `/storage/v1/object/${b.id}`, { prefixes: [path] });
          }
        }

        // Delete the victim's file.
        {
          const path = `/storage/v1/object/${b.id}`;
          const body = { prefixes: [v.path] };
          const res = await ctx.api.storage(actor, "DELETE", path, body);
          reach(res);
          if ((await fileContent(ctx, b.id, v.path)) === undefined) {
            observe(ctx, {
              probe: "file-delete",
              ...who2,
              facts: { bucket: b.id, path: v.path, seededByService },
              evidence: { ...base, request: { method: "DELETE", path, body }, status: res.status, proof: `file gone: ${v.path}`, curl: ctx.api.curl(actor, "DELETE", path, body) },
            });
            await restoreFile(ctx, b.id, v, victim.userId);
          }
        }
      }
    }
    for (const f of files.values()) await ctx.api.storage("service", "DELETE", `/storage/v1/object/${b.id}`, { prefixes: [f.path] });
  }
}

const gqlLiteral = (v: unknown) => (typeof v === "number" ? String(v) : JSON.stringify(String(v)));
const camel = (s: string) => s.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());

/**
 * 8. GraphQL (/graphql/v1, pg_graphql). It applies the same RLS as the REST API, so it should leak
 * exactly what REST leaks. Recent pg_graphql turns introspection off, so queries are built from the
 * database schema: every public table and view is read as each actor and searched for another
 * tenant's data. Leaks REST already proved are marked as also reachable here.
 */
async function graphqlProbe(ctx: Ctx, actors: Actor[]) {
  const on = await query(ctx.db, "select 1 from pg_extension where extname = 'pg_graphql'");
  if (!on.rowCount) {
    ctx.notes.push("GraphQL: pg_graphql is not installed, so /graphql/v1 serves nothing. Not tested.");
    return;
  }
  const comment = (await query(ctx.db, "select coalesce(obj_description('public'::regnamespace), '') as c")).rows[0].c as string;
  const inflect = /"inflect_names"\s*:\s*true/.test(comment) ? camel : (x: string) => x;
  let reached = 0;
  for (const rel of ctx.schema.relations) {
    if (rel.schema !== "public") continue;
    const q = qualified(rel);
    if (rel.kind === "table" && ctx.world.unscoped.has(q)) continue;
    const coll = `${inflect(rel.name)}Collection`;
    for (const actor of actors) {
      if (!rel.grants[roleOf(actor)].select) continue;
      for (const victim of victimsOf(ctx, actor)) {
        // pg_graphql returns 30 rows per page by default: ask for the victim's rows by key when possible.
        const pk = rel.primaryKey.length === 1 ? rel.primaryKey[0] : undefined;
        const ids = pk ? victimRows(ctx, victim, q).map((o) => o.pk[pk]) : [];
        const filter = ids.length ? `(filter: { ${inflect(pk!)}: { in: [${ids.map(gqlLiteral).join(", ")}] } })` : "";
        let cols = rel.columns.map((c) => inflect(c.name));
        let res: ApiResponse | undefined;
        let query = "";
        // Columns of types pg_graphql does not expose are dropped one by one from the selection.
        for (let attempt = 0; attempt < 5 && cols.length; attempt++) {
          query = `{ ${coll}${filter} { edges { node { ${cols.join(" ")} } } } }`;
          res = await ctx.api.request(actor, "POST", "/graphql/v1", { query });
          const bad = /Unknown field "([^"]+)"/.exec(res.text)?.[1];
          if (!bad || bad === coll) break;
          cols = cols.filter((c) => c !== bad);
        }
        if (!res || res.status !== 200) continue;
        const data = (res.body as { data?: Record<string, { edges: { node: Row }[] } | null> | null })?.data?.[coll];
        if (!data) continue;
        reached++;
        const leaked = data.edges.map((e) => e.node).filter((r) => findTokens(JSON.stringify(r), ctx.world.tokens.get(victim.label)!).length);
        if (!leaked.length) continue;
        observe(ctx, {
          probe: "graphql-read",
          target: q,
          actor: actor.label,
          victim: victim.label,
          facts: { relKind: rel.kind, leakedCount: leaked.length },
          evidence: {
            actor: actor.label,
            victim: victim.label,
            request: { method: "POST", path: "/graphql/v1", body: { query } },
            status: res.status,
            proof: short(leaked[0]),
            curl: ctx.api.curl(actor, "POST", "/graphql/v1", { query }),
          },
        });
      }
    }
  }
  ctx.notes.push(reached ? `GraphQL: /graphql/v1 is on; ${reached} collection read(s) answered and were checked for other tenants' data.` : "GraphQL: pg_graphql is installed but no collection answered. Not tested.");
}

/** One rightful-owner operation, used to prove a fix does not lock users out of their own data. */
export interface OwnerAccessRow {
  relation: string;
  actor: string;
  /** owner: own rows. coworker / admin / stranger: tenant A's rows. */
  role?: "owner" | "coworker" | "admin" | "stranger";
  op: "read" | "update" | "insert" | "delete";
  ok: boolean;
  detail?: string;
}

/** Policy and function text, lower-cased: where an app spells out who its admins and members are. */
function accessText(ctx: Ctx): string {
  return [...ctx.schema.policies.flatMap((p) => [p.using ?? "", p.withCheck ?? ""]), ...ctx.schema.functions.map((f) => f.body)].join("\n").toLowerCase();
}

/** Values a column may take: its enum labels, else the quoted literals of CHECKs that name it. */
function columnOptions(t: Relation, col: string): string[] {
  const c = t.columns.find((x) => x.name === col);
  if (c?.enumLabels.length) return c.enumLabels;
  return [...new Set(t.checks.filter((d) => new RegExp(`\\b${col}\\b`).test(d)).flatMap((d) => [...d.matchAll(/'((?:[^']|'')*)'/g)].map((m) => m[1].replace(/''/g, "'"))))];
}

async function serviceInsert(ctx: Ctx, t: Relation, row: Row): Promise<boolean> {
  const cols = Object.keys(row);
  const insertSql = `insert into ${qident(t)} (${cols.map(ident).join(", ")}) values (${cols.map((_, i) => `$${i + 1}`).join(", ")}) on conflict do nothing`;
  const params = cols.map((c) => toParam(row[c], t.columns.find((x) => x.name === c)?.type));
  for (const replica of [false, true]) {
    const [r] = await sql(ctx.db, [{ replica, statements: [{ text: insertSql, params }] }]);
    if (!r.error) return true;
  }
  return false;
}

/**
 * Make `coworker` a regular member of tenant A's workspace: copy each membership row of A
 * (a table with a person column that the policies or functions consult, or a junction table)
 * with the coworker as the person and the least privileged role. Returns the tables joined.
 */
async function joinWorkspace(ctx: Ctx, owner: Actor, coworker: Actor, text: string): Promise<string[]> {
  const joined: string[] = [];
  const profiles = ctx.world.profileTables;
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    if (profiles.has(q)) continue;
    const person = t.foreignKeys.filter((f) => isUserRef(f, profiles) && f.columns.length === 1);
    const parents = t.foreignKeys.filter((f) => !isUserRef(f, profiles));
    if (!person.length || !parents.length) continue;
    const junction = person.some((p) => parents.some((o) => [...p.columns, ...o.columns].every((c) => t.primaryKey.includes(c))));
    const named = /member|participant|collaborator|team_user|account_user|user_role|_users$|^users_/.test(t.name) || text.includes(t.name.toLowerCase());
    if (!junction && !named) continue;
    const rows = (await query(ctx.db, `select * from ${qident(t)} where ${person.map((p, i) => `${ident(p.columns[0])}::text = $1`).join(" or ")} limit 5`, [owner.userId])).rows as Row[];
    for (const r of rows) {
      const col = person.find((p) => String(r[p.columns[0]]) === owner.userId)!.columns[0];
      const copy: Row = { ...r, [col]: coworker.userId };
      for (const c of t.columns) {
        if (t.primaryKey.includes(c.name) && !t.foreignKeys.some((f) => f.columns.includes(c.name))) {
          if (c.isIdentity || c.hasDefault) delete copy[c.name];
          else if (c.type === "uuid") copy[c.name] = crypto.randomUUID();
        }
        if (c.isGenerated) delete copy[c.name];
        if (/created_at|updated_at|joined_at|accepted_at/.test(c.name) && c.hasDefault) delete copy[c.name];
        // The least privileged role the column allows: member, viewer, editor, ... never owner or admin.
        if (/role|permission|access|level/.test(c.name) && typeof r[c.name] === "string") {
          const opts = columnOptions(t, c.name);
          const pick = opts.find((o) => /^(member|viewer|editor|user|contributor|participant|student|reader|guest|staff)$/i.test(o)) ?? opts.find((o) => !/owner|admin/i.test(o));
          if (pick) copy[c.name] = pick;
        }
      }
      if (await serviceInsert(ctx, t, copy)) joined.push(q);
    }
  }
  return [...new Set(joined)];
}

/**
 * Make `admin` an app admin the way the app's own policies recognise one: a boolean or role column
 * on the profile table, a role in app_metadata, or a row in an admins table. Returns what was set.
 */
async function makeAdmin(ctx: Ctx, admin: Actor, text: string): Promise<string[]> {
  const done: string[] = [];
  const isAdminWord = (s: string) => /admin|superuser|super_user|staff|moderator/.test(s.toLowerCase());
  // Profile table columns.
  for (const q of ctx.world.profileTables) {
    const t = ctx.schema.relations.find((r) => qualified(r) === q);
    if (!t) continue;
    const set: Row = {};
    for (const c of t.columns) {
      if (!text.includes(c.name.toLowerCase())) continue;
      if (c.type === "boolean" && isAdminWord(c.name)) set[c.name] = true;
      else if (/role|type|tier|level|kind|permission/.test(c.name)) {
        const v = columnOptions(t, c.name).find((o) => /^(super_?)?admin$/i.test(o)) ?? columnOptions(t, c.name).find((o) => /admin/i.test(o));
        if (v && text.includes(`'${v.toLowerCase()}'`)) set[c.name] = v;
      }
    }
    if (!Object.keys(set).length) continue;
    const pk = t.primaryKey[0];
    const exists = (await query(ctx.db, `select 1 from ${qident(t)} where ${ident(pk)}::text = $1`, [admin.userId])).rowCount;
    if (!exists) {
      const built = buildRow(t, ctx.world.profileTables, (ref) => sharedRow(ctx, ref), "tp_admin", () => admin.userId);
      if ("error" in built || !(await serviceInsert(ctx, t, { ...built.row, [pk]: admin.userId }))) continue;
    }
    const cols = Object.keys(set);
    const [r] = await sql(ctx.db, [
      { replica: true, statements: [{ text: `update ${qident(t)} set ${cols.map((c, i) => `${ident(c)} = $${i + 2}`).join(", ")} where ${ident(pk)}::text = $1`, params: [admin.userId, ...cols.map((c) => set[c])] }] },
    ]);
    if (!r.error) done.push(...cols.map((c) => `${q}.${c} = ${set[c]}`));
  }
  // app_metadata role, e.g. (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'.
  const m = /app_metadata'(?:::text)?\)?\s*->>?\s*'(\w+)'[^']{0,60}'(\w*admin\w*)'/.exec(text);
  if (m) {
    const meta = { [m[1]]: m[2] };
    await query(ctx.db, `update auth.users set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || $2::jsonb where id = $1`, [admin.userId, JSON.stringify(meta)]).catch(() => {});
    admin.appMetadata = meta;
    done.push(`app_metadata.${m[1]} = ${m[2]}`);
  }
  // An admins table: a table named for admins with a person column, consulted by the policies.
  for (const t of tenantTables(ctx.schema)) {
    if (!/(^|_)(admins?|super_?admins?|staff|moderators?|platform_admins?)$/.test(t.name) || !text.includes(t.name.toLowerCase())) continue;
    const built = buildRow(t, ctx.world.profileTables, (ref) => sharedRow(ctx, ref), "tp_admin", () => admin.userId);
    if (!("error" in built) && (await serviceInsert(ctx, t, built.row))) done.push(qualified(t));
  }
  if (done.length) {
    if (admin.minted) ctx.api.mint(admin);
    else await ctx.api.signInOrMint(admin).catch(() => {});
  }
  return done;
}

/** Read, edit and create inside tenant A's data as `actor` (coworker, admin, or the stranger B). */
async function accessAsRole(ctx: Ctx, owner: Actor, actor: Actor, role: OwnerAccessRow["role"], out: OwnerAccessRow[]) {
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    if (ctx.world.unscoped.has(q) || ctx.world.profileTables.has(q)) continue;
    const row = victimRows(ctx, owner, q)[0];
    if (!row) continue;
    const rec = (op: OwnerAccessRow["op"], ok: boolean, detail?: string) => out.push({ relation: q, actor: actor.label, role, op, ok, detail });
    if (t.grants.authenticated.select) {
      const res = await ctx.api.request(actor, "GET", `/rest/v1/${t.name}?${pkFilter(t, row.pk)}&select=*`, undefined, profileHeaders(t));
      rec("read", res.status === 200 && Array.isArray(res.body) && res.body.length > 0, `${res.status}`);
    }
    const col = mutableColumn(t);
    if (col && t.grants.authenticated.update) {
      const before = await fetchRow(ctx, t, row.pk);
      if (before) {
        const isText = /text|character/.test(t.columns.find((c) => c.name === col)!.type);
        const value = isText ? `tp_${role}_edit` : Number(before[col] ?? 0) + 1;
        const res = await ctx.api.request(actor, "PATCH", `/rest/v1/${t.name}?${pkFilter(t, row.pk)}`, { [col]: value }, { Prefer: "return=minimal", ...profileHeaders(t) });
        const after = await fetchRow(ctx, t, row.pk);
        rec("update", !!after && String(after[col]) === String(value), `${res.status}`);
        await restoreColumns(ctx, t, before, [col], owner.userId);
      }
    }
    if (t.grants.authenticated.insert) {
      const own = (ref: string) => ctx.world.owned.find((o) => o.owner === owner.label && o.table === ref) ?? sharedRow(ctx, ref);
      const built = buildRow(t, ctx.world.profileTables, own, `tp_${role}_${t.name}`, () => actor.userId);
      if ("error" in built) continue;
      const res = await ctx.api.request(actor, "POST", `/rest/v1/${t.name}`, built.row, { Prefer: "return=minimal", ...profileHeaders(t) });
      rec("insert", res.status === 201, `${res.status}`);
      if (res.status === 201) await cleanupInserted(ctx, t, built.row, `tp_${role}_`);
    }
  }
}

/**
 * The "still works" check: each tenant reads, updates, creates and deletes its OWN rows through the
 * API. Compared before and after a fix, any operation that worked before and fails after is a fix
 * that broke the app.
 */
async function ownerAccessCheck(ctx: Ctx): Promise<OwnerAccessRow[]> {
  const out: OwnerAccessRow[] = [];
  for (const t of tenantTables(ctx.schema)) {
    const q = qualified(t);
    if (ctx.world.unscoped.has(q)) continue;
    for (const actor of ctx.world.tenants) {
      const mine = victimRows(ctx, actor, q)[0];
      if (!mine) continue;
      const rec = (op: OwnerAccessRow["op"], ok: boolean, detail?: string) => out.push({ relation: q, actor: actor.label, role: "owner", op, ok, detail });
      // read
      if (t.grants.authenticated.select) {
        const path = `/rest/v1/${t.name}?${pkFilter(t, mine.pk)}&select=*`;
        const res = await ctx.api.request(actor, "GET", path, undefined, profileHeaders(t));
        rec("read", res.status === 200 && Array.isArray(res.body) && res.body.length > 0, `${res.status}`);
      }
      // update a plain column of its own row, verified in the database, then restored
      const col = mutableColumn(t);
      if (col && t.grants.authenticated.update) {
        const before = await fetchRow(ctx, t, mine.pk);
        if (before) {
          const isText = /text|character/.test(t.columns.find((c) => c.name === col)!.type);
          const value = isText ? "tp_owner_edit" : Number(before[col] ?? 0) + 1;
          const path = `/rest/v1/${t.name}?${pkFilter(t, mine.pk)}`;
          const res = await ctx.api.request(actor, "PATCH", path, { [col]: value }, { Prefer: "return=minimal", ...profileHeaders(t) });
          const after = await fetchRow(ctx, t, mine.pk);
          rec("update", !!after && String(after[col]) === String(value), `${res.status}`);
          await restoreColumns(ctx, t, before, [col], actor.userId);
        }
      }
      // create a new row under its own parents, then delete it through the API
      if (t.grants.authenticated.insert) {
        const own = (ref: string) => ctx.world.owned.find((o) => o.owner === actor.label && o.table === ref) ?? sharedRow(ctx, ref);
        const built = buildRow(t, ctx.world.profileTables, own, `tp_owner_${t.name}`, () => actor.userId);
        if ("error" in built) continue;
        const res = await ctx.api.request(actor, "POST", `/rest/v1/${t.name}`, built.row, { Prefer: "return=representation", ...profileHeaders(t) });
        const created = res.status === 201 && Array.isArray(res.body) ? (res.body[0] as Row) : undefined;
        rec("insert", res.status === 201, `${res.status}`);
        if (created && t.grants.authenticated.delete && t.primaryKey.every((c) => created[c] !== undefined)) {
          const pk = Object.fromEntries(t.primaryKey.map((c) => [c, created[c]]));
          const path = `/rest/v1/${t.name}?${pkFilter(t, pk)}`;
          const del = await ctx.api.request(actor, "DELETE", path, undefined, { Prefer: "return=minimal", ...profileHeaders(t) });
          const gone = !(await fetchRow(ctx, t, pk));
          rec("delete", gone, `${del.status}`);
          if (!gone) await query(ctx.db, `delete from ${qident(t)} where ${t.primaryKey.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")}`, t.primaryKey.map((c) => String(pk[c]))).catch(() => {});
        } else if (res.status === 201) {
          await cleanupInserted(ctx, t, built.row, "tp_owner_");
        }
      }
    }
  }
  return out;
}

export interface ProbeResult {
  observations: Observation[];
  /** What the judge needs about the test world beyond the schema. */
  world: WorldSummary;
  notes: string[];
  coverage: Coverage[];
  ownerAccess?: OwnerAccessRow[];
}

/** Number of discrete probe steps runProbes walks; used to size an overall progress bar. */
export const PROBE_STEP_COUNT = 13;

export async function runProbes(
  api: SupabaseApi,
  db: pg.Client,
  schema: Schema,
  world: World,
  onProgress?: ScanProgress,
  progressOffset = 0,
  progressTotal?: number,
): Promise<ProbeResult> {
  const anon: Actor = { label: "anon" };
  const enums = new Map<string, string[]>(
    (await query(db, "select format_type(t.oid, null) as name, array_agg(e.enumlabel::text order by e.enumsortorder) as labels from pg_type t join pg_enum e on e.enumtypid = t.oid group by t.oid")).rows.map((r) => [r.name, r.labels]),
  );
  const vectorDims = new Map<string, number>();
  for (const r of schema.relations) for (const c of r.columns) {
    const m = /^(?:\w+\.)?(vector|halfvec)\((\d+)\)/.exec(c.type);
    if (m && !vectorDims.has(m[1])) vectorDims.set(m[1], Number(m[2]));
  }
  const ctx: Ctx = { api, db, schema, world, observations: [], notes: [], coverage: new Map(), enums, vectorDims };
  for (const t of tenantTables(schema)) {
    const q = qualified(t);
    // A table filed as "shared" only because attribution found no owner may in fact be tenant-scoped
    // through a JWT claim the scan does not mint. Mark that honestly: it is not shared, and not a silent
    // gap, but a tenancy the scan could not attack.
    const jwtScoped = world.unscoped.has(q) ? jwtClaimScope(schema, t) : undefined;
    ctx.coverage.set(q, { relation: q, kind: "table", reached: 0, unreachable: 0, populated: !world.unpopulated.has(q), reason: world.unpopulated.get(q), shared: world.unscoped.has(q) && !jwtScoped, staffList: /^app-wide staff list/.test(world.unpopulated.get(q) ?? ""), ...(jwtScoped ? { jwtScoped } : {}) });
  }
  const everyone = [anon, ...world.tenants];
  // Each probe is isolated: one failure is a note in the report, never a lost report.
  const steps: [string, () => Promise<void>][] = [
    ["read", () => readSweep(ctx, everyone)],
    ["policy_state_read", () => policyStateRead(ctx, everyone)],
    ["graphql", () => graphqlProbe(ctx, everyone)],
    ["user_metadata", () => metadataProbe(ctx)],
    ["self_escalation", () => selfEscalationProbe(ctx)],
    ["self_enrollment", () => selfEnrollmentProbe(ctx)],
    ["update", () => updateProbe(ctx, everyone)],
    ["reparent", () => reparentProbe(ctx)],
    ["insert", () => insertProbe(ctx, everyone)],
    ["impersonation", () => impersonationProbe(ctx)],
    ["rpc", () => rpcProbe(ctx, everyone)],
    ["storage", () => storageProbe(ctx, everyone)],
    ["delete", () => deleteProbe(ctx, everyone)],
  ];
  const total = progressTotal ?? steps.length;
  for (let i = 0; i < steps.length; i++) {
    const [name, run] = steps[i];
    onProgress?.({ step: name, done: progressOffset + i, total });
    try {
      await run();
    } catch (e) {
      ctx.notes.push(`${name} probe stopped early: ${(e as Error).message}`);
    }
  }
  // The "still works" check runs last and only on request (fix verification), after all attacks.
  let ownerAccess: OwnerAccessRow[] | undefined;
  if (process.env.TENANTBLEED_OWNER_CHECK) {
    ownerAccess = await ownerAccessCheck(ctx).catch((e) => (ctx.notes.push(`owner check stopped early: ${(e as Error).message}`), []));
    // Shared and privileged access: what a coworker in tenant A's workspace, an app admin and the
    // stranger (tenant B) can do with tenant A's data. A fix must not take away what the coworker or
    // admin could do unless the stranger could do it too (then it was open access, flagged for review).
    const [owner, stranger] = world.tenants;
    const text = accessText(ctx);
    const roles: [Actor | undefined, OwnerAccessRow["role"], (a: Actor) => Promise<string[]>][] = [
      [world.extra?.coworker, "coworker", (a) => joinWorkspace(ctx, owner, a, text)],
      [world.extra?.admin, "admin", (a) => makeAdmin(ctx, a, text)],
    ];
    try {
      await accessAsRole(ctx, owner, stranger, "stranger", ownerAccess);
      for (const [actor, role, setup] of roles) {
        if (!actor) continue;
        const how = await setup(actor);
        if (!how.length) {
          ctx.notes.push(role === "coworker" ? "Fix check: no workspace membership to share, so coworker access was not tested." : "Fix check: no admin role found in the policies, so admin access was not tested.");
          continue;
        }
        ctx.notes.push(`Fix check: ${role} set up through ${how.join(", ")}.`);
        await accessAsRole(ctx, owner, actor, role, ownerAccess);
      }
    } catch (e) {
      ctx.notes.push(`role check stopped early: ${(e as Error).message}`);
    }
  }
  const summary: WorldSummary = { tenants: world.tenants.map((t) => ({ label: t.label, email: t.email })), profileTokens: [...world.profileTokens] };
  return { observations: ctx.observations, world: summary, notes: ctx.notes, coverage: [...ctx.coverage.values()], ownerAccess };
}
