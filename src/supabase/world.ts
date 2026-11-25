import pg from "pg";
import type { Actor, SupabaseApi } from "./api.js";
import { pick, seeded, type Rand } from "../core/random.js";
import { asUserClaims, query, sql, sqlOne, type Row } from "../exec/sql.js";
import { mark, marksOf, trace } from "../core/trace.js";
import { qualified, type Column, type ForeignKey, type Relation, type Schema } from "./introspect.js";

export const ident = (s: string) => `"${s.replace(/"/g, '""')}"`;
export const qident = (r: { schema: string; name: string }) => `${ident(r.schema)}.${ident(r.name)}`;

export type { Row };

export interface OwnedRow {
  table: string; // schema.name
  pk: Row;
  row: Row;
  owner: string; // actor label
  /** How the row was built (trace ids: "row/check-solved", "check/json-type", "row/rules-paused"). */
  via?: string[];
}

export interface World {
  tenants: Actor[];
  /** Rows that belong to a tenant, discovered through foreign keys to auth.users. */
  owned: OwnedRow[];
  /** Strings that only appear in a given tenant's data. Used to detect leaks in any response. */
  tokens: Map<string, Set<string>>;
  /** Tables whose rows have no path to a user, or that the config declares shared. */
  unscoped: Set<string>;
  /** Tables the scan could not put tenant data into, with the reason. */
  unpopulated: Map<string, string>;
  /** Tables whose primary key is a foreign key to auth.users (profiles). Treated like auth.users. */
  profileTables: Set<string>;
  /**
   * Tokens that come from a profile row (keyed by the user id): name, avatar, bio. Showing another
   * user's profile is normal in social apps, so a leak made only of these is weaker evidence.
   * Value = the column, so sensitive profile fields (email, phone) keep full weight.
   */
  profileTokens: Map<string, string>;
  notes: string[];
  /** Fix verification only: a second member of tenant A's workspace and an app admin. */
  extra?: { coworker?: Actor; admin?: Actor };
}

export interface WorldOptions {
  /** Tables declared shared on purpose (tenantbleed.json "shared"). */
  shared: Set<string>;
  /** User id of an extra account that is neither attacker nor victim (the person an owner invites). */
  bystander?: () => Promise<string | undefined>;
}

export const isAuthUsers = (fk: { refSchema: string; refTable: string }) => fk.refSchema === "auth" && fk.refTable === "users";

/** Profile tables: primary key is exactly a foreign key to auth.users (public.users, public.profiles, ...). */
export function findProfileTables(schema: Schema): Set<string> {
  const out = new Set<string>();
  for (const r of schema.relations) {
    if (r.kind !== "table" || r.primaryKey.length !== 1) continue;
    if (r.foreignKeys.some((fk) => isAuthUsers(fk) && fk.columns.length === 1 && fk.columns[0] === r.primaryKey[0])) out.add(qualified(r));
  }
  return out;
}

/** Remove parenthesized groups that contain a SELECT (EXISTS/IN subqueries), innermost first, so a
 * subquery's `alias.id = auth.uid()` does not look like the row's own pk compared to the caller. The
 * bare `(select auth.uid())` wrapper is kept (it has no FROM), so that shape still matches. */
function stripSubqueries(text: string): string {
  // Remove each `exists (...)` / `in (...)` group and its balanced parentheses (which hold a
  // subquery over another table), so only top-level comparisons on this row's own columns remain.
  let t = text;
  const re = /\b(?:exists|in)\s*\(/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t))) {
    let depth = 1;
    let i = re.lastIndex;
    for (; i < t.length && depth > 0; i++) {
      if (t[i] === "(") depth++;
      else if (t[i] === ")") depth--;
    }
    t = t.slice(0, m.index) + " " + t.slice(i);
    re.lastIndex = 0;
  }
  return t;
}

/** `col = auth.uid()` in any of its common shapes (::text, ::uuid, (select auth.uid()), reversed). */
function comparedToCaller(text: string, col: string): boolean {
  const c = col.replace(/[^\w]/g, "");
  // auth.uid() in the shapes pg_get_expr prints: (( SELECT auth.uid() AS uid))::text, (select auth.uid()), auth.uid().
  const uid = String.raw`\(*\s*(?:select\s+)?auth\.uid\(\)(?:\s+as\s+\w+)?\s*\)*(?:::\s*\w+)?`;
  // \b around the column so "id" does not match the tail of "owner_id".
  const cref = String.raw`(?:\w+\.)?"?\b${c}\b"?(?:::\s*\w+)?`;
  return new RegExp(`${cref}\\s*=\\s*${uid}|${uid}\\s*=\\s*${cref}`, "i").test(text);
}

/**
 * Profile tables the app never ties to auth.users with a foreign key: the server writes the row with
 * the auth id (often as text), and a policy compares that key to the caller's id. Without this the
 * table has no owner and everything hanging off it is judged "shared" and never attacked (one
 * field-test app's user table and the ~440 tables below it). Found from the policies, kept apart.
 */
export function findProfileTablesByPolicy(schema: Schema, fkProfiles: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const r of schema.relations) {
    const q = qualified(r);
    if (r.kind !== "table" || r.primaryKey.length !== 1 || fkProfiles.has(q)) continue;
    const pk = r.primaryKey[0];
    const pkCol = r.columns.find((c) => c.name === pk);
    if (!pkCol || !/^(uuid|text|character varying|citext)/.test(pkCol.type) || r.foreignKeys.some((fk) => fk.columns.includes(pk))) continue;
    // Narrow and reliable: the table's OWN policy compares its primary key to the caller's id at the
    // top level (the `id = auth.uid()::text` self policy on a user table). A comparison inside an
    // EXISTS/subquery is a parent's id, not this row's; a policy that compares some other column
    // (owner_id) is an ordinary owned table. Both are left alone.
    const ownPolicies = schema.policies.filter((p) => p.schema === r.schema && p.table === r.name).map((p) => stripSubqueries(`${p.using ?? ""} ${p.withCheck ?? ""}`));
    if (ownPolicies.some((t) => comparedToCaller(t, pk))) out.add(q);
  }
  return out;
}

/**
 * A tenant column with no foreign key that a policy scopes through a membership subquery
 * (`workspace_id in (select m.workspace_id from workspace_members m where m.user_id = auth.uid())`,
 * or the EXISTS form). Returns an inferred foreign key from that column to the membership table's
 * column, so the row is filled and attributed like a real key instead of being judged "shared".
 * Narrow on purpose: the subquery's table must have a person column compared to the caller.
 */
export function inferPolicyLinks(schema: Schema): Array<{ table: string; fk: ForeignKey; policy: string }> {
  const out: Array<{ table: string; fk: ForeignKey; policy: string }> = [];
  const byName = new Map(schema.relations.map((r) => [r.name, r]));
  const uid = String.raw`\(*\s*(?:select\s+)?auth\.uid\(\)(?:\s+as\s+\w+)?\s*\)*(?:::\s*\w+)?`;
  for (const t of schema.relations) {
    if (t.kind !== "table") continue;
    const q = qualified(t);
    const seen = new Set<string>();
    for (const p of schema.policies) {
      if (p.schema !== t.schema || p.table !== t.name) continue;
      const text = `${p.using ?? ""} ${p.withCheck ?? ""}`;
      // col IN ( SELECT [a.]refCol FROM [s.]ref ... )  with the subquery scoped to the caller.
      const inRe = /"?(\w+)"?\s+in\s*\(\s*select\s+(?:"?\w+"?\.)?"?(\w+)"?\s+from\s+(?:"?(\w+)"?\.)?"?(\w+)"?/gi;
      for (const m of text.matchAll(inRe)) {
        const [, col, refCol, rschema, rtable] = m;
        const ref = byName.get(rtable);
        if (!col || !ref || seen.has(col) || t.foreignKeys.some((f) => f.columns.includes(col)) || !t.columns.some((c) => c.name === col)) continue;
        if (!ref.columns.some((c) => c.name === refCol)) continue;
        // The membership table must tie a person to the caller somewhere in this policy.
        const personCol = ref.columns.find((c) => new RegExp(String.raw`\b${c.name}\b\s*=\s*${uid}|${uid}\s*=\s*\b${c.name}\b`, "i").test(text));
        if (!personCol) continue;
        // Resolve through the membership's own FK when its column is itself a foreign key (tenant_id -> tenants).
        const through = ref.foreignKeys.find((f) => f.columns.length === 1 && f.columns[0] === refCol);
        const fk: ForeignKey = through
          ? { columns: [col], refSchema: through.refSchema, refTable: through.refTable, refColumns: through.refColumns, inferred: true }
          : { columns: [col], refSchema: rschema || ref.schema, refTable: rtable, refColumns: [refCol], inferred: true };
        out.push({ table: q, fk, policy: p.name });
        seen.add(col);
      }
    }
  }
  return out;
}

/** A foreign key that identifies a person: to auth.users, or to a profile table keyed by the user id. */
export const isUserRef = (fk: ForeignKey, profiles: Set<string>) =>
  isAuthUsers(fk) || (profiles.has(`${fk.refSchema}.${fk.refTable}`) && fk.columns.length === 1);

export function tenantTables(schema: Schema): Relation[] {
  // A managed-schema table (auth, storage) is Supabase's, never the app's: the builder (a privileged
  // role) must not write to it, so it is left out here and reached only by the read sweep. Partition
  // leaves stay in: PostgREST 404s them, so they cost little and their 404 is labelled as a partition.
  return schema.relations.filter((r) => r.kind === "table" && r.primaryKey.length > 0 && !r.managed);
}

/**
 * Tenancy carried in the JWT: a policy scopes the table by a claim from the token, e.g.
 * `(auth.jwt() ->> 'org_id')::uuid = org_id` or `... -> 'app_metadata' ->> 'tenant' = tenant_id`.
 * There is no person foreign key and no auth.uid() comparison, so attribution finds no owner and the
 * table would otherwise be filed as "shared" (a false all-clear). This reads the claim the policy
 * checks against one of the table's own columns, so the scan can say the tenancy is real but in the
 * token, which it does not mint. Returns the claim name, or undefined.
 */
export function jwtClaimScope(schema: Schema, rel: Relation): string | undefined {
  const cols = new Set(rel.columns.map((c) => c.name));
  const text = schema.policies
    .filter((p) => p.schema === rel.schema && p.table === rel.name)
    .map((p) => `${p.using ?? ""} ${p.withCheck ?? ""}`)
    .join(" ");
  if (!text) return undefined;
  // auth.jwt() ->> 'claim', auth.jwt() -> 'app_metadata' ->> 'claim', or the request.jwt.claims setting,
  // in an equality with a bare column of this table (either side). Tolerant of how Postgres stores a
  // policy: wrapping parens, a ::text cast on each json key, and a trailing ::uuid/::text on the whole.
  const jwt = String.raw`\(*\s*(?:auth\.jwt\(\)|current_setting\(\s*'request\.jwt\.claims'[^)]*\)\s*\)*(?:::\s*jsonb)?)\s*\)*(?:->\s*'[^']+'(?:::\s*\w+)?\s*\)?\s*)*->>\s*'([^']+)'(?:::\s*\w+)?\s*\)*(?:::\s*\w+)?`;
  const re = new RegExp(String.raw`(?:"?(\w+)"?\s*=\s*${jwt})|(?:${jwt}\s*=\s*"?(\w+)"?)`, "gi");
  for (const m of text.matchAll(re)) {
    const claim = m[2] ?? m[3];
    const col = m[1] ?? m[4];
    if (claim && col && cols.has(col)) return claim;
  }
  return undefined;
}

/**
 * Tables ordered so that referenced tables come first. Tables can point at each other (an offer
 * belongs to a gig, a gig remembers the offer it came from): a link the row needs (a required column,
 * or one its CHECK rules name, "gig_id is not null or draft_id is not null") wins over an optional one,
 * so an optional back-link never pulls a table ahead of a parent it needs.
 */
export function topoOrder(tables: Relation[]): Relation[] {
  const byName = new Map(tables.map((t) => [qualified(t), t]));
  // MATCH SIMPLE: one empty column switches the key off, so it is needed only when every column is
  // mandatory (a key back to a child that includes the row's own id is optional), or a CHECK names it.
  const needed = (t: Relation, fk: ForeignKey) =>
    fk.columns.every((c) => t.columns.find((x) => x.name === c)?.notNull) ||
    fk.columns.some((c) => t.checks.some((d) => new RegExp(`\\b${c.replace(/[^\w]/g, "")}\\b`).test(d.replace(/'(?:[^']|'')*'/g, "''"))));
  const parents = (t: Relation, req: boolean) =>
    [...new Set(t.foreignKeys.filter((fk) => needed(t, fk) === req).map((fk) => byName.get(`${fk.refSchema}.${fk.refTable}`)).filter((d): d is Relation => !!d && d !== t))];
  // Required links decide the order (Kahn's algorithm): a table comes only after every parent it
  // needs, however many optional links lead around in a circle. Optional links only break ties: among
  // the tables that are ready, one whose optional parents exist already comes first, so its links get
  // filled. A circle of required links cannot be filled at all; those tables come last, in schema
  // order, and report the missing parent.
  const required = new Map(tables.map((t) => [t, parents(t, true)]));
  const optional = new Map(tables.map((t) => [t, parents(t, false)]));
  const done = new Set<Relation>();
  const out: Relation[] = [];
  const left = [...tables];
  while (left.length) {
    const ready = left.filter((t) => required.get(t)!.every((d) => done.has(d)));
    // A required cycle: nothing is ready. Force out the table with the fewest still-missing required
    // parents (ties: the one the most others still need), so only the cycle's own tables are built
    // out of order, not everything below them.
    const unmet = (t: Relation) => required.get(t)!.filter((d) => left.includes(d)).length;
    const neededBy = (t: Relation) => left.filter((o) => required.get(o)!.includes(t)).length;
    // A required cycle somewhere stalls the rest. Force out the table with the fewest still-missing
    // required parents (ties: the one the most others still need), so only the cycle's own tables are
    // built out of order, not everything below them.
    const pick = ready.length
      ? (ready.find((t) => optional.get(t)!.every((d) => done.has(d) || !left.includes(d) || required.get(d)!.some((x) => x === t))) ?? ready[0])
      : [...left].sort((a, b) => unmet(a) - unmet(b) || neededBy(b) - neededBy(a))[0];
    out.push(pick);
    done.add(pick);
    left.splice(left.indexOf(pick), 1);
  }
  // Stabilize: a table force-picked out of a stall may sit before a required parent that does not
  // itself (transitively) need it. Move that parent just before the child. Bounded; genuine cycles,
  // where each needs the other, are left as they are.
  const needsVia = (from: Relation, to: Relation, seen = new Set<Relation>()): boolean =>
    from === to || (!seen.has(from) && (seen.add(from), required.get(from)!.some((d) => needsVia(d, to, seen))));
  for (let pass = 0; pass < Math.min(out.length, 30); pass++) {
    let moved = false;
    for (let i = 0; i < out.length; i++) {
      for (const parent of required.get(out[i])!) {
        const j = out.indexOf(parent);
        if (j > i && !needsVia(parent, out[i])) {
          out.splice(j, 1);
          out.splice(i, 0, parent);
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  return out;
}

/**
 * One stream of test-data randomness per scan, reset by buildWorld: the same app and the same
 * order of calls give the same values every run.
 */
let rand: Rand = seeded("tenantbleed");
export const resetSampling = (seed = "tenantbleed") => void (rand = seeded(seed));

const randomLetters = (n: number) => Array.from({ length: n }, () => String.fromCharCode(97 + pick(rand, 26))).join("");

/** Value constraints we can read from CHECK definitions for one column. */
function checkHints(t: Relation, col: string) {
  const c = col.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const hints: { exactLen?: number; maxLen?: number; minLen?: number; oneOf?: string[]; oneOfNumbers?: number[]; positive?: boolean; min?: number; max?: number; patterns?: RegExp[] } = {};
  for (const def of t.checks) {
    // A quoted word that happens to equal the column name (home_view IN ('default', 'focus')) is not a mention.
    if (!new RegExp(`\\b${c}\\b`).test(def.replace(/'(?:[^']|'')*'/g, "''"))) continue;
    let m;
    if ((m = new RegExp(`(?:char_length|length)\\(\\(?${c}\\)?(?:::\\w+)?\\)\\s*=\\s*(\\d+)`).exec(def))) hints.exactLen = Number(m[1]);
    if ((m = new RegExp(`(?:char_length|length)\\(\\(?${c}\\)?(?:::\\w+)?\\)\\s*<=?\\s*(\\d+)`).exec(def))) hints.maxLen = Number(m[1]);
    if ((m = new RegExp(`(?:char_length|length)\\(\\(?${c}\\)?(?:::\\w+)?\\)\\s*>=?\\s*(\\d+)`).exec(def))) hints.minLen = Number(m[1]) + 1;
    const own = new RegExp(`\\(?${c}\\)?(?:::[\\w ]+)?\\s*=\\s*ANY\\s*\\(\\s*\\(?ARRAY\\[([^\\]]+)\\]`, "i").exec(def);
    // A list not written right after the column belongs to it only when the rule names no other
    // column: in CASE WHEN kind = ANY (...) THEN amount IS NOT NULL, the words are kind's, not amount's.
    const unquoted = def.replace(/'(?:[^']|'')*'/g, "''");
    const alone = t.columns.every((x) => x.name === col || !new RegExp(`\\b${x.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(unquoted));
    if (own || (alone && ((m = /ANY\s*\(\s*\(?ARRAY\[([^\]]+)\]/i.exec(def)) || (m = /\bIN\s*\(([^)]+)\)/i.exec(def))))) {
      const list = (own ?? m!)[1];
      const vals = [...list.matchAll(/'((?:[^']|'')*)'/g)].map((x) => x[1].replace(/''/g, "'"));
      if (vals.length) hints.oneOf = vals;
      // A list of numbers: run_day = ANY (ARRAY[1, 7, 14]).
      else if (own && /^[\s\d.,-]+$/.test(list)) hints.oneOfNumbers = list.split(",").map((x) => Number(x.trim()));
    } else if ((m = new RegExp(`(?<!\\w\\()(?<![\\w.])\\(?${c}\\)?(?:::\\w+)?\\s*=\\s*'((?:[^']|'')*)'`).exec(def)) && !/\bOR\b/.test(def)) {
      // Postgres deparses IN ('x') with one value as col = 'x'. Not inside a function call
      // (jsonb_typeof(value) = 'object'), and not one branch of an OR (left to the solver).
      hints.oneOf = [m[1].replace(/''/g, "'")];
    }
    if ((m = new RegExp(`\\(?${c}\\)?\\s*>\\s*\\(?(-?\\d+)`).exec(def))) hints.min = Number(m[1]) + 1;
    if ((m = new RegExp(`\\(?${c}\\)?\\s*>=\\s*\\(?(-?\\d+)`).exec(def))) hints.min = Number(m[1]);
    if ((m = new RegExp(`\\(?${c}\\)?\\s*<\\s*\\(?(-?\\d+)`).exec(def))) hints.max = Number(m[1]) - 1;
    if ((m = new RegExp(`\\(?${c}\\)?\\s*<=\\s*\\(?(-?\\d+)`).exec(def))) hints.max = Number(m[1]);
    // Regex checks, e.g. CHECK ((slug ~ '^[a-z0-9-]{2,50}$'::text)). POSIX classes are mostly JS-compatible.
    // Only checks that are a single regex: alternatives joined by OR are left to the constraint solver.
    if (!/\bOR\b/.test(def))
      for (const r of def.matchAll(new RegExp(`\\(?${c}\\)?(?:::\\w+)?\\s*(~\\*?)\\s*'((?:[^']|'')*)'`, "g"))) {
        const re = pgRegex(r[2], r[1] === "~*" ? "i" : "");
        if (re) (hints.patterns ??= []).push(re);
      }
  }
  return hints;
}

/**
 * A string matching a simple anchored regex: literals, escapes (\d \w \.), character classes and
 * quantifiers ({n}, {n,m}, +, *, ?). Covers hashes (^[0-9a-f]{64}$), prefixed ids (^mcpc_[A-Za-z0-9_-]{20,80}$),
 * colours and slugs. Groups and alternation are not handled.
 */
export function sampleFromRegex(re: RegExp): string | undefined {
  const src = re.source.replace(/^\^/, "").replace(/\$$/, "");
  const out = sampleSeq(src);
  return out !== undefined && re.test(out) ? out : undefined;
}

const PRINTABLE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/** Characters a bracket class allows, from a printable pool (negated classes too). */
function classChars(body: string): string {
  const negated = body.startsWith("^");
  const inner = negated ? body.slice(1) : body;
  const test = (() => {
    try {
      return new RegExp(`^[${inner}]$`);
    } catch {
      return undefined;
    }
  })();
  if (!test) return "";
  return [...PRINTABLE].filter((ch) => test.test(ch) !== negated).join("");
}

/** Index of the bracket or parenthesis that closes the one at `i`. */
function closing(src: string, i: number): number {
  if (src[i] === "[") {
    let j = i + 1;
    if (src[j] === "^") j++;
    if (src[j] === "]") j++;
    for (; j < src.length; j++) {
      if (src[j] === "\\") j++;
      else if (src[j] === "]") return j;
    }
    return -1;
  }
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === "\\") j++;
    else if (src[j] === "[") j = closing(src, j);
    else if (src[j] === "(") depth++;
    else if (src[j] === ")" && --depth === 0) return j;
    if (j < 0) return -1;
  }
  return -1;
}

/** Split on | at the top level of a pattern. */
function alternatives(src: string): string[] {
  const parts: string[] = [];
  let start = 0;
  for (let j = 0; j < src.length; j++) {
    if (src[j] === "\\") j++;
    else if (src[j] === "[" || src[j] === "(") {
      j = closing(src, j);
      if (j < 0) return [src];
    } else if (src[j] === "|") {
      parts.push(src.slice(start, j));
      start = j + 1;
    }
  }
  parts.push(src.slice(start));
  return parts;
}

/** A string for a pattern: first alternative, minimum repetitions, random characters from classes. */
function sampleSeq(src: string): string | undefined {
  const alts = alternatives(src);
  if (alts.length > 1) return sampleSeq(alts[0]);
  let out = "";
  let i = 0;
  while (i < src.length) {
    let piece: () => string | undefined;
    const ch = src[i];
    if (ch === "(") {
      const end = closing(src, i);
      if (end < 0) return undefined;
      const inner = src.slice(i + 1, end).replace(/^\?:/, "");
      piece = () => sampleSeq(inner);
      i = end + 1;
    } else if (ch === "[") {
      const end = closing(src, i);
      if (end < 0) return undefined;
      const chars = classChars(src.slice(i + 1, end));
      if (!chars) return undefined;
      piece = () => chars[pick(rand, chars.length)];
      i = end + 1;
    } else if (ch === "\\") {
      const e = src[i + 1];
      const chars = e === "d" ? "0123456789" : e === "w" ? "abcdefghijklmnopqrstuvwxyz" : e === "s" ? " " : e;
      piece = () => chars[pick(rand, chars.length)];
      i += 2;
    } else if (ch === ".") {
      piece = () => "abcdefghijklmnopqrstuvwxyz"[pick(rand, 26)];
      i++;
    } else if (ch === "^" || ch === "$") {
      i++;
      continue;
    } else {
      piece = () => ch;
      i++;
    }
    let n = 1;
    const q = /^\{(\d+)(?:,(\d*))?\}|^[+*?]/.exec(src.slice(i));
    if (q) {
      n = q[0] === "*" || q[0] === "?" ? 0 : q[0] === "+" ? 1 : Number(q[1]);
      i += q[0].length;
    }
    for (let k = 0; k < n; k++) {
      const v = piece();
      if (v === undefined) return undefined;
      out += v;
    }
  }
  return out;
}

/**
 * A staff list under any name (instance_delegates, trusted_users): a gate function named for a
 * privilege (is_operator(), has_admin_access()) only asks whether the caller has a row in the table,
 * and other tables' policies or other functions call it. A row there is the privilege itself, so test
 * users must not get one. A check that reads a flag or a role (is_admin, role = 'admin') is left
 * alone: the fill already avoids privileged values there.
 */
const GATE_NAME = /(^|_)(admins?|administrators?|operators?|staff|moderators?|superusers?|super_?admins?|sysadmins?)(_|$)/i;
const ROLE_COLUMN = /(^|_)(role|roles|access_level|permission|permissions|level|tier|rank)$/i;
const AUTH_UID = /\(\s*select\s+auth\.uid\(\)(?:\s+as\s+\w+)?\s*\)|auth\.uid\(\)/gi;
export function staffGate(schema: Schema, t: Relation, profiles: Set<string>): boolean {
  // A leaf: nothing points at it (a profile table that other rows hang off is never a staff list).
  const q = qualified(t);
  if (!t.foreignKeys.length || !t.foreignKeys.every((fk) => isAuthUsers(fk) || profiles.has(`${fk.refSchema}.${fk.refTable}`))) return false;
  if (schema.relations.some((r) => r !== t && r.foreignKeys.some((fk) => `${fk.refSchema}.${fk.refTable}` === q))) return false;
  const name = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const exists = new RegExp(
    String.raw`exists\s*\(\s*select\s+[\w.*]+\s+from\s+(?:"?${name(t.schema)}"?\.)?"?${name(t.name)}"?(?:\s+(?:as\s+)?(?!where\b)\w+)?\s+where\s+((?:[^()]|\([^()]*\))*)\)`,
    "gi",
  );
  const userOnly = (where: string) => {
    const conds = where.split(/\band\b/i).map((c) => c.trim().replace(/^\(+|\)+$/g, "").trim());
    const mine = conds.filter((c) => /^(\w+\.)?\w+\s*=\s*AUTHUID$|^AUTHUID\s*=\s*(\w+\.)?\w+$/i.test(c));
    const literal = (c: string) => {
      // status = 'active', withdrawn_at is null; never a bare flag (is_admin) or a role value.
      const m = /^(?:\w+\.)?(\w+)(?:\s*=\s*'[^']*'|\s+is\s+(?:not\s+)?null)$/i.exec(c);
      return !!m && !ROLE_COLUMN.test(m[1]);
    };
    return mine.length === 1 && conds.every((c) => mine.includes(c) || literal(c));
  };
  const call = (f: string) => new RegExp(String.raw`\b${name(f)}\s*\(`, "i");
  return schema.functions.some(
    (f) =>
      GATE_NAME.test(f.name) &&
      [...f.body.replace(AUTH_UID, "AUTHUID").matchAll(exists)].some((m) => userOnly(m[1])) &&
      (schema.policies.some((p) => p.table !== t.name && call(f.name).test(`${p.using ?? ""} ${p.withCheck ?? ""}`)) ||
        schema.functions.some((g) => g.name !== f.name && call(f.name).test(g.body))),
  );
}

/**
 * App-wide privilege values (platform_admin, super_admin, system, staff): a test user holding one sees
 * every tenant by design, which would turn the app's own admin feature into a fake leak. Roles inside
 * the tenant (owner, admin of their own workspace) stay allowed.
 */
const APP_WIDE = /^(platform|super|system|global|root|staff|internal|site|app|god)[_ -]?(admin|administrator|user|owner|staff|moderator|operator)?$|^(super_?admin|superuser|sysadmin|platform_admin|site_admin|app_admin|staff|moderator|support|service|system)$/i;
function firstSafe(options: string[], column: string): string {
  if (!/role|permission|access|level|tier|scope|type|kind|position|rank/i.test(column)) return options[0];
  return options.find((o) => !APP_WIDE.test(o)) ?? options[0];
}

function sampleValue(t: Relation, c: Column, marker: string): { ok: boolean; value?: unknown; via?: string } {
  const type = c.type.toLowerCase();
  const h = checkHints(t, c.name);
  if (type.endsWith("[]")) return h.oneOf ? { ok: true, value: [firstSafe(h.oneOf, c.name)], via: "value/check-list" } : { ok: true, value: [] };
  const numeric = /^(integer|bigint|smallint|numeric|real|double precision)/.test(type);
  if (h.oneOf && (!numeric || h.oneOf.every((v) => v.trim() !== "" && !Number.isNaN(Number(v))))) return { ok: true, value: firstSafe(h.oneOf, c.name), via: "value/check-list" };
  if (h.oneOfNumbers?.length) return { ok: true, value: h.oneOfNumbers[0], via: "value/check-number-list" };
  if (c.enumLabels.length) return { ok: true, value: firstSafe(c.enumLabels, c.name), via: "value/enum" };
  if (type === "uuid") return { ok: true, value: crypto.randomUUID() };
  // Transaction ids (an audit row's transaction_xid): any valid one will do.
  if (type === "xid8" || type === "xid") return { ok: true, value: "1" };
  const varcharLen = /character varying\((\d+)\)|character\((\d+)\)/.exec(type);
  if (/^(text|character varying|varchar|character|citext)/.test(type)) {
    const max = Math.min(h.maxLen ?? Infinity, varcharLen ? Number(varcharLen[1] ?? varcharLen[2]) : Infinity);
    if (h.exactLen !== undefined) return { ok: true, value: randomLetters(h.exactLen), via: "value/check-length" };
    if (h.patterns?.length) {
      const fit = (v: string) => v.slice(0, Math.min(max, 50));
      const slug = marker.toLowerCase().replace(/[^a-z0-9]+/g, "-");
      const tries = [marker, slug, marker.replace(/[^A-Za-z0-9]/g, "").toLowerCase(), `${slug}@example.com`, `${marker.replace(/[^A-Za-z0-9]/g, "").toLowerCase()}@example.com`, `https://example.com/${slug}`].map(fit);
      const ok = tries.find((v) => h.patterns!.every((re) => re.test(v)));
      if (ok) return { ok: true, value: ok, via: "value/check-pattern" };
      const gen = h.patterns.map(sampleFromRegex).find((v) => v !== undefined && h.patterns!.every((re) => re.test(v)));
      if (gen !== undefined) return { ok: true, value: gen, via: "value/check-pattern-generated" };
    }
    // Named for a value the database checks against its own list (a time zone through AT TIME ZONE or
    // pg_timezone_names): a made-up text fails, often in a trigger no CHECK hint shows.
    const known = wellKnownValue(c.name);
    if (known !== undefined && known.length <= max && (!h.patterns?.length || h.patterns.every((re) => re.test(known)))) return { ok: true, value: known, via: "value/well-known-format" };
    if (marker.length <= max) return { ok: true, value: marker.padEnd(h.minLen ?? 0, "x"), ...(h.minLen && marker.length < h.minLen ? { via: "value/check-length" } : {}) };
    return { ok: true, value: randomLetters(Math.max(1, Math.min(max, h.minLen ?? max))), via: "value/check-length" };
  }
  if (/^(integer|bigint|smallint)/.test(type)) {
    const lo = h.min ?? 1;
    const hi = h.max ?? lo + 9000;
    return { ok: true, value: lo + pick(rand, Math.max(1, hi - lo + 1)), ...(h.min !== undefined || h.max !== undefined ? { via: "value/check-range" } : {}) };
  }
  if (/^(numeric|real|double precision)/.test(type)) return { ok: true, value: Math.max(h.min ?? 1.5, Math.min(h.max ?? 1.5, 1.5)) };
  // A test user is an ordinary user: never an admin, moderator or staff member, or every
  // admin-only function would "prove" a leak that needs that role first.
  if (type === "boolean") return PRIVILEGE.test(c.name) ? { ok: true, value: false, via: "value/not-privileged" } : { ok: true, value: true };
  if (/^(timestamp|date)/.test(type)) return { ok: true, value: new Date().toISOString() };
  if (/^time with time zone/.test(type)) return { ok: true, value: "09:00:00+00" };
  if (/^time\b/.test(type)) return { ok: true, value: "09:00:00" };
  const vec = /^(?:\w+\.)?(vector|halfvec)\((\d+)\)/.exec(type);
  if (vec) return { ok: true, value: `[${Array.from({ length: Number(vec[2]) }, () => "0.1").join(",")}]` };
  if (type === "bytea") return { ok: true, value: `\\x${[...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("")}` };
  if (/^jsonb?$/.test(type)) return { ok: true, value: { tp: marker } };
  if (type === "inet") return { ok: true, value: "10.0.0.1" };
  // PostGIS: a point in the column's SRID (default 4326) is valid for Point and generic columns.
  const geo = /^(?:\w+\.)?(geography|geometry)(?:\((\w+)(?:,\s*(\d+))?\))?$/.exec(type);
  if (geo && (!geo[2] || /^point$/i.test(geo[2]) || /^geometry$/i.test(geo[2]))) return { ok: true, value: `SRID=${geo[3] ?? "4326"};POINT(0 0)` };
  return { ok: false };
}

/** Real values for columns named after a standard list: time zone, currency, country, language, locale. */
const WELL_KNOWN: [RegExp, string][] = [
  [/(^|_)(time_?zone|tz|tzid|tz_name|iana_tz)$/i, "UTC"],
  [/(^|_)currency(_code|_iso)?$/i, "USD"],
  [/(^|_)country(_code|_iso)?$/i, "US"],
  [/(^|_)(lang|language)(_code)?$/i, "en"],
  [/(^|_)locale$/i, "en-US"],
];
export const wellKnownValue = (column: string) => WELL_KNOWN.find(([re]) => re.test(column))?.[1];

/** Columns that grant a role: is_admin, superuser, is_staff, moderator, can_manage. */
const PRIVILEGE = /(^|_)(admin|administrator|superuser|super_admin|superadmin|staff|moderator|mod|root|owner_override|elevated|privileged|is_internal|can_manage|can_admin)($|_)/i;

/**
 * Both test users are ordinary users. Many apps make the first user to sign up an admin (a
 * bootstrap trigger), and the scan always creates tenant A first; left alone, every admin-only
 * function would "prove" that A can change B's data. Role columns on the test users' profile rows
 * are set back to false once the test data is built.
 */
async function demoteTestUsers(db: pg.Client, schema: Schema, profiles: Set<string>, tenants: Actor[], notes: string[]) {
  const ids = tenants.map((t) => t.userId).filter((x): x is string => !!x);
  if (!ids.length) return;
  for (const rel of schema.relations) {
    if (!profiles.has(qualified(rel))) continue;
    const roles = rel.columns.filter((c) => c.type === "boolean" && PRIVILEGE.test(c.name));
    if (!roles.length || rel.primaryKey.length !== 1) continue;
    const res = await query(
      db,
      `update ${qident(rel)} set ${roles.map((c) => `${ident(c.name)} = false`).join(", ")} where ${ident(rel.primaryKey[0])}::text = any($1) and (${roles.map((c) => `${ident(c.name)} is true`).join(" or ")})`,
      [ids],
    );
    if (res.rowCount) trace("world/admin-demoted", qualified(rel));
    if (res.rowCount)
      notes.push(`A test user was made ${roles.map((c) => c.name).join("/")} by the app itself (for example, the first user to sign up becomes admin), so the scan set it back: both test users are tested as ordinary users.`);
  }
}

/**
 * Apps that keep permissions in their own tables (member, role, role_permissions, permissions)
 * check them inside their functions. The test users get a role, but a role with no permissions, so
 * every call is refused, even the owner's own, and nothing can be told apart. Give each role a test
 * user holds every permission listed in the app's permission table (rows its migrations insert):
 * the test users become full owners of their own organization, nothing more.
 */
const CATALOG = /(^|_)(permissions?|capabilit(y|ies)|privileges?|scopes?)$/i;
const ROLE_TABLE = /(^|_)roles?$/i;
async function grantOwnPermissions(db: pg.Client, schema: Schema, owned: OwnedRow[], notes: string[]) {
  const byName = new Map(schema.relations.map((r) => [qualified(r), r]));
  for (const j of schema.relations) {
    if (j.kind !== "table") continue;
    const fkC = j.foreignKeys.find((fk) => !fk.inferred && CATALOG.test(fk.refTable));
    const fkR = fkC && j.foreignKeys.find((fk) => fk !== fkC && !fk.inferred && ROLE_TABLE.test(fk.refTable));
    if (!fkC || !fkR) continue;
    const roleTable = `${fkR.refSchema}.${fkR.refTable}`;
    // Role keys the test users hold: rows they own that point at the role table (member_roles).
    const keys = new Map<string, Row>();
    for (const o of owned) {
      const m = byName.get(o.table);
      for (const fk of m?.foreignKeys ?? []) {
        if (`${fk.refSchema}.${fk.refTable}` !== roleTable) continue;
        const key: Row = {};
        fk.refColumns.forEach((rc, i) => (key[rc] = o.row[fk.columns[i]]));
        if (fkR.refColumns.every((rc) => key[rc] !== undefined && key[rc] !== null)) keys.set(JSON.stringify(fkR.refColumns.map((rc) => key[rc])), key);
      }
    }
    if (!keys.size) continue;
    const covered = new Set([...fkC.columns, ...fkR.columns]);
    if (j.columns.some((c) => c.notNull && !c.hasDefault && !c.isIdentity && !c.isGenerated && !covered.has(c.name))) continue;
    const type = (c: string) => j.columns.find((x) => x.name === c)?.type ?? "text";
    const cols = [...fkR.columns, ...fkC.columns];
    let added = 0;
    for (const key of keys.values()) {
      const res = await query(
        db,
        `insert into ${qident(j)} (${cols.map(ident).join(", ")}) select ${fkR.columns.map((c, i) => `$${i + 1}::text::${type(c)}`).join(", ")}, ${fkC.refColumns.map((rc) => `c.${ident(rc)}`).join(", ")} from ${ident(fkC.refSchema)}.${ident(fkC.refTable)} c on conflict do nothing`,
        fkR.refColumns.map((rc) => String(key[rc])),
      ).catch(() => ({ rowCount: 0 }));
      added += res.rowCount ?? 0;
    }
    if (added) trace("world/permissions-granted", qualified(j));
    if (added) notes.push(`The test users' roles were given every permission in ${fkC.refSchema}.${fkC.refTable} (${added} grant(s) in ${qualified(j)}), so they act as full owners of their own organization and permission checks can be told apart.`);
  }
}

/** deferred: optional person columns left empty because the user's profile row did not exist yet. */
export type BuildResult = { row: Row; deferred?: { column: string; profile: string }[] } | { error: string };

/**
 * Values for a new row in `t`. Person columns get `userFor(col)`; tenant foreign keys get rows from
 * `fkSource` (normally the same tenant; the victim when probing inserts).
 */
export function buildRow(
  t: Relation,
  profiles: Set<string>,
  fkSource: (refTable: string, fk: ForeignKey, want?: Row) => OwnedRow | undefined,
  markerPrefix: string,
  userFor: (col: string) => string | undefined,
  hasProfile?: (profileTable: string) => boolean,
): BuildResult {
  const row: Row = {};
  const fkCols = new Set<string>();
  const deferred: { column: string; profile: string }[] = [];
  const setByKey = new Set<string>(); // columns a non-person foreign key has set
  // Person columns first, then the other foreign keys: a multi-column key such as
  // (project_id, user_id) -> project_members must copy the member row's user, not the tenant's.
  const ordered = [...t.foreignKeys].sort((a, b) => Number(!isUserRef(a, profiles)) - Number(!isUserRef(b, profiles)));
  for (const fk of ordered) {
    fk.columns.forEach((c) => fkCols.add(c));
    if (isUserRef(fk, profiles)) {
      // An optional column pointing at a profile table (workspaces.renewal_reminder_user_id ->
      // users) stays empty until the user's profile row exists: that row may itself need this one
      // first (users.workspace_id), and a filled key would fail. It is filled in afterwards.
      const optional = fk.columns.every((c) => !t.columns.find((x) => x.name === c)?.notNull);
      const profile = `${fk.refSchema}.${fk.refTable}`;
      if (!isAuthUsers(fk) && optional && hasProfile && !hasProfile(profile)) {
        fk.columns.forEach((c) => deferred.push({ column: c, profile }));
        continue;
      }
      fk.columns.forEach((c) => (row[c] = userFor(c)));
      continue;
    }
    const refQ = `${fk.refSchema}.${fk.refTable}`;
    // A column another foreign key already set (project_id -> projects and -> repositories): the
    // row for this key must carry the same value, or one of the two keys fails.
    // Person columns stay free to be replaced (a member row's user, not the tenant's).
    const want: Row = {};
    fk.columns.forEach((c, i) => {
      if (setByKey.has(c) && row[c] !== undefined && row[c] !== null) want[fk.refColumns[i]] = row[c];
    });
    const shared = Object.keys(want).length > 0;
    // Prefer a row that agrees; without one, take the usual row and let the later repair steps
    // (composite keys, a helper parent) reconcile it, as before.
    let ref = refQ === qualified(t) ? undefined : fkSource(refQ, fk, shared ? want : undefined);
    if (ref && shared && !Object.entries(want).every(([k, v]) => String(ref!.row[k]) === String(v))) ref = undefined;
    if (!ref && shared && refQ !== qualified(t)) ref = fkSource(refQ, fk);
    // MATCH SIMPLE: one null column skips the check, so the key is required only if every column is mandatory.
    const required = fk.columns.every((c) => t.columns.find((x) => x.name === c)?.notNull && !t.columns.find((x) => x.name === c)?.hasDefault);
    if (!ref) {
      if (required) return { error: `no ${refQ} row available for required foreign key ${fk.columns.join(", ")}` };
      continue;
    }
    fk.columns.forEach((c, i) => {
      row[c] = ref!.row[fk.refColumns[i]];
      setByKey.add(c);
    });
  }
  for (const c of t.columns) {
    if (fkCols.has(c.name) || c.isIdentity || c.isGenerated) continue;
    const isPk = t.primaryKey.includes(c.name);
    // A unique text column with a constant default ('' or 'draft') would be the same for both tenants
    // and collide on the second insert; fill it with a marker instead so each tenant gets its own row.
    const uniqueText = /^(text|character varying|varchar|character|citext)/.test(c.type.toLowerCase()) && (t.uniqueKeys ?? []).some((k) => k.length === 1 && k[0] === c.name) && t.columns.length > 2;
    // Supply our own uuid keys so we can find the row again; otherwise respect defaults.
    if (c.hasDefault && !(isPk && c.type === "uuid") && !uniqueText) continue;
    if (uniqueText) mark(row, "value/unique-default-filled");
    // Optional columns stay empty unless they are text (where the leak markers go): a filled
    // deleted_at, archived_at, locked flag or delete claim turns a fresh record into an unusual one,
    // which hides it from policies (deleted_at is null) or makes triggers refuse its children.
    if (!c.notNull && !isPk && !/^(text|character varying|varchar|character|citext|jsonb?|integer|bigint|smallint|numeric|(?:\w+\.)?vector|(?:\w+\.)?halfvec)\b/.test(c.type.toLowerCase())) continue;
    const v = sampleValue(t, c, `${markerPrefix}_${c.name}_${crypto.randomUUID().slice(0, 8)}`);
    if (!v.ok) {
      if (c.notNull) return { error: `unsupported required column ${c.name} (${c.type})` };
      continue;
    }
    row[c.name] = v.value;
    if (v.via) mark(row, v.via);
  }
  return deferred.length ? { row, deferred } : { row };
}

export function pkFilter(t: Relation, pk: Row): string {
  return t.primaryKey.map((c) => `${encodeURIComponent(c)}=eq.${encodeURIComponent(String(pk[c]))}`).join("&");
}

/**
 * The schema of every request, public included: PostgREST serves the first exposed schema when a
 * request names none, and an app may list another one before public (["archive", "public"]). The
 * curl lines in the evidence then reproduce the exact request.
 */
export function profileHeaders(t: { schema: string }): Record<string, string> {
  return { "Accept-Profile": t.schema, "Content-Profile": t.schema };
}

export const toParam = (v: unknown, type?: string) =>
  v !== null && typeof v === "object" && !(v instanceof Date) && (!Array.isArray(v) || /^jsonb?$/.test(type ?? "")) ? JSON.stringify(v) : v;

/** Parameter for a column of `t`: JSON columns always get JSON text, even for arrays. */
const colParam = (t: Relation, col: string, v: unknown) => {
  const type = t.columns.find((c) => c.name === col)?.type;
  // A plain string headed for a JSON column (a marker, a word from a CHECK list) must be JSON text.
  if (typeof v === "string" && /^jsonb?$/.test(type ?? "")) {
    try {
      JSON.parse(v);
      return v;
    } catch {
      return JSON.stringify(v);
    }
  }
  return toParam(v, type);
};

/** A refused insert. raised: the app's own code refused it (a RAISE in a trigger or function), whatever error code it chose. */
interface InsertFailure {
  code?: string;
  message?: string;
  constraint?: string;
  raised?: boolean;
}

async function insertAsService(db: pg.Client, t: Relation, row: Row, userId?: string): Promise<{ row?: Row } & InsertFailure> {
  const cols = Object.keys(row);
  const sql = cols.length
    ? `insert into ${qident(t)} (${cols.map(ident).join(", ")}) values (${cols.map((_, i) => `$${i + 1}`).join(", ")}) returning *`
    : `insert into ${qident(t)} default values returning *`;
  try {
    const [res] = await sqlOne(db, { ...asUserClaims(userId), statements: [{ text: sql, params: cols.map((c) => colParam(t, c, row[c])) }] });
    return { row: res.rows[0] };
  } catch (e) {
    const err = e as { code?: string; message?: string; constraint?: string; where?: string };
    return { code: err.code, message: err.message, constraint: err.constraint, raised: /\bat RAISE\b/.test(err.where ?? "") };
  }
}

/**
 * Last resort for a test row the app's own rules refuse however it is built (a JSON shape per kind,
 * a validation function, a trigger that needs onboarding to be finished): write that one row with
 * the table's CHECK constraints and triggers paused, in one transaction. The CHECKs come back at once
 * as NOT VALID, which the database still enforces on every new insert and update, so the attacks
 * that follow face all of the app's rules; only the test row itself skipped them.
 */
async function insertRelaxed(db: pg.Client, t: Relation, row: Row): Promise<{ row?: Row; paused: string[] }> {
  const checks = (await query(db, `select conname, pg_get_constraintdef(oid) as def from pg_constraint where conrelid = $1::regclass and contype = 'c'`, [qident(t)]).catch(() => ({ rows: [] as Row[] }))).rows as { conname: string; def: string }[];
  const cols = Object.keys(row);
  const insert = cols.length
    ? `insert into ${qident(t)} (${cols.map(ident).join(", ")}) values (${cols.map((_, i) => `$${i + 1}`).join(", ")}) returning *`
    : `insert into ${qident(t)} default values returning *`;
  try {
    const res = await sqlOne(db, {
      replica: true,
      statements: [
        ...checks.map((c) => ({ text: `alter table ${qident(t)} drop constraint ${ident(c.conname)}` })),
        { text: insert, params: cols.map((c) => colParam(t, c, row[c])) },
        ...checks.map((c) => ({ text: `alter table ${qident(t)} add constraint ${ident(c.conname)} ${c.def} not valid` })),
      ],
    });
    return { row: res[checks.length].rows[0], paused: checks.map((c) => c.conname) };
  } catch {
    return { paused: [] };
  }
}

/** Find a row we just inserted, by its uuid key or a unique marker value. */
async function locate(db: pg.Client, t: Relation, row: Row): Promise<Row | undefined> {
  const keys = t.primaryKey.filter((c) => row[c] !== undefined);
  const markerCol = Object.keys(row).find((c) => typeof row[c] === "string" && String(row[c]).startsWith("tp_"));
  const where = keys.length === t.primaryKey.length ? keys : markerCol ? [markerCol] : [];
  if (!where.length) return undefined;
  const res = await query(db, 
    `select * from ${qident(t)} where ${where.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")} limit 1`,
    where.map((c) => String(row[c])),
  );
  return res.rows[0];
}

/** Rows that already belong to a tenant, e.g. created by a signup trigger or by a parent insert. */
async function existingRows(db: pg.Client, t: Relation, tenant: Actor, profiles: Set<string>, mine: OwnedRow[]): Promise<Row[]> {
  const conds: string[] = [];
  const params: unknown[] = [];
  for (const fk of t.foreignKeys) {
    if (isUserRef(fk, profiles)) {
      params.push(tenant.userId);
      conds.push(`${ident(fk.columns[0])}::text = $${params.length}`);
      continue;
    }
    const parents = mine.filter((m) => m.table === `${fk.refSchema}.${fk.refTable}`);
    if (!parents.length || fk.columns.length !== 1) continue;
    params.push(parents.map((p) => String(p.row[fk.refColumns[0]])));
    conds.push(`${ident(fk.columns[0])}::text = any($${params.length})`);
  }
  if (!conds.length) return [];
  return (await query(db, `select * from ${qident(t)} where ${conds.join(" or ")} limit 20`, params)).rows;
}

// ---------------------------------------------------------------- CHECK constraint solver
// When the database names the CHECK a row broke, read its definition, try each OR branch, set the
// columns that branch needs (null, not null, a literal, true/false, a format, a different value),
// and ask Postgres whether the whole constraint now holds before inserting again.

/** Remove parentheses that wrap the whole expression. */
function unwrap(e: string): string {
  let s = e.trim();
  for (;;) {
    // COALESCE(rule, false) holds exactly when the rule holds.
    const co = /^COALESCE\(([\s\S]*), false\)$/i.exec(s);
    if (co && balanced(co[1])) {
      s = co[1].trim();
      continue;
    }
    if (!s.startsWith("(") || !s.endsWith(")")) return s;
    let depth = 0;
    let quoted = false;
    let wraps = true;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === "'") quoted = !quoted;
      if (quoted) continue;
      if (ch === "(") depth++;
      if (ch === ")") depth--;
      if (depth === 0 && i < s.length - 1) {
        wraps = false;
        break;
      }
    }
    if (!wraps) return s;
    s = s.slice(1, -1).trim();
  }
}

/** Parentheses outside quotes open and close in order and end level. */
function balanced(e: string): boolean {
  let depth = 0;
  let quoted = false;
  for (const ch of e) {
    if (ch === "'") quoted = !quoted;
    if (quoted) continue;
    if (ch === "(") depth++;
    if (ch === ")" && --depth < 0) return false;
  }
  return depth === 0 && !quoted;
}

/** Split on a boolean operator at the top level (outside parentheses and quotes). */
function splitTop(e: string, op: "OR" | "AND"): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quoted = false;
  let start = 0;
  const needle = ` ${op} `;
  for (let i = 0; i < e.length; i++) {
    const ch = e[i];
    if (ch === "'") quoted = !quoted;
    if (quoted) continue;
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (depth === 0 && e.startsWith(needle, i)) {
      parts.push(e.slice(start, i));
      start = i + needle.length;
      i += needle.length - 1;
    }
  }
  parts.push(e.slice(start));
  return parts.map(unwrap);
}

/** Postgres regex text to a JS RegExp (POSIX classes mapped). */
export function pgRegex(src: string, flags = ""): RegExp | undefined {
  const js = src
    .replace(/''/g, "'")
    .replace(/\[:alnum:\]/g, "A-Za-z0-9")
    .replace(/\[:alpha:\]/g, "A-Za-z")
    .replace(/\[:digit:\]/g, "0-9")
    .replace(/\[:space:\]/g, " \\t\\n\\r")
    .replace(/\[:cntrl:\]/g, "\\x00-\\x1f")
    .replace(/\[:upper:\]/g, "A-Z")
    .replace(/\[:lower:\]/g, "a-z");
  try {
    return new RegExp(js, flags);
  } catch {
    return undefined;
  }
}

type Alternative = (col: string, avoid: unknown, ownOnly?: boolean) => Promise<unknown>;

async function applyAtom(t: Relation, row: Row, atom: string, alt: Alternative): Promise<void> {
  const a = unwrap(atom);
  const col = (n: string) => t.columns.find((c) => c.name === n.replace(/"/g, ""));
  const name = `("?[A-Za-z_][A-Za-z0-9_]*"?)`;
  let m: RegExpExecArray | null;
  if ((m = new RegExp(`^${name} IS NULL$`).exec(a)) && col(m[1])) {
    mark(row, "check/is-null");
    row[col(m[1])!.name] = null;
    return;
  }
  if ((m = new RegExp(`^${name} IS NOT NULL$`).exec(a)) && col(m[1])) {
    mark(row, "check/not-null");
    const c = col(m[1])!;
    // A foreign-key column cannot take an invented value: take the tenant's own parent row (an offer
    // must belong to a gig or a draft). Without one, the candidate fails the check instead.
    const fk = t.foreignKeys.find((f) => f.columns.includes(c.name));
    if (fk) {
      if (fk.columns.length === 1 && (row[c.name] === null || row[c.name] === undefined)) {
        const v = await alt(c.name, undefined, true);
        if (v !== undefined && v !== null) {
          row[c.name] = v;
          mark(row, "check/parent-link");
        }
      }
      return;
    }
    if (row[c.name] === null || row[c.name] === undefined) {
      const v = sampleValue(t, c, `tp_fill_${c.name}_${crypto.randomUUID().slice(0, 8)}`);
      if (v.ok) row[c.name] = v.value;
    }
    return;
  }
  if ((m = new RegExp(`^NOT ${name}$`).exec(a)) && col(m[1])?.type === "boolean") {
    mark(row, "check/boolean-false");
    row[col(m[1])!.name] = false;
    return;
  }
  if ((m = new RegExp(`^${name}$`).exec(a)) && col(m[1])?.type === "boolean") {
    mark(row, "check/boolean-true");
    row[col(m[1])!.name] = true;
    return;
  }
  if ((m = new RegExp(`^${name} = '((?:[^']|'')*)'(?:::[\\w ]+)?$`).exec(a)) && col(m[1])) {
    mark(row, "check/equals-literal");
    row[col(m[1])!.name] = m[2].replace(/''/g, "'");
    return;
  }
  if ((m = new RegExp(`^${name}(?:::[\\w ]+)? = ANY \\(+ARRAY\\[\\(?(-?\\d+(?:\\.\\d+)?)`).exec(a)) && col(m[1])) {
    mark(row, "check/number-list");
    row[col(m[1])!.name] = Number(m[2]);
    return;
  }
  if ((m = new RegExp(`^${name} = ANY \\(+ARRAY\\['((?:[^']|'')*)'`).exec(a)) && col(m[1])) {
    mark(row, "check/text-list");
    row[col(m[1])!.name] = m[2].replace(/''/g, "'");
    return;
  }
  if ((m = new RegExp(`^${name} (?:<>|IS DISTINCT FROM) ${name}$`).exec(a)) && col(m[1]) && col(m[2])) {
    mark(row, "check/columns-differ");
    const [c1, c2] = [col(m[1])!, col(m[2])!];
    if (row[c1.name] === null || row[c2.name] === null || String(row[c1.name]) !== String(row[c2.name])) return;
    if (!c2.notNull) row[c2.name] = null;
    else if (!c1.notNull) row[c1.name] = null;
    else row[c2.name] = await alt(c2.name, row[c1.name]);
    return;
  }
  // Numeric bound: position >= 1, delta < 0, price_cents <= 10000000.
  if ((m = new RegExp(`^${name} (<=|>=|<|>) \\(?(-?\\d+(?:\\.\\d+)?)\\)?(?:::[\\w ]+)?$`).exec(a)) && col(m[1])) {
    mark(row, "check/number-bound");
    const c = col(m[1])!;
    const [op, bound] = [m[2], Number(m[3])];
    const cur = row[c.name];
    const ok = (x: number) => (op === "<" ? x < bound : op === "<=" ? x <= bound : op === ">" ? x > bound : x >= bound);
    if (typeof cur === "number" && ok(cur)) return;
    if (typeof cur === "string" && cur !== "" && !Number.isNaN(Number(cur)) && ok(Number(cur))) return;
    row[c.name] = op === "<" ? bound - 1 : op === ">" ? bound + 1 : bound;
    return;
  }
  // Date or time bound against a literal: happened_at >= '2026-01-01 00:00:00+00'::timestamp with time zone.
  if ((m = new RegExp(`^${name} (<=|>=|<|>) '(\\d{4}-\\d{2}-\\d{2}[^']*)'(?:::[\\w ]+)?$`).exec(a)) && col(m[1]) && /^(timestamp|date)/.test(col(m[1])!.type)) {
    mark(row, "check/date-bound");
    const c = col(m[1])!;
    const [op, bound] = [m[2], Date.parse(m[3].replace(" ", "T").replace(/\+00$/, "Z"))];
    if (Number.isNaN(bound)) return;
    const cur = Date.parse(String(row[c.name]));
    const ok = (x: number) => (op === "<" ? x < bound : op === "<=" ? x <= bound : op === ">" ? x > bound : x >= bound);
    if (!Number.isNaN(cur) && ok(cur)) return;
    const step = temporalStep(c.type);
    row[c.name] = temporalValue(op === "<" ? bound - step : op === ">" ? bound + step : bound, c.type);
    return;
  }
  // Clock time bound against a literal: opens_at >= '06:00:00'::time without time zone.
  if ((m = new RegExp(`^${name} (<=|>=|<|>) '(\\d{1,2}:\\d{2}(?::\\d{2})?[^']*)'(?:::[\\w ]+)?$`).exec(a)) && col(m[1]) && isClock(col(m[1])!.type)) {
    mark(row, "check/date-bound");
    const c = col(m[1])!;
    const [op, bound] = [m[2], temporalMs(m[3], c.type)];
    if (Number.isNaN(bound)) return;
    const cur = temporalMs(row[c.name], c.type);
    const ok = (x: number) => (op === "<" ? x < bound : op === "<=" ? x <= bound : op === ">" ? x > bound : x >= bound);
    if (!Number.isNaN(cur) && ok(cur)) return;
    row[c.name] = temporalValue(op === "<" ? bound - 3600_000 : op === ">" ? bound + 3600_000 : bound, c.type);
    return;
  }
  // NOT IN: kind <> ALL (ARRAY['a'::k, 'b'::k]) takes a value outside the list.
  if ((m = new RegExp(`^${name} <> ALL \\(+ARRAY\\[(.*)\\]\\)+$`).exec(a)) && col(m[1])) {
    mark(row, "check/not-in-list");
    const c = col(m[1])!;
    const listed = [...m[2].matchAll(/'((?:[^']|'')*)'/g)].map((x) => x[1].replace(/''/g, "'"));
    if (row[c.name] !== undefined && row[c.name] !== null && !listed.includes(String(row[c.name]))) return;
    const options = c.enumLabels.length ? c.enumLabels : (checkHints(t, c.name).oneOf ?? []);
    row[c.name] = options.find((o) => !listed.includes(o)) ?? `${listed[0] ?? "x"}_other`;
    return;
  }
  if ((m = new RegExp(`^${name} <> '((?:[^']|'')*)'(?:::[\\w ]+)?$`).exec(a)) && col(m[1])) {
    mark(row, "check/not-equal-literal");
    const c = col(m[1])!;
    const lit = m[2].replace(/''/g, "'");
    if (row[c.name] !== undefined && row[c.name] !== null && String(row[c.name]) !== lit) return;
    const options = c.enumLabels.length ? c.enumLabels : (checkHints(t, c.name).oneOf ?? []);
    const other = options.find((o) => o !== lit);
    row[c.name] = other ?? `${lit}_other`;
    return;
  }
  if ((m = new RegExp(`^${name} (<=|>=|<|>) ${name}$`).exec(a)) && col(m[1]) && col(m[3])) {
    mark(row, "check/column-order");
    const [c1, c2, op] = [col(m[1])!, col(m[3])!, m[2]];
    const fill = (c: Column) => {
      if (row[c.name] === undefined || row[c.name] === null) {
        const v = sampleValue(t, c, `tp_fill_${c.name}_${crypto.randomUUID().slice(0, 8)}`);
        if (v.ok) row[c.name] = v.value;
      }
    };
    fill(c1);
    fill(c2);
    const [v1, v2] = [row[c1.name], row[c2.name]];
    const holds = (x: unknown, y: unknown) => {
      const [p, q] = [temporalMs(x, c1.type), temporalMs(y, c2.type)];
      const [l, r] = !Number.isNaN(p) && !Number.isNaN(q) && isTemporal(c1.type) ? [p, q] : typeof x === "number" ? [x, Number(y)] : [String(x), String(y)];
      return op === "<" ? l < r : op === "<=" ? l <= r : op === ">" ? l > r : l >= r;
    };
    if (holds(v1, v2)) return;
    const bigger0 = op.startsWith(">") ? c1 : c2;
    const smaller0 = bigger0 === c1 ? c2 : c1;
    if (isTemporal(bigger0.type)) {
      // Chains of dates (a_start <= a_end < b_start <= b_end): move the side that must be later to
      // just after the other, never swap, so earlier links of the chain stay true.
      const base = temporalMs(row[smaller0.name], smaller0.type);
      if (Number.isNaN(base)) return;
      row[bigger0.name] = temporalValue(base + (op.includes("=") ? 0 : temporalStep(bigger0.type)), bigger0.type);
      if (isClock(bigger0.type) && temporalMs(row[bigger0.name], bigger0.type) <= base && !op.includes("=")) {
        // Too close to midnight to move later: move the earlier side back instead.
        row[smaller0.name] = temporalValue(base - temporalStep(smaller0.type), smaller0.type);
      }
      return;
    }
    if (holds(v2, v1)) {
      // Swapping works for canonical pairs (user_id_a < user_id_b).
      [row[c1.name], row[c2.name]] = [v2, v1];
      return;
    }
    // Equal values: move the side that must be greater by one hour or one unit; for ids
    // (user_id_a < user_id_b), take another row for one side, then order the pair.
    const bigger = op.startsWith(">") ? c1 : c2;
    const v = row[bigger.name];
    if (isTemporal(bigger.type)) {
      const ms = temporalMs(v, bigger.type);
      if (!Number.isNaN(ms)) row[bigger.name] = temporalValue(ms + temporalStep(bigger.type), bigger.type);
    }
    else if (typeof v === "number") row[bigger.name] = v + 1;
    else {
      row[c2.name] = await alt(c2.name, v1);
      if (!holds(row[c1.name], row[c2.name])) [row[c1.name], row[c2.name]] = [row[c2.name], row[c1.name]];
    }
    return;
  }
  if ((m = new RegExp(`^(?:cardinality|array_length)\\(${name}(?:, 1)?\\) (>=|>) (\\d+)$`).exec(a)) && col(m[1])) {
    mark(row, "check/array-length");
    const c = col(m[1])!;
    // Keep elements that a sibling atom (scopes <@ ARRAY[...]) already chose.
    if (Array.isArray(row[c.name]) && (row[c.name] as unknown[]).length) return;
    const el = c.type.replace(/\[\]$/, "");
    const one = c.enumLabels.length ? c.enumLabels[0] : /^(text|character varying)/.test(el) ? "https://example.com/tenantbleed" : /int/.test(el) ? 1 : el === "uuid" ? crypto.randomUUID() : "x";
    row[c.name] = Array.from({ length: Math.max(1, Number(m[3]) + (m[2] === ">" ? 1 : 0)) }, () => one);
    return;
  }
  // Array drawn from a fixed list: scopes <@ ARRAY['a', 'b'] (or the list contains it).
  if ((m = new RegExp(`^${name} <@ \\(?ARRAY\\['((?:[^']|'')*)'`).exec(a)) && col(m[1])) {
    mark(row, "check/array-from-list");
    row[col(m[1])!.name] = [m[2].replace(/''/g, "'")];
    return;
  }
  // A key of a JSON document pinned by the rule: (plan ->> 'kind') = 'scene', = ANY (ARRAY['1', '2']),
  // or = (id)::text, the row repeating its own id inside the document.
  const jsonKey = `\\(?${name} ->> '((?:[^']|'')*)'(?:::text)?\\)?`;
  const setKey = (c: Column, key: string, v: unknown) => {
    const cur = row[c.name];
    row[c.name] = { ...(cur !== null && typeof cur === "object" && !Array.isArray(cur) ? cur : {}), [key.replace(/''/g, "'")]: v };
    mark(row, "check/json-key");
  };
  const isJson = (n: string) => /^jsonb?$/.test(col(n)?.type ?? "");
  if ((m = new RegExp(`^${jsonKey} = '((?:[^']|'')*)'(?:::[\\w ]+)?$`).exec(a)) && isJson(m[1])) {
    setKey(col(m[1])!, m[2], m[3].replace(/''/g, "'"));
    return;
  }
  if ((m = new RegExp(`^${jsonKey} = ANY \\(+ARRAY\\['((?:[^']|'')*)'`).exec(a)) && isJson(m[1])) {
    setKey(col(m[1])!, m[2], m[3].replace(/''/g, "'"));
    return;
  }
  if ((m = new RegExp(`^${jsonKey} = \\(?${name}\\)?(?:::[\\w ]+)?$`).exec(a)) && isJson(m[1]) && col(m[3])) {
    const other = col(m[3])!;
    if (row[other.name] === undefined || row[other.name] === null) {
      // The other side has a default (a generated id): pick its value now so both agree.
      if (other.type === "uuid") row[other.name] = crypto.randomUUID();
      else {
        const v = sampleValue(t, other, `tp_fill_${other.name}_${crypto.randomUUID().slice(0, 8)}`);
        if (v.ok) row[other.name] = v.value;
      }
    }
    if (row[other.name] !== undefined && row[other.name] !== null) setKey(col(m[1])!, m[2], String(row[other.name]));
    return;
  }
  if ((m = new RegExp(`^jsonb?_typeof\\(${name}\\) = '(\\w+)'`).exec(a)) && col(m[1])) {
    mark(row, "check/json-type");
    const c = col(m[1])!;
    const cur = row[c.name];
    if (m[2] === "array" ? Array.isArray(cur) : m[2] === "object" ? cur !== null && typeof cur === "object" && !Array.isArray(cur) : false) return;
    row[c.name] = m[2] === "array" ? [] : m[2] === "object" ? {} : m[2] === "string" ? "tp" : m[2] === "number" ? 1 : m[2] === "boolean" ? true : {};
    return;
  }
  // Array length bounds: jsonb_array_length(steps) >= 1 (elements are empty objects).
  if ((m = new RegExp(`^jsonb?_array_length\\(${name}\\) (>=|>|<=|<|=) (\\d+)$`).exec(a)) && col(m[1])) {
    mark(row, "check/json-array-length");
    const c = col(m[1])!;
    const [op, n] = [m[2], Number(m[3])];
    const cur = Array.isArray(row[c.name]) ? (row[c.name] as unknown[]) : [];
    const len = op === ">=" || op === "=" ? Math.max(cur.length, n) : op === ">" ? Math.max(cur.length, n + 1) : op === "<" ? Math.min(cur.length, n - 1) : Math.min(cur.length, n);
    row[c.name] = Array.from({ length: len }, (_, i) => cur[i] ?? {});
    return;
  }
  if ((m = new RegExp(`^${name} (~\\*?) '((?:[^']|'')*)'(?:::\\w+)?$`).exec(a)) && col(m[1])) {
    mark(row, "check/regex");
    const re = pgRegex(m[3], m[2] === "~*" ? "i" : "");
    const v = re && sampleFromRegex(re);
    if (v !== undefined) row[col(m[1])!.name] = v;
    return;
  }
}

/** `(A) = (B)` at the top level, where both sides are conditions. */
function splitEquality(e: string): { l: string; r: string; op: "=" | "<>" } | undefined {
  const s = unwrap(e);
  if (!s.startsWith("(")) return undefined;
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "'") quoted = !quoted;
    if (quoted) continue;
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (depth === 0 && (s.startsWith(" = ", i) || s.startsWith(" <> ", i))) {
      const op = s.startsWith(" = ", i) ? "=" : "<>";
      const [l, r] = [s.slice(0, i), s.slice(i + op.length + 2)];
      const isCondition = (x: string) => /\bIS\b|=|\bANY\b|~|\bNOT\b/i.test(x);
      if (isCondition(l) && isCondition(r)) return { l: unwrap(l), r: unwrap(r), op };
      return undefined;
    }
  }
  return undefined;
}

/** The opposite condition, for the atoms the solver understands. */
/**
 * CASE WHEN a THEN x WHEN b THEN y ELSE z END, as the branches the solver already handles:
 * (a AND x) OR (NOT a AND b AND y) OR (NOT a AND NOT b AND z). Undefined when e is not one CASE.
 */
export function caseToOr(e: string): string | undefined {
  const x = unwrap(e).trim();
  if (!/^CASE\b/i.test(x) || !/\bEND$/i.test(x)) return undefined;
  // Split at the top-level keywords, outside quotes and parentheses.
  const parts: { kw: string; text: string }[] = [];
  let depth = 0;
  let quoted = false;
  let kw = "";
  let start = 0;
  for (let i = 0; i < x.length; i++) {
    const ch = x[i];
    if (ch === "'") quoted = !quoted;
    if (quoted) continue;
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (depth === 0 && /\s|^/.test(i ? x[i - 1] : " ")) {
      const m = /^(CASE|WHEN|THEN|ELSE|END)\b/i.exec(x.slice(i));
      if (m) {
        if (kw) parts.push({ kw, text: x.slice(start, i).trim() });
        kw = m[1].toUpperCase();
        start = i + m[1].length;
        i += m[1].length - 1;
      }
    }
  }
  const whens: { cond: string; then: string }[] = [];
  let otherwise: string | undefined;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].kw === "WHEN" && parts[i + 1]?.kw === "THEN") whens.push({ cond: unwrap(parts[i].text), then: unwrap(parts[i + 1].text) });
    if (parts[i].kw === "ELSE") otherwise = unwrap(parts[i].text);
  }
  // CASE x WHEN 'a' (a simple CASE) is not handled: its WHEN parts are values, not conditions.
  if (!whens.length || parts[0]?.text) return undefined;
  const not = (c: string) => (splitTop(c, "AND").length > 1 || splitTop(c, "OR").length > 1 ? `NOT (${c})` : negate(c));
  const branches = whens.map((w, i) => [...whens.slice(0, i).map((p) => not(p.cond)), w.cond, w.then].map((p) => `(${p})`).join(" AND "));
  // No ELSE: the CASE is NULL, which a CHECK accepts.
  branches.push([...whens.map((p) => not(p.cond)), otherwise ?? "true"].map((p) => `(${p})`).join(" AND "));
  return branches.map((b) => `(${b})`).join(" OR ");
}

function negate(atom: string): string {
  const a = unwrap(atom);
  if (/ IS NOT NULL$/.test(a)) return a.replace(/ IS NOT NULL$/, " IS NULL");
  if (/ IS NULL$/.test(a)) return a.replace(/ IS NULL$/, " IS NOT NULL");
  if (/^NOT /.test(a)) return a.slice(4);
  const m = /^("?[A-Za-z_][A-Za-z0-9_]*"?) = ('(?:[^']|'')*'(?:::[\w ]+)?)$/.exec(a);
  if (m) return `${m[1]} <> ${m[2]}`;
  const any = /^("?[A-Za-z_][A-Za-z0-9_]*"?) = ANY (\(+ARRAY\[.*\]\)+)$/.exec(a);
  if (any) return `${any[1]} <> ALL ${any[2]}`;
  return a;
}

/** Does `expr` (a CHECK body) hold for this row? Unset columns take their default, as an insert would. */
async function checkHolds(db: pg.Client, t: Relation, row: Row, expr: string): Promise<boolean> {
  const defaults = new Map<string, string>(
    (
      await query(db, 
        `select a.attname as name, pg_get_expr(d.adbin, d.adrelid) as def from pg_attrdef d
           join pg_attribute a on a.attrelid = d.adrelid and a.attnum = d.adnum where d.adrelid = $1::regclass`,
        [qident(t)],
      )
    ).rows.map((r) => [r.name, r.def]),
  );
  const params: unknown[] = [];
  const cols = t.columns.map((c) => {
    if (c.name in row) {
      params.push(colParam(t, c.name, row[c.name]));
      return `$${params.length}::${c.type} as ${ident(c.name)}`;
    }
    const d = defaults.get(c.name);
    return `${d && !/nextval|auth\.|current_setting/i.test(d) ? `(${d})` : "null"}::${c.type} as ${ident(c.name)}`;
  });
  // Evaluated in a transaction that is always rolled back; an error means the row does not fit.
  const [r] = await sql(db, [{ rollback: true, statements: [{ text: `select (${expr}) is not false as ok from (select ${cols.join(", ")}) as x`, params }] }]);
  return !r.error && r.results[0].rows[0]?.ok === true;
}

/** A row that satisfies the named CHECK constraint, or undefined when no branch can be satisfied. */
/** Stands for a partition's range (FOR VALUES FROM .. TO ..), which errors without a constraint name. */
const PARTITION = "\u0000partition";
const ANY_PARTITION = "\u0000any partition";

/**
 * Dates, timestamps and clock times as one number to compare and move. A time of day ("09:00:00",
 * "09:00:00+00") is milliseconds since midnight, never a date: Date.parse cannot read it.
 */
const DAY_MS = 86400_000;
const isClock = (type: string) => /^time\b/.test(type);
const isTemporal = (type: string) => /^(timestamp|date|time\b)/.test(type);
function temporalMs(v: unknown, type: string): number {
  if (!isClock(type)) return Date.parse(String(v));
  const m = /^(\d{1,2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?/.exec(String(v));
  return m ? ((Number(m[1]) * 60 + Number(m[2])) * 60 + Number(m[3] ?? 0)) * 1000 : NaN;
}
function temporalValue(ms: number, type: string): string {
  if (isClock(type)) {
    const t = Math.max(0, Math.min(DAY_MS - 1000, ms));
    const hh = String(Math.floor(t / 3600_000)).padStart(2, "0");
    const mm = String(Math.floor((t % 3600_000) / 60_000)).padStart(2, "0");
    const ss = String(Math.floor((t % 60_000) / 1000)).padStart(2, "0");
    return `${hh}:${mm}:${ss}${/with time zone/.test(type) ? "+00" : ""}`;
  }
  const d = new Date(ms);
  return type === "date" ? d.toISOString().slice(0, 10) : d.toISOString();
}
const temporalStep = (type: string) => (type === "date" ? DAY_MS : 3600_000);

async function solveCheck(db: pg.Client, t: Relation, row: Row, constraint: string, alt: Alternative): Promise<Row[]> {
  const def = (
    constraint === PARTITION
      ? (await query(db, "select 'CHECK (' || pg_get_partition_constraintdef($1::regclass) || ')' as d", [qident(t)])).rows[0]?.d
      : constraint === ANY_PARTITION
        ? // A partitioned table whose row fits no partition: aim at its first partition's range.
          (await query(db, "select 'CHECK (' || pg_get_partition_constraintdef(i.inhrelid) || ')' as d from pg_inherits i where i.inhparent = $1::regclass order by i.inhrelid limit 1", [qident(t)])).rows[0]?.d
      : (await query(db, "select pg_get_constraintdef(oid) as d from pg_constraint where conrelid = $1::regclass and conname = $2", [qident(t), constraint])).rows[0]?.d
  ) as string | undefined;
  if (!def) return [];
  const expr = unwrap(def.replace(/^CHECK\s*/i, "").replace(/\s+NOT VALID$/i, ""));
  // A CASE rule is solved as the OR of its branches; the rule itself still decides (checkHolds).
  const asOr = caseToOr(expr);
  if (asOr) trace("check/case", qualified(t));
  // Every branch that satisfies the constraint, in order: a trigger can still rewrite a column
  // (source := 'manual'), so the insert loop falls through to the next branch when one is refused.
  const out: Row[] = [];
  for (const branch of splitTop(asOr ?? expr, "OR")) {
    const atoms = splitTop(branch, "AND").flatMap((a) => splitTop(a, "AND"));
    const cand: Row = { ...row };
    for (const atom of atoms) await applyAtom(t, cand, atom, alt);
    if (await checkHolds(db, t, cand, expr)) out.push(cand);
    // (kind = 'wanted') = (budget IS NOT NULL): each side both true or both false. Several such
    // rules can be ANDed ((kind = 'photo') = (photo_path IS NOT NULL) AND (kind = 'statement') =
    // (body IS NOT NULL)), so try every combination, the plain atoms applied first.
    const eqs = (splitEquality(branch) ? [branch] : atoms).map(splitEquality).filter((e): e is NonNullable<typeof e> => !!e).slice(0, 4);
    if (eqs.length) {
      const plain = atoms.filter((x) => !splitEquality(x));
      for (let mask = 0; mask < 1 << (eqs.length * 1); mask++) {
        for (const order of [eqs, [...eqs].reverse()]) {
          const cand2: Row = { ...row };
          for (const atom of plain) await applyAtom(t, cand2, atom, alt);
          for (const eq of order) {
            const both = ((mask >> eqs.indexOf(eq)) & 1) === 0;
            const [lt, rt] = eq.op === "=" ? [both, both] : [both, !both];
            await applyAtom(t, cand2, lt ? eq.l : negate(eq.l), alt);
            await applyAtom(t, cand2, rt ? eq.r : negate(eq.r), alt);
          }
          if (await checkHolds(db, t, cand2, expr)) out.push(cand2);
        }
      }
    }
  }
  // Last resort: leave every optional column the constraint mentions empty.
  const cand: Row = { ...row };
  for (const c of t.columns) if (!c.notNull && new RegExp(`\\b${c.name}\\b`).test(expr)) cand[c.name] = null;
  if (await checkHolds(db, t, cand, expr)) out.push(cand);
  return out;
}

// ---------------------------------------------------------------- overlapping composite keys
// member_project_workspaces: (project_id, user_id) -> project_members and (workspace_id, user_id)
// -> workspaces(id, owner_id). Filled one at a time, the shared user_id disagrees. Walk the
// multi-column keys, keep the values an earlier key fixed, and find or create a parent row that
// matches them (here: a workspace owned by the invited member).

async function refRowExists(db: pg.Client, fk: ForeignKey, row: Row): Promise<boolean> {
  if (fk.columns.some((c) => row[c] === undefined || row[c] === null)) return true; // MATCH SIMPLE: nulls pass
  const where = fk.refColumns.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ");
  const res = await query(db, `select 1 from ${ident(fk.refSchema)}.${ident(fk.refTable)} where ${where} limit 1`, fk.columns.map((c) => String(row[c]))).catch(() => ({ rowCount: 1 }));
  return !!res.rowCount;
}

type EnsureRow = (ref: Relation, fixed: Row) => Promise<Row | undefined>;

async function reconcileCompositeKeys(db: pg.Client, t: Relation, row: Row, pool: OwnedRow[], ensure: EnsureRow, schema: Schema): Promise<Row> {
  const composite = t.foreignKeys.filter((f) => f.columns.length > 1);
  if (composite.length < 2) return row;
  // Which key anchors the shared column matters (an owner cannot be a member of their own project,
  // so the membership must pick the person and the workspace must follow). Try each key first and
  // keep the first combination where every key points at a real row.
  for (let k = 0; k < composite.length; k++) {
    const order = [composite[k], ...composite.filter((_, i) => i !== k)];
    const out: Row = { ...row };
    const fixed = new Set<string>();
    for (const fk of order) {
      const pinned = fk.columns.filter((c) => fixed.has(c));
      if (!(await refRowExists(db, fk, out))) {
        const ref = `${fk.refSchema}.${fk.refTable}`;
        const match = (r: Row) => pinned.every((c) => String(r[fk.refColumns[fk.columns.indexOf(c)]]) === String(out[c]));
        let parent = pool.filter((o) => o.table === ref).map((o) => o.row).find(match);
        if (!parent && pinned.length) {
          const rel = schema.relations.find((r) => qualified(r) === ref);
          if (rel) parent = await ensure(rel, Object.fromEntries(pinned.map((c) => [fk.refColumns[fk.columns.indexOf(c)], out[c]])));
        }
        if (parent) fk.columns.forEach((c, i) => (out[c] = parent![fk.refColumns[i]]));
      }
      fk.columns.forEach((c) => fixed.add(c));
    }
    let ok = true;
    for (const fk of composite) if (!(await refRowExists(db, fk, out))) ok = false;
    if (ok) return out;
  }
  return row;
}

/**
 * Each tenant creates rows in every table through the API, the way the real app would. Rows that
 * already exist for the tenant (signup triggers, parent triggers) are adopted first. When the API
 * refuses, the row is created with the service role but with the tenant's JWT claims, so triggers
 * and auth.uid() defaults behave as they would for that user.
 */
export async function buildWorld(api: SupabaseApi, db: pg.Client, schema: Schema, tenants: Actor[], opts: WorldOptions): Promise<World> {
  resetSampling();
  const notes: string[] = [];
  // Tenant columns with no foreign key that a policy scopes through a membership subquery: add an
  // inferred key so the row is filled and attributed, not judged "shared". (Mutates the in-memory
  // schema before ordering and building, so both see the link.)
  for (const { table, fk, policy } of inferPolicyLinks(schema)) {
    const r = schema.relations.find((x) => qualified(x) === table);
    if (!r) continue;
    r.foreignKeys.push(fk);
    notes.push(`${table}.${fk.columns[0]} has no foreign key; it was linked to ${fk.refSchema}.${fk.refTable} because policy "${policy}" scopes it that way.`);
  }
  const fkProfiles = findProfileTables(schema);
  const policyProfiles = findProfileTablesByPolicy(schema, fkProfiles);
  const profiles = new Set([...fkProfiles, ...policyProfiles]);
  for (const q of policyProfiles) {
    const r = schema.relations.find((x) => qualified(x) === q)!;
    notes.push(`${q} is treated as the user table: its ${r.primaryKey[0]} is compared to the signed-in user's id in a policy, though it has no foreign key to auth.users.`);
  }
  // A non-key column, with no foreign key, that a table's own policy compares to the caller's id
  // (recipient = auth.uid()): the column names a person, so it is filled with the test user's id.
  const noFkPersonCols = new Map<string, string[]>();
  for (const r of schema.relations) {
    const own = schema.policies.filter((p) => p.schema === r.schema && p.table === r.name).map((p) => `${p.using ?? ""} ${p.withCheck ?? ""}`);
    const cols = r.columns.filter((c) => !r.primaryKey.includes(c.name) && !r.foreignKeys.some((fk) => fk.columns.includes(c.name)) && /^(uuid|text|character varying|citext)/.test(c.type) && own.some((t) => comparedToCaller(t, c.name)));
    if (cols.length) noFkPersonCols.set(qualified(r), cols.map((c) => c.name));
  }
  // Shared tables are still populated (tenant rows point at them) but never get an owner.
  const tables = topoOrder(tenantTables(schema));
  const unpopulated = new Map<string, string>();
  // Rows that exist before the scan writes anything: lookup values and config from migrations or seed.sql.
  const preexisting = new Map<string, Row[]>();
  for (const t of tables) preexisting.set(qualified(t), (await query(db, `select * from ${qident(t)} limit 3`)).rows);

  // App-wide staff lists (moderators, admins, superusers) that the app's own rules consult: giving
  // the test users a row there makes them staff, who see everyone's data by design. Never fill them.
  const rules = [...schema.policies.map((p) => `${p.using ?? ""} ${p.withCheck ?? ""}`), ...schema.functions.map((f) => f.body)].join("\n").toLowerCase();
  const staffList = (t: Relation) =>
    /(^|_)(admins?|administrators?|moderators?|superusers?|super_admins?|staff|staff_members|platform_admins?|app_admins?|operators?)$/i.test(t.name) &&
    t.foreignKeys.every((fk) => (fk.refSchema === "auth" && fk.refTable === "users") || profiles.has(`${fk.refSchema}.${fk.refTable}`)) &&
    rules.includes(t.name.toLowerCase());
  const staff = new Set(tables.filter((t) => staffList(t) || staffGate(schema, t, profiles)).map(qualified));
  for (const q of staff) unpopulated.set(q, "app-wide staff list (the app's rules check it); test users are never made staff");

  const needsFiles = tables.some((t) => t.foreignKeys.some((f) => f.refSchema === "storage" && f.refTable === "objects"));
  const buckets = needsFiles ? ((await query(db, "select id, allowed_mime_types from storage.buckets order by id")).rows as { id: string; allowed_mime_types: string[] | null }[]) : [];

  for (const tenant of tenants) {
    const mine: OwnedRow[] = [];
    const later: { t: Relation; own: OwnedRow; deferred: { column: string; profile: string }[] }[] = [];
    const short = tenant.label.replace(/\W+/g, "").toLowerCase();
    // Tables that point at an uploaded file (documents.storage_object_id): upload one per bucket
    // as the tenant, under their user id, the way the app's upload button would. Upload triggers
    // run too, which is how some apps create those rows in the first place.
    for (const b of buckets) {
      const allowed = b.allowed_mime_types ?? [];
      const mime = !allowed.length || allowed.includes("text/plain") ? "text/plain" : (allowed.find((m) => !m.includes("*")) ?? "image/png");
      const name = `${tenant.userId}/tp_${short}_upload_${crypto.randomUUID().slice(0, 8)}.txt`;
      const res = await api.storage(tenant, "POST", `/storage/v1/object/${b.id}/${name.split("/").map(encodeURIComponent).join("/")}`, `tp_${short}_upload`, { "Content-Type": mime });
      if (res.status !== 200) continue;
      const obj = (await query(db, "select * from storage.objects where bucket_id = $1 and name = $2", [b.id, name])).rows[0];
      if (obj) mine.push({ table: "storage.objects", pk: { id: obj.id }, row: obj, owner: tenant.label });
    }
    for (const t of tables) {
      const q = qualified(t);
      if (staff.has(q)) continue;
      // One table's unexpected error leaves that table without test data; it never ends the scan.
      try {
        const adopted = await existingRows(db, t, tenant, profiles, mine);
        for (const r of adopted) mine.push({ table: q, pk: Object.fromEntries(t.primaryKey.map((c) => [c, r[c]])), row: r, owner: tenant.label, via: ["row/adopted-existing"] });
        if (adopted.length) trace("row/adopted-existing", q);

        // Prefer the parent the tenant actually owns through a person column; for shared parents
        // (catalogs) any row works, so fall back to the newest row in the table.
        const fkSource = (ref: string, _fk?: ForeignKey, want?: Row) =>
          mine.filter((r) => r.table === ref && (!want || Object.entries(want).every(([k, v]) => String(r.row[k]) === String(v)))).at(-1);
        const built = buildRow(t, profiles, fkSource, `tp_${short}_${t.name}`, () => tenant.userId, (profile) => mine.some((r) => r.table === profile));
        if ("error" in built) {
          if (!adopted.length) unpopulated.set(q, built.error);
          continue;
        }
        // A policy-profile's primary key is the user's id (written as text when the column is text),
        // and any no-foreign-key person column is the user's id, so the row belongs to the tenant.
        if (policyProfiles.has(q)) {
          const pk = t.primaryKey[0];
          const textPk = /^(text|character varying|citext)/.test(t.columns.find((c) => c.name === pk)?.type ?? "");
          built.row[pk] = textPk ? String(tenant.userId) : tenant.userId;
        }
        for (const c of noFkPersonCols.get(q) ?? []) built.row[c] = tenant.userId;
        // A parent row for another person (the invited member's own workspace), created with that
        // person's claims; its own parents come from the tenant's rows. Never owned by a tenant.
        const ensure: EnsureRow = async (rel, fixedVals) => {
          // Reuse a matching row first (the bystander's workspace made during the other tenant's pass).
          const keys = Object.keys(fixedVals);
          const found = await query(db, `select * from ${qident(rel)} where ${keys.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")} limit 1`, keys.map((c) => String(fixedVals[c])))
            .catch(() => ({ rows: [] as Row[] }));
          if (found.rows[0]) return found.rows[0] as Row;
          const person =Object.entries(fixedVals).find(([c]) => rel.foreignKeys.some((f) => isUserRef(f, profiles) && f.columns.includes(c)))?.[1] as string | undefined;
          const b = buildRow(rel, profiles, (ref) => mine.filter((r) => r.table === ref).at(-1), `tp_${short}_helper_${rel.name}`, () => person ?? tenant.userId);
          if ("error" in b) return undefined;
          const res = await insertAsService(db, rel, { ...b.row, ...fixedVals }, person ?? tenant.userId);
          if (res.row) trace("row/helper-parent", qualified(rel));
          return res.row;
        };
        // How this row gets built, step by step: counted and kept on the row once it is stored.
        const via = new Set<string>(marksOf(built.row));
        const beforeKeys = JSON.stringify(built.row);
        built.row = await reconcileCompositeKeys(db, t, built.row, mine, ensure, schema);
        if (JSON.stringify(built.row) !== beforeKeys) via.add("row/composite-keys");
        let stored: Row | undefined;
        let failure: InsertFailure | undefined;
        // Second attempt after a CHECK violation: leave optional columns that a CHECK mentions empty
        // (colour ~ '^#[0-9a-f]{6}$', iv-matches-status, shape checks across columns).
        const relaxed = (r: Row): Row =>
          Object.fromEntries(
            Object.entries(r).filter(([c]) => {
              const col = t.columns.find((x) => x.name === c);
              const inCheck = t.checks.some((d) => new RegExp(`\\b${c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(d));
              return !(col && !col.notNull && inCheck && !t.primaryKey.includes(c) && !t.foreignKeys.some((f) => f.columns.includes(c)));
            }),
          );
        // Value for a column that must differ from another (a <> b): another row of the same parent.
        const alt: Alternative = async (colName, avoid, ownOnly) => {
          const fk = t.foreignKeys.find((f) => f.columns.length === 1 && f.columns[0] === colName);
          if (!fk) return crypto.randomUUID();
          // A second person column that must differ (a chat's member_id, a transfer's to_user): use
          // the bystander, never another test user. Then the row names the tenant and a stranger, so
          // it belongs to the tenant and the other tenant attacking it is a real cross-tenant read;
          // picking tenant B would make the row shared between A and B and the table "shared".
          if (isUserRef(fk, profiles)) {
            const by = (await opts.bystander?.()) ?? undefined;
            if (by !== undefined && String(by) !== String(avoid)) return by;
            if (ownOnly) return undefined;
            // Fall back to any id that is neither the avoided one nor a test user.
            const notTenant = tenants.map((a) => a.userId).filter(Boolean) as string[];
            const q2 = await query(db, `select ${ident(fk.refColumns[0])} as v from ${ident(fk.refSchema)}.${ident(fk.refTable)} where ${ident(fk.refColumns[0])}::text <> all($1) limit 1`, [[String(avoid), ...notTenant]]).catch(() => ({ rows: [] as Row[] }));
            return q2.rows[0]?.v ?? avoid;
          }
          const ref = `${fk.refSchema}.${fk.refTable}`;
          const own = mine.filter((r) => r.table === ref).map((r) => r.row[fk.refColumns[0]]).find((v) => String(v) !== String(avoid));
          if (own !== undefined) return own;
          if (ownOnly) return undefined;
          const [rs, rn] = [fk.refSchema, fk.refTable];
          const other = await query(db, `select ${ident(fk.refColumns[0])} as v from ${ident(rs)}.${ident(rn)} where ${ident(fk.refColumns[0])}::text <> $1 limit 1`, [String(avoid)]).catch(() => ({ rows: [] }));
          return other.rows[0]?.v ?? avoid;
        };
        let row = built.row;
        const candidates = new Map<string, Row[]>();
        let relaxedTried = false;
        let bystanderTried = false;
        let shifted = false;
        let shortTried = false;
        let optionalTried = false;
        const filledForTrigger = new Set<string>();
        for (let attempt = 0; attempt < 12; attempt++) {
          if (t.grants.authenticated.insert) {
            const res = await api.request(tenant, "POST", `/rest/v1/${t.name}`, row, { Prefer: "return=minimal", ...profileHeaders(t) });
            if (res.status === 201) stored = await locate(db, t, row);
            if (stored) via.add("row/api-insert");
          }
          if (!stored) {
            const res = await insertAsService(db, t, row, tenant.userId);
            stored = res.row;
            failure = res;
            if (stored) via.add("row/service-insert");
          }
          if (stored) break;
          if (failure?.code === "23P01" && !shifted) {
            // An exclusion constraint (no overlapping campaigns or bookings): move this row's dates a year on.
            shifted = true;
            via.add("row/exclusion-shift");
            // Dates the table fills by default (a booking's next free slot) are not in the row yet:
            // evaluate their defaults so they move too.
            const defaulted = t.columns.filter((c) => /date|time/.test(c.type) && c.hasDefault && !(c.name in row));
            if (defaulted.length) {
              const d = await query(
                db,
                `select ${defaulted.map((c) => `(select pg_get_expr(ad.adbin, ad.adrelid) from pg_attrdef ad join pg_attribute a on a.attrelid = ad.adrelid and a.attnum = ad.adnum where ad.adrelid = $1::regclass and a.attname = '${c.name.replace(/'/g, "''")}') as ${ident(c.name)}`).join(", ")}`,
                [qident(t)],
              ).catch(() => ({ rows: [] as Row[] }));
              for (const c of defaulted) {
                const expr = d.rows[0]?.[c.name];
                if (typeof expr !== "string") continue;
                const v = await query(db, `select (${expr})::timestamptz as v`).catch(() => ({ rows: [] as Row[] }));
                if (v.rows[0]?.v) row = { ...row, [c.name]: new Date(v.rows[0].v as string).toISOString() };
              }
            }
            row = Object.fromEntries(
              Object.entries(row).map(([c, v]) => {
                const ty = t.columns.find((x) => x.name === c)?.type ?? "";
                return [c, /^(timestamp|date)/.test(ty) && v && !Number.isNaN(Date.parse(String(v))) ? new Date(Date.parse(String(v)) + 365 * 864e5).toISOString() : v];
              }),
            );
            continue;
          }
          if (failure?.code === "23514") {
            const msg = failure.message ?? "";
            const con = (failure as { constraint?: string }).constraint ?? (/violates partition constraint/.test(msg) ? PARTITION : /no partition of relation .* found for row/.test(msg) ? ANY_PARTITION : undefined);
            if (con) {
              if (!candidates.has(con)) candidates.set(con, await solveCheck(db, t, row, con, alt));
              const next = candidates.get(con)!.shift();
              if (next) {
                row = next;
                via.add(con === PARTITION || con === ANY_PARTITION ? "row/partition-solved" : "row/check-solved");
                for (const m of marksOf(next)) via.add(m);
                continue;
              }
            }
            if (!relaxedTried) {
              relaxedTried = true;
              row = relaxed(row);
              via.add("row/optional-left-empty");
              continue;
            }
          }
          // The app refused the row with its own rule on text shape or length (a trigger that allows
          // codes of at most 32 characters): the scan's marker text is long. Once, write it again with
          // short markers, still recognizable (tp_ and 8 hex characters).
          // A trigger copies a column this row left empty into another table that requires it (an
          // outbox event takes the row's tenant_id). Fill that column once: the parent row's value
          // for a column of the same name when there is one, else a value of its type.
          const copied = failure?.code === "23502" ? /null value in column "([^"]+)" of relation "([^"]+)"/.exec(failure.message ?? "") : null;
          const copiedCol = copied && copied[2] !== t.name ? t.columns.find((c) => c.name === copied[1] && !c.notNull) : undefined;
          if (copiedCol && (row[copiedCol.name] === undefined || row[copiedCol.name] === null) && !filledForTrigger.has(copiedCol.name)) {
            filledForTrigger.add(copiedCol.name);
            const fromParent = t.foreignKeys
              .map((fk) => mine.find((r) => r.table === `${fk.refSchema}.${fk.refTable}` && fk.refColumns.every((rc, i) => row[fk.columns[i]] !== undefined && String(r.row[rc]) === String(row[fk.columns[i]]))))
              .map((r) => r?.row[copiedCol.name])
              .find((v) => v !== undefined && v !== null);
            const sampled = fromParent === undefined ? sampleValue(t, copiedCol, `tp_${short}_${t.name}_${copiedCol.name}`) : undefined;
            const value = fromParent ?? (sampled?.ok ? sampled.value : undefined);
            if (value !== undefined) {
              row = { ...row, [copiedCol.name]: value };
              via.add("row/trigger-needs-column");
              continue;
            }
          }
          if (!shortTried && failure && !["23505", "23503", "23502"].includes(failure.code ?? "")) {
            // Never a link column: a text key that names the parent must keep naming it.
            const long = Object.keys(row).filter((c) => typeof row[c] === "string" && (row[c] as string).startsWith("tp_") && (row[c] as string).length > 11 && !t.foreignKeys.some((f) => f.columns.includes(c)));
            if (long.length) {
              shortTried = true;
              row = { ...row, ...Object.fromEntries(long.map((c) => [c, `tp_${crypto.randomUUID().slice(0, 8)}`])) };
              via.add("row/short-markers");
              continue;
            }
          }
          // The app's own error (a trigger that raises), not a constraint: optional links often carry
          // extra business rules (a debt may only be linked to an expense). Once, leave every optional
          // column empty except the person columns, so the row needs only what the table requires.
          if (!optionalTried && failure && (failure.raised || !/^23/.test(failure.code ?? ""))) {
            const optional = Object.keys(row).filter((c) => {
              const col = t.columns.find((x) => x.name === c);
              return col && !col.notNull && row[c] !== null && row[c] !== undefined && !t.primaryKey.includes(c) && !t.foreignKeys.some((f) => f.columns.includes(c) && isUserRef(f, profiles));
            });
            if (optional.length) {
              optionalTried = true;
              row = Object.fromEntries(Object.entries(row).filter(([c]) => !optional.includes(c)));
              via.add("row/optional-left-empty");
              continue;
            }
          }
          // Rules such as "an owner cannot add themselves as a member": the app expects another
          // person in the person column. Use a bystander account that is never an attacker or a
          // victim; the row still belongs to the tenant through its other foreign keys.
          const personCols = t.foreignKeys.filter((f) => isUserRef(f, profiles) && f.columns.length === 1).map((f) => f.columns[0]);
          const swappable = personCols.filter((c) => String(row[c]) === tenant.userId);
          const keepsOwner = t.foreignKeys.some((f) => !isUserRef(f, profiles) && f.columns.some((c) => row[c] !== undefined && row[c] !== null));
          if (!bystanderTried && opts.bystander && swappable.length && keepsOwner && failure?.code !== "23505") {
            bystanderTried = true;
            const other = await opts.bystander();
            if (other) {
              row = { ...row, ...Object.fromEntries(swappable.map((c) => [c, other])) };
              via.add("row/stand-in-person");
              continue;
            }
          }
          // Last: write it the way the app's own backend would (an accepted invite, a webhook), with
          // no signed-in user. Triggers that guard user actions usually let server writes through.
          if (failure?.code !== "23505") {
            const res = await insertAsService(db, t, row, undefined);
            if (res.row) {
              stored = res.row;
              via.add("row/backend-write");
              if (!notes.some((n) => n.startsWith("Some test rows"))) notes.push("Some test rows were written without a signed-in user, the way the app's backend would, because its triggers refuse that write from a user session.");
            }
          }
          // A rule no value we can build satisfies (CHECK 23514, or a trigger that raises, with P0001 or
          // an error code of its own such as 42501 or 55000): write the one test row with the rules
          // paused, and say so.
          // A raise with an error code of its own (42501 "join by invitation", "regions are fixed") is
          // often an access rule: it is paused only when there is no row the app made itself to use
          // instead (the tenant's own, or rows its migrations put in the table).
          if (!stored && (failure?.code === "23514" || failure?.code === "P0001" || (failure?.raised && !adopted.length && !preexisting.get(q)?.length))) {
            const res = await insertRelaxed(db, t, row);
            if (res.row) {
              stored = res.row;
              via.add("row/rules-paused");
              if (!notes.some((n) => n.startsWith(`${q}: its test rows`))) notes.push(`${q}: its test rows were written with the app's own rules paused for that insert (${res.paused.length ? `checks ${res.paused.join(", ")}, and its triggers` : "its triggers"}), because no value tenantbleed could build satisfies them (${(failure.message ?? "").slice(0, 100)}). Every attack still faces those rules.`);
            }
          }
          break;
        }
        if (!stored && failure && !adopted.length) {
          // Refused, but the table already has rows (lookup values its migrations insert, a singleton
          // config): children can point at those, and ownership is still worked out from the data.
          const seeded = preexisting.get(q) ?? [];
          if (seeded.length) {
            for (const r of seeded) mine.push({ table: q, pk: Object.fromEntries(t.primaryKey.map((c) => [c, r[c]])), row: r, owner: tenant.label, via: ["row/existing-parents"] });
            trace("row/existing-parents", q);
            if (failure.code !== "23505" && !notes.some((n) => n.includes(q))) notes.push(`${q} refuses new rows (${(failure.message ?? "").slice(0, 80)}); its existing rows were used as parents.`);
            continue;
          }
          // A unique violation on a table that already has rows (a row another tenant created under a
          // constant default, or a shared catalog): adopt the conflicting row by the key that failed,
          // so this tenant's children can point at it. Without this the table looked filled but this
          // tenant got no row in `mine`, and its children reported "no parent row available".
          if (failure.code === "23505") {
            for (const key of [t.primaryKey, ...(t.uniqueKeys ?? [])]) {
              if (!key.length || !key.every((c) => row[c] !== undefined && row[c] !== null)) continue;
              const found = await query(db, `select * from ${qident(t)} where ${key.map((c, i) => `${ident(c)}::text = $${i + 1}`).join(" and ")} limit 1`, key.map((c) => String(row[c]))).catch(() => ({ rows: [] as Row[] }));
              if (found.rows[0]) {
                stored = found.rows[0];
                via.add("row/existing-parents");
                break;
              }
            }
          }
          if (!stored) {
            const hasRows = failure.code === "23505" && !!(await query(db, `select 1 from ${qident(t)} limit 1`)).rowCount;
            if (!hasRows) unpopulated.set(q, `insert rejected by the database: ${failure.message ?? failure.code ?? "unknown error"}`);
          }
        }
        if (stored) {
          unpopulated.delete(q);
          for (const id of via) trace(id, q);
          const own: OwnedRow = { table: q, pk: Object.fromEntries(t.primaryKey.map((c) => [c, stored![c]])), row: stored, owner: tenant.label, via: [...via] };
          mine.push(own);
          if (built.deferred) later.push({ t, own, deferred: built.deferred });
        }
      } catch (e) {
        if (!mine.some((r) => r.table === q)) unpopulated.set(q, `tenantbleed could not build a row: ${(e as Error).message}`);
      }
    }
    // Fill in the optional person columns left empty above, now that the profile rows exist, so
    // policies that read them (renewal_reminder_user_id = auth.uid()) see a real value.
    for (const { t, own, deferred } of later) {
      const cols = deferred.filter((d) => mine.some((r) => r.table === d.profile)).map((d) => d.column);
      if (!cols.length) continue;
      const res = await query(
        db,
        `update ${qident(t)} set ${cols.map((c, i) => `${ident(c)} = $${i + 1}`).join(", ")} where ${t.primaryKey.map((c, i) => `${ident(c)}::text = $${cols.length + i + 1}`).join(" and ")}`,
        [...cols.map(() => tenant.userId), ...t.primaryKey.map((c) => String(own.pk[c]))],
      ).catch(() => ({ rowCount: 0 }));
      if (res.rowCount) {
        cols.forEach((c) => (own.row[c] = tenant.userId));
        own.via = [...(own.via ?? []), "row/person-filled-later"];
        trace("row/person-filled-later", own.table);
      }
    }
  }

  return attribute(db, schema, tenants, profiles, opts, unpopulated, notes, policyProfiles, noFkPersonCols);
}

/**
 * Ownership comes from data, not from who created a row:
 *  1. a row with a person foreign key (auth.users or a profile table) belongs to that user;
 *  2. a row referenced by a junction row (one that has a person FK, e.g. memberships) belongs to that user;
 *  3. a row referencing an owned row belongs to the same owner (repeat until stable).
 * Tables none of this reaches, or that the config declares shared, are "unscoped".
 */
async function attribute(
  db: pg.Client,
  schema: Schema,
  tenants: Actor[],
  profiles: Set<string>,
  opts: WorldOptions,
  unpopulated: Map<string, string>,
  notes: string[],
  policyProfiles: Set<string>,
  noFkPersonCols: Map<string, string[]>,
): Promise<World> {
  const tables = tenantTables(schema).filter((t) => !opts.shared.has(qualified(t)));
  const rows = new Map<string, Row[]>();
  for (const t of tables) rows.set(qualified(t), (await query(db, `select * from ${qident(t)} limit 5000`)).rows);

  const byUser = new Map(tenants.map((a) => [a.userId!, a.label]));
  const owner = new Map<string, string>(); // "table|pkjson" -> label
  const key = (t: Relation, r: Row) => `${qualified(t)}|${JSON.stringify(t.primaryKey.map((c) => r[c]))}`;
  const lookup = (refQ: string, cols: string[], vals: unknown[]): Row | undefined =>
    rows.get(refQ)?.find((x) => cols.every((c, i) => String(x[c]) === String(vals[i])));

  // Rows that name two different test users (a block, a message, a payment between them) belong to
  // both, so to neither for leak purposes: they never become one tenant's evidence or parent.
  const shared = new Set<string>();
  for (const t of tables) {
    for (const r of rows.get(qualified(t))!) {
      const people = new Set(t.foreignKeys.filter((fk) => isUserRef(fk, profiles)).map((fk) => byUser.get(String(r[fk.columns[0]]))).filter(Boolean));
      if (people.size > 1) {
        shared.add(key(t, r));
        continue;
      }
      // A policy-profile row whose primary key is a user id, or a no-foreign-key person column that
      // holds one, belongs to that user (the same as a person foreign key would).
      if (policyProfiles.has(qualified(t))) {
        const label = byUser.get(String(r[t.primaryKey[0]]));
        if (label) owner.set(key(t, r), label);
      }
      for (const col of noFkPersonCols.get(qualified(t)) ?? []) {
        const label = byUser.get(String(r[col]));
        if (label) owner.set(key(t, r), label);
      }
      for (const fk of t.foreignKeys) {
        if (!isUserRef(fk, profiles)) continue;
        const label = byUser.get(String(r[fk.columns[0]]));
        if (!label) continue;
        owner.set(key(t, r), label);
        // Junction rule, only for real membership tables: the person column and the parent column
        // are both part of the primary key (memberships(org_id, user_id)), or of one UNIQUE
        // constraint when the membership has its own id. A tenant table that merely points at a
        // catalog row (subscriptions.price_id) must not claim the catalog.
        for (const other of t.foreignKeys) {
          if (isUserRef(other, profiles)) continue;
          const pair = [...fk.columns, ...other.columns];
          if (!pair.every((c) => t.primaryKey.includes(c)) && !(t.uniqueKeys ?? []).some((k) => k.length === pair.length && pair.every((c) => k.includes(c)))) continue;
          const refT = tables.find((x) => qualified(x) === `${other.refSchema}.${other.refTable}`);
          const target = refT && lookup(qualified(refT), other.refColumns, other.columns.map((c) => r[c]));
          if (refT && target && !owner.has(key(refT, target))) {
            owner.set(key(refT, target), label);
            trace(pair.every((c) => t.primaryKey.includes(c)) ? "world/membership-claims-parent" : "world/membership-claims-parent-unique", qualified(t));
          }
        }
      }
    }
  }
  // A row that names both test users stays unowned even if a membership row (a per-user read
  // receipt such as chat_reads(chat_id, user_id)) claimed it for one of them.
  for (const k of shared) owner.delete(k);

  let changed = true;
  while (changed) {
    changed = false;
    for (const t of tables) {
      for (const r of rows.get(qualified(t))!) {
        if (owner.has(key(t, r)) || shared.has(key(t, r))) continue;
        for (const fk of t.foreignKeys) {
          if (isUserRef(fk, profiles)) continue;
          const refT = tables.find((x) => qualified(x) === `${fk.refSchema}.${fk.refTable}`);
          const target = refT && lookup(qualified(refT), fk.refColumns, fk.columns.map((c) => r[c]));
          const label = refT && target && owner.get(key(refT, target));
          if (label) {
            owner.set(key(t, r), label);
            changed = true;
            break;
          }
        }
      }
    }
  }

  const owned: OwnedRow[] = [];
  const unscoped = new Set<string>(opts.shared);
  // Singleton tables (a boolean primary key, `CHECK (id)`): one row of app configuration, not tenant data.
  for (const t of tables) {
    const pk = t.primaryKey.length === 1 ? t.columns.find((c) => c.name === t.primaryKey[0]) : undefined;
    if (pk?.type === "boolean") unscoped.add(qualified(t));
  }
  for (const t of tables) {
    if (unscoped.has(qualified(t))) continue;
    let any = false;
    for (const r of rows.get(qualified(t))!) {
      const label = owner.get(key(t, r));
      if (!label) continue;
      any = true;
      owned.push({ table: qualified(t), pk: Object.fromEntries(t.primaryKey.map((c) => [c, r[c]])), row: r, owner: label });
    }
    if (!any && !unpopulated.has(qualified(t))) unscoped.add(qualified(t));
  }

  // Tokens: values that identify ONE tenant's data. Only the row's own key, marker strings, and
  // foreign keys into other tenant-scoped tables. Foreign keys into shared catalogs are excluded
  // (both tenants may point at the same product, and a catalog id is not tenant data).
  const tokens = new Map<string, Set<string>>();
  const profileTokens = new Map<string, string>();
  for (const a of tenants) tokens.set(a.label, new Set([a.userId!]));
  for (const a of tenants) profileTokens.set(a.userId!, "id");
  for (const o of owned) {
    const t = tables.find((x) => qualified(x) === o.table)!;
    const set = tokens.get(o.owner)!;
    if (profiles.has(o.table)) for (const [col, v] of Object.entries(o.row)) if (typeof v === "string") profileTokens.set(v, col);
    const unscopedCols = new Set(t.foreignKeys.filter((fk) => unscoped.has(`${fk.refSchema}.${fk.refTable}`)).flatMap((fk) => fk.columns));
    for (const [col, v] of Object.entries(o.row)) {
      if (unscopedCols.has(col) || typeof v !== "string") continue;
      if (v.startsWith("tp_") || (/^[0-9a-f-]{36}$/i.test(v) && (t.primaryKey.includes(col) || t.foreignKeys.some((fk) => fk.columns.includes(col))))) set.add(v);
    }
  }
  // A value both tenants share is not evidence of anything.
  const [a, b] = tenants.map((x) => tokens.get(x.label)!);
  for (const v of [...a]) if (b.has(v)) (a.delete(v), b.delete(v));

  await demoteTestUsers(db, schema, profiles, tenants, notes);
  await grantOwnPermissions(db, schema, owned, notes);
  return { tenants, owned, tokens, unscoped, unpopulated, profileTables: profiles, profileTokens, notes };
}

export function findTokens(text: string, tokens: Set<string>): string[] {
  const hits: string[] = [];
  for (const t of tokens) if (text.includes(t)) hits.push(t);
  return hits;
}
