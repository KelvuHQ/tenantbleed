import pg from "pg";
import { query } from "../exec/sql.js";

export interface Column {
  name: string;
  type: string; // format_type output, e.g. "uuid", "text", "integer"
  typeCategory: string; // pg_type.typcategory
  notNull: boolean;
  hasDefault: boolean;
  isIdentity: boolean;
  isGenerated: boolean;
  enumLabels: string[];
}

export interface ForeignKey {
  columns: string[];
  refSchema: string;
  refTable: string;
  refColumns: string[];
  /** Not declared in the database: inferred from policies (user_id = auth.uid() without a foreign key). */
  inferred?: boolean;
}

export interface Relation {
  schema: string;
  name: string;
  kind: "table" | "view";
  rlsEnabled: boolean;
  securityInvoker: boolean;
  columns: Column[];
  primaryKey: string[];
  foreignKeys: ForeignKey[];
  /** CHECK constraint definitions, e.g. "CHECK ((char_length(currency) = 3))". */
  checks: string[];
  /** Columns of each UNIQUE constraint (memberships with their own id and UNIQUE (org_id, user_id)). */
  uniqueKeys?: string[][];
  grants: { anon: Privs; authenticated: Privs };
  /** A leaf of a partitioned table: "schema.parent". PostgREST serves the data as the parent, so this
   * leaf gets only a plain read sweep (a directly served, RLS-off leaf still leaks); the write and
   * reparent probes run against the parent, never the leaf. */
  partitionOf?: string;
  /** In a Supabase-managed schema (auth, storage, ...) that the app exposed. Never built or write-probed
   * (the builder runs as a privileged role, so it must not touch auth.users); still read-swept, since an
   * exposed managed table leaks like any other. */
  managed?: string;
}

export interface Privs {
  select: boolean;
  insert: boolean;
  update: boolean;
  delete: boolean;
}

export interface Policy {
  schema: string;
  table: string;
  name: string;
  cmd: string; // SELECT, INSERT, UPDATE, DELETE, ALL
  roles: string[];
  using: string | null;
  withCheck: string | null;
  /** False for AS RESTRICTIVE policies. */
  permissive?: boolean;
}

export interface RpcFunction {
  schema: string;
  name: string;
  args: { name: string; type: string }[];
  /** Number of trailing args that have defaults (can be omitted). */
  defaultedArgs: number;
  body: string;
  volatile: boolean;
  securityDefiner: boolean;
  returnsSet: boolean;
  returnType: string;
  execAnon: boolean;
  execAuthenticated: boolean;
}

export interface Schema {
  relations: Relation[];
  policies: Policy[];
  functions: RpcFunction[];
  /**
   * Bodies of the app's other functions (schemas not scanned, such as private), "schema.name" to
   * body, overloads joined. The caller check follows calls into them.
   */
  helpers?: Record<string, string>;
}

/** Schemas that belong to Supabase or Postgres, never to the app. */
const SYSTEM_SCHEMAS = `'auth','storage','realtime','supabase_functions','extensions','graphql','graphql_public','pgsodium','vault','net','cron','pgbouncer','supabase_migrations','information_schema','pg_catalog','_realtime','_analytics','pgmq'`;

/** Managed schemas an app can wrongly expose to the Data API. Their tables are Supabase's, not the
 * app's, so the builder (a privileged role) must never write to them; they are read-swept, not attacked. */
const MANAGED_SCHEMAS = new Set(["auth", "storage", "realtime", "supabase_functions", "vault", "pgsodium", "net", "cron", "pgmq"]);

export async function introspect(db: pg.Client, schemas: string[]): Promise<Schema> {
  const rels = await query(db, 
    `select c.oid, n.nspname as schema, c.relname as name, c.relkind, c.relrowsecurity,
            coalesce(c.reloptions::text[] && array['security_invoker=true','security_invoker=on'], false) as sec_invoker,
            has_table_privilege('anon', c.oid, 'SELECT') as a_sel,
            has_table_privilege('anon', c.oid, 'INSERT') as a_ins,
            has_table_privilege('anon', c.oid, 'UPDATE') as a_upd,
            has_table_privilege('anon', c.oid, 'DELETE') as a_del,
            has_table_privilege('authenticated', c.oid, 'SELECT') as u_sel,
            has_table_privilege('authenticated', c.oid, 'INSERT') as u_ins,
            has_table_privilege('authenticated', c.oid, 'UPDATE') as u_upd,
            has_table_privilege('authenticated', c.oid, 'DELETE') as u_del,
            pg_get_partition_constraintdef(c.oid) as part_def
       from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = any($1) and c.relkind in ('r','p','v','m')
        and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e')
      order by 2, 3`,
    [schemas],
  );

  const cols = await query(db, 
    `select a.attrelid as oid, a.attname as name,
            -- A domain (create domain cents as bigint check (value >= 0)) is its base type plus its rules.
            case when t.typtype = 'd' then format_type(t.typbasetype, t.typtypmod) else format_type(a.atttypid, a.atttypmod) end as type,
            case when t.typtype = 'd' then coalesce((select array_agg(pg_get_constraintdef(dc.oid)) from pg_constraint dc where dc.contypid = t.oid and dc.contype = 'c'), '{}') else '{}' end as domain_checks,
            case when t.typtype = 'd' then (select bt.typcategory from pg_type bt where bt.oid = t.typbasetype) else t.typcategory end as typcategory,
            a.attnotnull, a.atthasdef, a.attidentity <> '' as is_identity,
            a.attgenerated <> '' as is_generated,
            coalesce((select array_agg(e.enumlabel::text order by e.enumsortorder) from pg_enum e where e.enumtypid = coalesce(nullif(t.typelem, 0::oid), t.oid)), '{}') as enum_labels
       from pg_attribute a join pg_type t on t.oid = a.atttypid
      where a.attrelid = any($1) and a.attnum > 0 and not a.attisdropped
      order by a.attrelid, a.attnum`,
    [rels.rows.map((r) => r.oid)],
  );

  const cons = await query(db, 
    `select c.conrelid as oid, c.contype, pg_get_constraintdef(c.oid) as def,
            array(select attname from unnest(c.conkey) with ordinality k(n, i) join pg_attribute a on a.attrelid = c.conrelid and a.attnum = k.n order by k.i)::text[] as cols,
            rn.nspname as ref_schema, rc.relname as ref_table,
            array(select attname from unnest(c.confkey) with ordinality k(n, i) join pg_attribute a on a.attrelid = c.confrelid and a.attnum = k.n order by k.i)::text[] as ref_cols
       from pg_constraint c
       left join pg_class rc on rc.oid = c.confrelid
       left join pg_namespace rn on rn.oid = rc.relnamespace
      where c.conrelid = any($1) and c.contype in ('p','f','c','u')`,
    [rels.rows.map((r) => r.oid)],
  );

  // Leaf partitions: the parent is a partitioned table (relkind 'p'). PostgREST serves the data as the
  // parent, so a leaf is read-swept but not write-probed. Old-style INHERITS (non-partition parents)
  // is left out, since those children are their own served tables.
  const parts = await query(db,
    `select i.inhrelid as oid, pn.nspname || '.' || pc.relname as parent
       from pg_inherits i join pg_class pc on pc.oid = i.inhparent
       join pg_namespace pn on pn.oid = pc.relnamespace
      where i.inhrelid = any($1) and pc.relkind = 'p'`,
    [rels.rows.map((r) => r.oid)],
  );
  const partitionOf = new Map<number, string>(parts.rows.map((r) => [r.oid, r.parent]));

  const relations: Relation[] = rels.rows.map((r) => {
    const myCols = cols.rows.filter((c) => c.oid === r.oid);
    const myCons = cons.rows.filter((c) => c.oid === r.oid);
    return {
      schema: r.schema,
      name: r.name,
      kind: r.relkind === "v" || r.relkind === "m" ? "view" : "table",
      rlsEnabled: r.relrowsecurity,
      securityInvoker: r.sec_invoker,
      columns: myCols.map((c) => ({
        name: c.name,
        type: c.type,
        typeCategory: c.typcategory,
        notNull: c.attnotnull,
        hasDefault: c.atthasdef,
        isIdentity: c.is_identity,
        isGenerated: c.is_generated,
        enumLabels: c.enum_labels,
      })),
      primaryKey: myCons.find((c) => c.contype === "p")?.cols ?? [],
      foreignKeys: myCons
        .filter((c) => c.contype === "f")
        .map((c) => ({ columns: c.cols, refSchema: c.ref_schema, refTable: c.ref_table, refColumns: c.ref_cols })),
      uniqueKeys: myCons.filter((c) => c.contype === "u").map((c) => c.cols),
      // A partition's range (FOR VALUES FROM .. TO ..) works like a CHECK on its rows.
      checks: [
        ...myCons.filter((c) => c.contype === "c").map((c) => c.def),
        ...(r.part_def ? [`CHECK (${r.part_def})`] : []),
        // A domain's rule, written for the column it types (VALUE becomes the column).
        ...myCols.flatMap((c) => (c.domain_checks as string[]).map((d) => d.replace(/\bVALUE\b/g, /^[a-z_][a-z0-9_]*$/.test(c.name) ? c.name : `"${c.name}"`))),
      ],
      grants: {
        anon: { select: r.a_sel, insert: r.a_ins, update: r.a_upd, delete: r.a_del },
        authenticated: { select: r.u_sel, insert: r.u_ins, update: r.u_upd, delete: r.u_del },
      },
      ...(partitionOf.has(r.oid) ? { partitionOf: partitionOf.get(r.oid) } : {}),
      ...(MANAGED_SCHEMAS.has(r.schema) ? { managed: r.schema } : {}),
    };
  });

  const pols = await query(db, 
    `select schemaname, tablename, policyname, cmd, roles::text[] as roles, qual, with_check, permissive
       from pg_policies where schemaname = any($1)`,
    [schemas],
  );
  const policies: Policy[] = pols.rows.map((p) => ({
    schema: p.schemaname,
    table: p.tablename,
    name: p.policyname,
    cmd: p.cmd,
    roles: p.roles,
    using: p.qual,
    withCheck: p.with_check,
    permissive: p.permissive !== "RESTRICTIVE",
  }));

  const fns = await query(db, 
    `select n.nspname as schema, p.proname as name, p.prosecdef, p.proretset, p.pronargdefaults, p.prosrc, p.provolatile,
            format_type(p.prorettype, null) as ret,
            coalesce(p.proargnames, '{}') as argnames,
            array(select format_type(t, null) from unnest(p.proargtypes) t) as argtypes,
            has_function_privilege('anon', p.oid, 'EXECUTE') as exec_anon,
            has_function_privilege('authenticated', p.oid, 'EXECUTE') as exec_auth
       from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = any($1) and p.prokind = 'f'
        and p.prorettype <> 'trigger'::regtype
        and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`,
    [schemas],
  );
  const functions: RpcFunction[] = fns.rows.map((f) => ({
    schema: f.schema,
    name: f.name,
    args: (f.argtypes as string[]).map((t, i) => ({ name: f.argnames[i] ?? `arg${i}`, type: t })),
    defaultedArgs: f.pronargdefaults,
    body: f.prosrc ?? "",
    volatile: f.provolatile === "v",
    securityDefiner: f.prosecdef,
    returnsSet: f.proretset,
    returnType: f.ret,
    execAnon: f.exec_anon,
    execAuthenticated: f.exec_auth,
  }));

  const others = await query(
    db,
    `select n.nspname || '.' || p.proname as name, string_agg(coalesce(p.prosrc, ''), E'\n') as body
       from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where not (n.nspname = any($1)) and n.nspname not in (${SYSTEM_SCHEMAS}) and n.nspname not like 'pg\\_%'
        and p.prokind = 'f'
        and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
      group by 1`,
    [schemas],
  );
  const helpers = Object.fromEntries(others.rows.map((r) => [r.name as string, r.body as string]));

  inferPersonColumns(relations, policies);
  return { relations, policies, functions, helpers };
}

export function qualified(r: { schema: string; name: string }): string {
  return `${r.schema}.${r.name}`;
}

/** Schemas the Data API serves, from supabase/config.toml [api] schemas. */
export function exposedSchemasFromConfig(configToml: string): string[] | undefined {
  const api = /\[api\]([\s\S]*?)(?:\n\[|$)/.exec(configToml)?.[1];
  const list = api && /^\s*schemas\s*=\s*\[([^\]]*)\]/m.exec(api)?.[1];
  if (!list) return undefined;
  return [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]).filter((s) => !["graphql_public", "storage"].includes(s));
}

/** Schemas (other than the scanned ones) that hold tables granted to API roles: reachable the day they get exposed. */
export async function grantedButUnexposed(db: pg.Client, scanned: string[]): Promise<string[]> {
  const res = await query(db, 
    `select distinct n.nspname from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where c.relkind in ('r','p','v') and not (n.nspname = any($1))
        and n.nspname not in (${SYSTEM_SCHEMAS})
        and n.nspname not like 'pg_%'
        and (has_table_privilege('authenticated', c.oid, 'SELECT') or has_table_privilege('anon', c.oid, 'SELECT'))`,
    [scanned],
  );
  return res.rows.map((r) => r.nspname);
}

/**
 * Person columns without a foreign key. Many apps write `user_id uuid not null` (or a profiles.id
 * that is not a foreign key) and enforce ownership only in policies: `user_id = auth.uid()`. A uuid
 * column of the table that its own policies compare with auth.uid() holds a user id, so it gets an
 * inferred foreign key to auth.users and is treated exactly like a declared one.
 */
export function inferPersonColumns(relations: Relation[], policies: Policy[]): void {
  const uid = String.raw`\(?\s*(?:SELECT\s+)?auth\.uid\(\)(?:\s+AS\s+uid)?\s*\)?`;
  for (const r of relations) {
    if (r.kind !== "table") continue;
    const text = policies
      .filter((p) => p.schema === r.schema && p.table === r.name)
      .map((p) => `${p.using ?? ""} ${p.withCheck ?? ""}`)
      .join(" ");
    if (!text) continue;
    for (const c of r.columns) {
      if (c.type !== "uuid") continue;
      if (r.foreignKeys.some((f) => f.columns.length === 1 && f.columns[0] === c.name)) continue;
      const col = c.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      // Unqualified column (not x.user_id from a subquery on another table) compared with auth.uid().
      const direct = new RegExp(String.raw`(?<![.\w"])"?${col}"?\s*=\s*${uid}|${uid}\s*=\s*"?${col}"?(?![\w.])`, "i");
      // auth.uid() IN (owner_id, member_id), stored by Postgres as auth.uid() = ANY (ARRAY[owner_id, member_id]).
      const anyOf = [...text.matchAll(new RegExp(String.raw`${uid}\s*=\s*ANY\s*\(\s*ARRAY\[([^\]]+)\]`, "gi"))].some((m) =>
        m[1].split(",").some((x) => x.trim().replace(/"/g, "") === c.name),
      );
      if (direct.test(text) || anyOf) r.foreignKeys.push({ columns: [c.name], refSchema: "auth", refTable: "users", refColumns: ["id"], inferred: true });
    }
  }
}
