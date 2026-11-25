// Run Supabase's own linter (splinter, the SQL behind the dashboard's Security Advisor) against
// the local database, in a transaction that changes nothing. The judge labels each warning.
//
// splinter is vendored from github.com/supabase/splinter (PostgreSQL License, see
// SPLINTER-LICENSE; commit in SPLINTER-VERSION).

import type pg from "pg";
import type { LintRow } from "../core/scan-result.js";
import { query, sqlOne } from "../exec/sql.js";
import SPLINTER from "./splinter.sql";

export async function runSplinter(db: pg.Client, exposedSchemas: string[]): Promise<LintRow[]> {
  // splinter reads the exposed schemas from pgrst.db_schemas and sets search_path itself, both
  // with "set local", so it runs in its own transaction that changes nothing.
  const schemas = exposedSchemas.join(",").replace(/'/g, "''");
  const [, lints] = await sqlOne(db, { rollback: true, statements: [{ text: `set local pgrst.db_schemas = '${schemas}'` }, { text: SPLINTER }] });
  return lints.rows as LintRow[];
}

/** Functions and tables owned by an extension: the linter warns about them, but they are not the app's code. */
export async function extensionObjects(db: pg.Client): Promise<Record<string, string>> {
  const res = await query(
    db,
    `select n.nspname || '.' || coalesce(p.proname, c.relname) as name, e.extname as ext
       from pg_depend d
       join pg_extension e on e.oid = d.refobjid
       left join pg_proc p on d.classid = 'pg_proc'::regclass and p.oid = d.objid
       left join pg_class c on d.classid = 'pg_class'::regclass and c.oid = d.objid
       join pg_namespace n on n.oid = coalesce(p.pronamespace, c.relnamespace)
      where d.deptype = 'e' and d.refclassid = 'pg_extension'::regclass`,
  );
  return Object.fromEntries(res.rows.map((r) => [r.name as string, r.ext as string]));
}

/** Trigger functions, which the API cannot call: the judge needs them to label function lints. */
export async function triggerFunctions(db: pg.Client): Promise<string[]> {
  return (await query(db, "select n.nspname || '.' || p.proname as f from pg_proc p join pg_namespace n on n.oid = p.pronamespace where p.prorettype in ('trigger'::regtype, 'event_trigger'::regtype)")).rows.map(
    (r) => r.f as string,
  );
}
