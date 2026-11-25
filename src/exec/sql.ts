import type pg from "pg";

/**
 * The `sql` primitive: every database call the scan makes goes through here. One operation is one
 * transaction: optional replica mode (no triggers or foreign-key checks), database role and JWT
 * claims, then its statements in order, then commit or roll back. A failed statement is a result,
 * not an exception: the operation stops there, rolls back and reports which statement failed.
 * Operations are plain JSON so the second split can send them over the network.
 */
export type Row = Record<string, unknown>;
/** A row read from the database: column values as pg returns them (loosely typed, like pg's own). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type DbRow = Record<string, any>;

export interface SqlStatement {
  text: string;
  params?: unknown[];
}

export interface SqlOp {
  statements: SqlStatement[];
  /** Database role for the whole transaction (`set local role`). Default: the service connection. */
  role?: "authenticated" | "anon";
  /** JWT claims seen by auth.uid() and auth.jwt(); `sub` also goes to request.jwt.claim.sub. */
  claims?: Record<string, unknown>;
  /** Skip triggers and foreign-key checks (session_replication_role = replica). */
  replica?: boolean;
  /** Roll back at the end instead of committing. */
  rollback?: boolean;
}

export interface SqlError {
  code?: string;
  message: string;
  constraint?: string;
  /** Where the error was raised, as the database reports it ("PL/pgSQL function f() line 3 at RAISE"). */
  where?: string;
  /** Index of the failed statement; -1 for the transaction setup, statements.length for the commit. */
  at: number;
}

export interface SqlResult {
  /** One entry per statement that ran, in order. */
  results: { rows: DbRow[]; rowCount: number }[];
  error?: SqlError;
}

const errorOf = (e: unknown, at: number): SqlError => {
  const x = e as { code?: string; message?: string; constraint?: string; where?: string };
  return { code: x.code, message: x.message ?? String(e), constraint: x.constraint, ...(x.where ? { where: x.where } : {}), at };
};

async function runOp(db: pg.Client, op: SqlOp): Promise<SqlResult> {
  const results: SqlResult["results"] = [];
  const run = async (s: SqlStatement) => {
    // A text with several statements (a vendored script) yields the rows of its last statement that has columns.
    const r = (await db.query(s.text, s.params)) as pg.QueryResult | pg.QueryResult[];
    const last = Array.isArray(r) ? ([...r].reverse().find((x) => x.fields?.length) ?? r[r.length - 1]) : r;
    results.push({ rows: last?.rows ?? [], rowCount: last?.rowCount ?? 0 });
  };
  // A single committed statement with no role or claims needs no explicit transaction.
  if (op.statements.length === 1 && !op.role && !op.claims && !op.replica && !op.rollback) {
    try {
      await run(op.statements[0]);
      return { results };
    } catch (e) {
      return { results, error: errorOf(e, 0) };
    }
  }
  const fail = async (e: unknown, at: number): Promise<SqlResult> => {
    await db.query("rollback").catch(() => {});
    return { results, error: errorOf(e, at) };
  };
  try {
    await db.query("begin");
    if (op.replica) await db.query("set local session_replication_role = replica");
    if (op.role) await db.query(`set local role ${op.role === "anon" ? "anon" : "authenticated"}`);
    if (op.claims)
      await db.query("select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true)", [JSON.stringify(op.claims), String(op.claims.sub ?? "")]);
  } catch (e) {
    return fail(e, -1);
  }
  for (let i = 0; i < op.statements.length; i++) {
    try {
      await run(op.statements[i]);
    } catch (e) {
      return fail(e, i);
    }
  }
  try {
    await db.query(op.rollback ? "rollback" : "commit");
  } catch (e) {
    return fail(e, op.statements.length);
  }
  return { results };
}

/** Run a batch of operations, in order, on one connection. */
export async function sql(db: pg.Client, ops: SqlOp[]): Promise<SqlResult[]> {
  const out: SqlResult[] = [];
  for (const op of ops) out.push(await runOp(db, op));
  return out;
}

/** One operation; throws the database error (with code and constraint) the way pg does. */
export async function sqlOne(db: pg.Client, op: SqlOp): Promise<SqlResult["results"]> {
  const [r] = await sql(db, [op]);
  if (r.error) throw Object.assign(new Error(r.error.message), { code: r.error.code, constraint: r.error.constraint, where: r.error.where, at: r.error.at });
  return r.results;
}

/** One committed statement; returns its rows, throws like pg. */
export async function query(db: pg.Client, text: string, params?: unknown[]): Promise<{ rows: DbRow[]; rowCount: number }> {
  return (await sqlOne(db, { statements: [{ text, params }] }))[0];
}

/** JWT claims for running as a signed-in user (triggers and defaults see auth.uid()). */
export const asUserClaims = (userId: string | undefined, extra: Record<string, unknown> = {}) =>
  userId ? { claims: { sub: userId, role: "authenticated", ...extra } } : {};
