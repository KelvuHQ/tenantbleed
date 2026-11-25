/** Shapes of database functions that run on the clock, shared by the scanner and the judge. */

// A scheduled job (a cleanup, a reminder run): every write is gated on the clock, no caller check,
// and its only arguments are optional whole numbers (a batch size, a day window). A caller cannot
// pick whose rows change or what is written, only make the job run early.
const TIME = /\b(now\(\)|current_timestamp|current_date|clock_timestamp\(\)|interval\s*'|make_interval\s*\()/i;
export type JobShape = { args: { name: string; type: string }[]; defaultedArgs?: number; body: string } | undefined;
/**
 * A job gated on the clock that no argument can aim at a user: arguments are at most a batch size or
 * a time window (an amount such as p_count or p_credits is aimed and stays out), and it never reads
 * the caller. `anyArgs` also accepts such arguments without defaults (a retention period the caller
 * must pass); a scheduled job proper has every argument defaulted.
 */
const timeGated = (f: JobShape, anyArgs: boolean) =>
  !!f &&
  (anyArgs || (f.defaultedArgs ?? 0) >= f.args.length) &&
  f.args.every((a) => /^(integer|bigint|smallint|interval)$/.test(a.type) && (a.type === "interval" || /(batch|limit|size|max|days?|hours?|minutes?|window|gun|older|older_than|retention|ttl|ttl_days|ms|runtime_ms|batches|batches_total)$/i.test(a.name))) &&
  TIME.test(f.body) &&
  !/auth\.(uid|jwt|role)\(\)/i.test(f.body);
export const scheduledJob = (f: JobShape) => timeGated(f, false);
/** Maintenance by age (cleanup, reap, purge, expire): changes rows only past a time limit. */
export const timeMaintenance = (f: JobShape) => timeGated(f, true) && /\b(delete\s+from|update\s+[\w".]+\s+set|truncate)\b/i.test(f!.body);
