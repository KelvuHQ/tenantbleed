/**
 * What the scan had to do to test an app: each test-data step and argument strategy that actually
 * contributed (a row built by solving a CHECK, a call aimed with a parent column), counted, with a
 * few of the tables or functions it was used on. Reports carry it, so across many scans we can see
 * which strategies do the work, which shapes most often block testing, and which code never runs.
 * scripts/rules.json lists every strategy; the fixture suite checks each is exercised.
 *
 * One scan runs per process, so a module-level tally is enough; scan() resets it.
 */
export interface TraceRow {
  id: string;
  count: number;
  /** Up to five tables or functions it was used on. */
  examples: string[];
}

const tally = new Map<string, { count: number; examples: string[] }>();

export function trace(id: string, where?: string): void {
  const t = tally.get(id) ?? { count: 0, examples: [] };
  t.count++;
  if (where && t.examples.length < 5 && !t.examples.includes(where)) t.examples.push(where);
  tally.set(id, t);
}

export function traceReset(): void {
  tally.clear();
}

/**
 * Marks: the strategy ids that shaped one object (a row being built, the body of a call). A step
 * marks what it works on; when the row is stored or the call proves something, its marks are
 * counted with trace() and copied into the finding's evidence ("via"), so the report can say what
 * a proof relied on. Same primitive for every engine.
 */
const marks = new WeakMap<object, Set<string>>();

export function mark(obj: object, id: string): void {
  const s = marks.get(obj) ?? new Set<string>();
  s.add(id);
  marks.set(obj, s);
}

export function marksOf(obj: object | undefined): string[] {
  return obj ? [...(marks.get(obj) ?? [])] : [];
}

export function traceRows(): TraceRow[] {
  return [...tally.entries()].map(([id, t]) => ({ id, count: t.count, examples: t.examples })).sort((a, b) => a.id.localeCompare(b.id));
}
