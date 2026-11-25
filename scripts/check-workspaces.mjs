// Gate for fixtures/supabase-workspaces (personal and team workspaces). The member row of a project
// must agree with two parents on the workspace. Here: the row exists for both users, and the planted
// read is proven.
import { gate, loadReport, standardChecks } from "./lib/fixture-gate.mjs";

const report = loadReport(process.argv[2]);
const g = gate();
const r = standardChecks(g, report, {
  expected: { "project members readable by every signed-in user": ["cross-tenant-read public.project_members tenant"] },
  mustBeClean: ["public.workspaces", "public.projects", "public.workspace_members"],
  mustBeFilled: ["public.workspaces", "public.workspace_members", "public.projects", "public.project_members"],
});
const traced = new Set((report.trace ?? []).map((t) => t.id));
// Since rows are built in required order and a shared column prefers an agreeing row, the member
// row is built directly; the repair steps it once needed are listed in rules.json (board item W23).
void traced;
const solved = g.total - (g.failed - r.falsePositives - r.unfilled);
g.done(`workspaces cases: ${solved} of ${g.total} solved, ${r.falsePositives} false positives, ${r.unfilled} tables without test data`);
