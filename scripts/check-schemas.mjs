// Gate for fixtures/supabase-schemas (another schema listed before public in [api] schemas).
// usage: node scripts/check-schemas.mjs <scan report>
import { gate, loadReport, provenOf, reportContext } from "./lib/fixture-gate.mjs";

const scan = loadReport(process.argv[2]);
const g = gate();
const proven = provenOf(scan);
const has = (kind, target) => proven.some((f) => f.kind === kind && f.target === target);
g.check(has("cross-tenant-read", "public.boards"), "S1 a public table is reached although another schema comes first", proven.map((f) => `${f.kind} ${f.target}`).join(", ") || "nothing proven");
g.check(has("rpc-leak", "public.board_titles"), "S2 a public function is reached although another schema comes first");
const unserved = (scan.coverage ?? []).filter((c) => c.relation.startsWith("public.") && c.reached === 0 && c.unreachable > 0).map((c) => c.relation);
g.check(!unserved.length, "S3 no public object counted as not served", unserved.join(", "));
const curls = proven.map((f) => f.evidence?.curl ?? "").filter(Boolean);
g.check(curls.length > 0 && curls.every((c) => /Accept-Profile: public/.test(c)), "S4 the evidence curl names the schema", curls.find((c) => !/Accept-Profile: public/.test(c))?.slice(0, 160) ?? "");
reportContext(g, scan);
g.done(`schemas cases: ${g.total - g.failed} of ${g.total} solved`);
