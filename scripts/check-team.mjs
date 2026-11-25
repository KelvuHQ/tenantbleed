// Gate for fixtures/supabase-team (a single-workspace intranet).
// usage: node scripts/check-team.mjs <scan report> <the same facts judged with "tenancy": "single">
import { gate, loadReport, provenOf, reportContext, sideOf } from "./lib/fixture-gate.mjs";

const scan = loadReport(process.argv[2]);
const single = loadReport(process.argv[3]);
const g = gate();

const staff = ["announcements", "documents", "contacts", "tasks", "wiki_pages", "meeting_notes"].map((t) => `public.${t}`);
const read = new Set(provenOf(scan).filter((f) => f.kind === "cross-tenant-read").map((f) => f.target));
g.check(staff.every((t) => read.has(t)), "staff tables are readable by every signed-in user", `not proven: ${staff.filter((t) => !read.has(t)).join(", ")}`);
g.check(provenOf(scan).some((f) => f.target === "public.meeting_notes" && f.kind === "anon-read"), "meeting notes are readable by visitors");
g.check((scan.notes ?? []).some((n) => /^Signup refused the test users/.test(n)), "signup refused: the test users were created directly");
g.check((scan.notes ?? []).some((n) => /^Heads-up: .* readable by every signed-in user/.test(n)), "heads-up suggests tenancy single");

const notLow = provenOf(single).filter((f) => sideOf(f) === "tenant" && f.severity !== "low");
g.check(!notLow.length, "with tenancy single, user-to-user findings are low", notLow.map((f) => `${f.target} ${f.severity}`).join(", "));
const anon = provenOf(single).filter((f) => sideOf(f) === "anon");
g.check(anon.length > 0 && anon.every((f) => f.severity !== "low"), "with tenancy single, what a visitor can do keeps its severity", anon.map((f) => `${f.target} ${f.severity}`).join(", ") || "no visitor finding");

reportContext(g, scan);
g.done(`team cases: ${g.total - g.failed} of ${g.total} solved`);
