// Regression gate for tenantbleed itself: the planted bugs in fixtures/supabase-vuln must be
// proven, and the correctly isolated tables must produce zero proven findings.
// Strict: unlike the other planted apps, any proven finding not listed here fails too.
import { gate, keyOf, loadReport, provenOf, reportContext, sideOf as side } from "./lib/fixture-gate.mjs";

const report = loadReport(process.argv[2]);
const proven = provenOf(report);
const got = new Set(proven.map(keyOf));

const expected = [
  "anon-read public.invoices anon",
  "anon-read public.project_overview anon",
  "cross-tenant-read public.invoices tenant",
  "cross-tenant-read public.projects tenant",
  "view-leak public.project_overview tenant",
  "rpc-leak public.get_org_documents anon",
  "rpc-leak public.get_org_documents tenant",
  "cross-tenant-update public.invoices anon",
  "cross-tenant-update public.invoices tenant",
  "cross-tenant-insert public.invoices anon",
  "cross-tenant-insert public.invoices tenant",
  "cross-tenant-delete public.invoices anon",
  "cross-tenant-delete public.invoices tenant",
  "cross-tenant-reparent public.invoices tenant",
  "metadata-escalation public.org_settings tenant",
  // Found by the impersonation probe, not planted on purpose: documents_insert checks the org but
  // never that owner_id is the caller, so A can create documents "owned" by B.
  "impersonation-insert public.documents tenant",
  // Function that writes: renames any document by id without checking the caller.
  "rpc-write public.rename_document anon",
  "rpc-write public.rename_document tenant",
  // Storage: attachments only checks the bucket on read and delete.
  "cross-tenant-read bucket:attachments tenant",
  "cross-tenant-delete bucket:attachments tenant",
];
const mustBeClean = ["public.notes", "public.orgs", "public.memberships", "public.products", "public.documents", "public.archive_document", "bucket:receipts", "bucket:avatars"];

const missing = expected.filter((e) => !got.has(e));
const unexpected = [...got].filter((g) => !expected.includes(g));
const falsePositives = proven.filter((f) => mustBeClean.includes(f.target) && !expected.includes(`${f.kind} ${f.target} ${side(f)}`));
const latent = report.findings.some((f) => f.target === "public.documents" && f.title.includes("(latent)"));

// Linter triage: splinter must have run, and the warnings on planted bugs must be labeled proven.
const t = report.triage;
const triageOk = !t || (t.ran && ["public.invoices", "public.project_overview"].every((x) => t.rows.some((r) => r.target === x && r.verdict === "proven")));
if (t) console.log(`triage: ran ${t.ran}, ${t.rows.length} access warning(s), ${t.rows.filter((r) => r.verdict === "proven").length} proven${triageOk ? "" : "  TRIAGE CHECK FAILED"}`);

// Customer-report fields: shared checks, then what this app's planted bugs must carry.
const ctx = gate();
reportContext(ctx, report);
const find = (kind, target, actor) => proven.find((f) => f.kind === kind && f.target === target && side(f) === actor);
ctx.check(find("anon-read", "public.invoices", "anon")?.data?.classes.includes("financial"), "the open invoices are labelled financial data");
ctx.check(find("metadata-escalation", "public.org_settings", "tenant")?.location?.some((l) => l.what.startsWith('policy "org_settings_select"')), "the metadata finding points at the policy that trusts it");
ctx.check(/migrations\/.*\.sql$/.test(find("rpc-leak", "public.get_org_documents", "tenant")?.location?.[0]?.file ?? ""), "the leaking function points at its migration");
for (const l of ctx.lines()) if (l.startsWith("FAIL")) console.log(l);
console.log(`expected ${expected.length}, proven ${got.size}, missing ${missing.length}, unexpected ${unexpected.length}, false positives ${falsePositives.length}, documents latent: ${latent}`);
missing.forEach((m) => console.log(`  MISSING     ${m}`));
unexpected.forEach((u) => console.log(`  UNEXPECTED  ${u}`));
falsePositives.forEach((f) => console.log(`  FALSE POS   ${f.kind} ${f.target}`));
process.exit(ctx.failed || missing.length || unexpected.length || falsePositives.length || !latent || !triageOk ? 1 : 0);
