// Gate for fixtures/supabase-managed (spec 08c: an app that exposes a Supabase-managed schema).
// The app lists "auth" in [api] schemas and grants authenticated a read on auth.users. auth.users and
// the rest of the auth schema are Supabase's own tables: the builder (a privileged role) must never try
// to write to them, and the scan must still run the app's own tables. auth.users keeps RLS on with no
// policy, so the exposure leaks nothing; the scan must read-sweep it and correctly find it clean, not
// invent a finding.
// usage: node scripts/check-managed.mjs <scan report>
import { gate, loadReport, provenOf, reportContext } from "./lib/fixture-gate.mjs";

const scan = loadReport(process.argv[2]);
const g = gate();
const proven = provenOf(scan);
const cov = scan.coverage ?? [];
const MANAGED = /^(auth|storage|realtime|supabase_functions|vault|pgsodium|net|cron|pgmq)\./;

g.check(scan.complete === true, "M0 scan completed", `complete=${scan.complete}`);

// The app's own table was built and attacked as usual.
const notes = cov.find((c) => c.relation === "public.notes");
g.check(!!notes && notes.reached > 0 && notes.populated, "M1 the app's own table is built and attacked", JSON.stringify(notes));

// The builder never wrote into a managed schema: a build attempt leaves a `reason` (an insert that was
// rejected, or that worked). No managed-schema table may carry one.
const built = cov.filter((c) => MANAGED.test(c.relation) && c.kind === "table" && c.reason);
g.check(built.length === 0, "M2 the builder never wrote to a managed-schema table", built.map((c) => `${c.relation}: ${c.reason}`).join("; "));

// Only the one granted managed table (auth.users) is reached at all; the builder did not enumerate the
// whole auth schema as tenant tables.
const managedTables = cov.filter((c) => MANAGED.test(c.relation) && c.kind === "table");
g.check(managedTables.length <= 1 && managedTables.every((c) => c.relation === "auth.users"), "M3 only the exposed, granted managed table is reached", managedTables.map((c) => c.relation).join(", "));

// auth.users is actually read-swept (so an exposed, unprotected managed table would be caught), and found
// clean, because its own RLS still denies the read: no invented finding.
const authUsers = cov.find((c) => c.relation === "auth.users");
g.check(!!authUsers && authUsers.reached > 0, "M4 auth.users is read-swept, not skipped as shared", JSON.stringify(authUsers));
g.check(!proven.some((f) => MANAGED.test(f.target)), "M5 no finding invented on a managed table (RLS protects it)", proven.filter((f) => MANAGED.test(f.target)).map((f) => f.target).join(", "));

reportContext(g, scan);
g.done(`managed cases: ${g.total - g.failed} of ${g.total} solved`);
