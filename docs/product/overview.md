# tenantbleed: product description

## What it is

tenantbleed proves, with real accounts and real requests, whether one user of a Supabase app can read, change or delete another user's data. It is a free, open-source, fully local tool: a command-line scanner and a local web UI (loopback `127.0.0.1` only). It runs against a throwaway database built from the repo's own migrations (it reads only the supabase/ folder, never the app code) on your own machine, and reports the result. No accounts, no sign-in, no network calls off the box.

**Pitch:** Supabase's linter tells you what might be wrong. tenantbleed proves what is, shows the exact request that does it, and hands you the fix.

It never touches production. The scan and the verdict both run locally, in-process. Every proof is deterministic code (no AI in the verdict) and comes with a `curl` command that reproduces it.

## The problem

In a Supabase app the browser talks to the database directly, so row level security (RLS) policies are the only thing between one customer's data and the next. One missing condition is a data breach, and nothing in normal testing catches it: the app works perfectly for every user who only looks at their own data.

The failures are rarely "RLS is off". They are logic mistakes that look correct on review:

- an insert policy that checks you are the author, but not that you belong to the workspace you are writing into;
- a SECURITY DEFINER function that skips RLS and never checks the caller;
- a policy written `using (true)` without `to authenticated`, so it is open to the whole internet;
- a function that was locked down in one migration, then dropped and recreated in a later one that forgot the lock;
- a storage bucket whose read and delete policies check only the bucket name.

AI app builders (Lovable, Bolt, Cursor, v0) generate exactly this code at scale, for builders who cannot read a policy. Every one of the examples above was found in real open-source apps during our field test.

## How it works

Every finding is a request that worked, confirmed in the database:

1. **Build a throwaway copy:** a local Supabase from the repo's own migrations.
2. **Create two real users** and data owned by each, tagged with unique markers.
3. **Attack as A, B and anon:** the same HTTP requests a browser could send.
4. **Confirm in the database:** markers leaked, rows really changed or deleted.
5. **Undo every side effect:** rows and files restored, functions rolled back.
6. **Report locally:** a plain sentence, the proof, a `curl` and an AI fix prompt, in the terminal and the local web UI.

Ownership is inferred from the schema (foreign keys to users, membership tables, chains of foreign keys), so no configuration is needed. A finding exists only when an attack request actually worked; status codes are never trusted on their own. There is no AI in the verdict: the same app gives the same result every run.

## What it tests

Ten probes, each run as an anonymous visitor and as each signed-in test user against the other's data.

| Probe | What the attacker tries | How success is confirmed |
| --- | --- | --- |
| Reads | Read every exposed table and view | The other user's unique markers appear in the response |
| Updates and deletes | Change or delete the other user's row by key | Row compared in the database before and after (the API answers 204 either way), then restored |
| Inserts | Create rows inside the other user's records | The victim can see the planted row; if not, reported low as a dangling reference |
| Reparenting | Move your own row into the other user's account | Foreign key checked in the database |
| Impersonation | Create rows that name the other user as owner or author | Stored row read back, so triggers that rewrite the owner do not count |
| Functions | Call every exposed function with the other user's ids | Read-only ones over the API; writing ones in a rolled-back transaction, with the victim's rows diffed |
| user_metadata | Edit your own profile metadata to the victim's ids, as any browser can | Victim's data appears on the next read |
| Storage | Download, list, overwrite, delete and upload into the other user's files | Checked with the service role, files restored |
| GraphQL | Read every table through /graphql/v1 | Same marker check; also catches public hidden from REST but served by GraphQL |
| Static checks | RLS off, open policies, definer views and functions | Listed separately; an open policy that could not be exploited is marked latent |

## Who it is for and how they use it

**Who:** small teams and solo builders shipping multi-tenant SaaS on Supabase, especially apps generated with AI tools; agencies that build Supabase apps for clients; and reviewers who need evidence, not a hunch.

**Setup:** one command. tenantbleed starts a local Supabase from the repo's migrations, runs the scan in about 30 seconds, and prints the result in the terminal. The local web UI opens the same report at a loopback URL with a per-session token (`http://127.0.0.1:7171/?token=...`).

**The report is written for people who ship with AI:**

- the headline never says clean when coverage is incomplete;
- **Fix these first** lists the top five issues in one plain sentence each ("Any logged-in user can delete other users' files in the attachments storage bucket");
- every finding carries a prompt to paste into Lovable, Bolt, Cursor or Claude that asks for the fixing migration;
- the technical proof, the request and a `curl` to reproduce sit underneath for developers;
- a coverage section lists every table it could not test, and why.

**Configuration** is optional: a `tenantbleed.json` can mark tables that are shared by design and declare a single-workspace app (`"tenancy": "single"`), where coworkers sharing data is the point.

## Comparison with alternatives

On 18 known issues across a planted test app and two real apps, tenantbleed proved 16 and flagged the other 2. No other tool proved any. The closest, Supabase's own linter, flagged 16 but cannot tell an exploitable bug from a harmless pattern, and misses logic bugs that match no pattern. All tools were run locally, side by side.

| Tool | Type | Proved | Flagged only | Missed | Noise and setup |
| --- | --- | --- | --- | --- | --- |
| **tenantbleed** | Dynamic, ownership-aware, two real accounts | 16 | 2 | 0 | 0 false positives on the test app; zero setup, about 30 s |
| Supabase linter (splinter) | Static lints, behind the Security Advisor | 0 | 16 | 2 | One lint covered 9 separate problems; deliberately skips `SELECT using (true)` |
| supabase-rls-audit-kit | Static | 0 | 15 | 3 | About 76 of 82 findings were noise |
| supabase-rls-ab-test | Two-user read test | 0 | 2 | 16 | Owner-column model only; no writes, inserts or functions |
| Autoswagger (Intruder) | Unauthenticated API discovery | 0 | 3 (not marked as issues) | 15 | Needed a proxy to send auth headers |
| OWASP ZAP | Generic API scanner | 0 | 0 | 18 | Reported a false "SQL injection" after creating hundreds of real users |
| Akto | BOLA templates from recorded traffic | 0 | about 2 at best | 16 | Heavy multi-service install; needs real traffic |

Commercial DAST tools (StackHawk, Escape, Bright, Aikido, Snyk) test generic APIs and swap IDs between sessions. None of them builds the data model of a Supabase app, creates data owned by each tenant, or checks the database to confirm a write landed.

**What only tenantbleed does:** proof instead of suspicion; logic bugs no linter pattern matches; latent versus live (a bad policy masked by another is reported low, not high); writes confirmed in the database, side effects rolled back; and a report a non-security person can act on.

## Field results

tenantbleed was run on 39 open-source Supabase apps. 31 could be built from their own migrations; the other 8 fail on their own migrations (duplicate versions, missing tables), so nobody can build them from a clean checkout. Each app ran locally, in about 30 to 50 seconds; nothing ran against anyone's hosted project. Every medium-or-worse finding was checked by hand against the app's SQL.

**Real, exploitable isolation bugs in 12 of the 31 apps**, with no known false positive at medium or above after triage:

| App | Worst confirmed issue | Severity |
| --- | --- | --- |
| App A | Personal records readable without login, and editable by any other user | critical |
| App B | Anyone can rewrite or delete content and payment records (policies that allow every row, an open webhook table) | critical |
| App C | A function callable without login returns records from every tenant; anyone can join any tenant by id | critical |
| App D | Without login: a user directory (emails, admin flags), an activity feed, and stored secrets' names and owners (not values), through policies missing `to authenticated` and a function that lost its lock | critical |
| App E | Anyone, without login, can advance any user's counter through an unchecked function | critical |
| App F | Any tenant's admin can edit every profile, in every tenant | high |
| App G | Invitations can be redirected into someone else's group | high |
| App H | Any user can post comments and fake activity into any other tenant | high |
| App I | User profiles readable without login through a public function | medium |
| App J | Records can be created in another user's name | medium |
| App K | Records can be created in another user's name | medium |
| App L | Accounts can be created naming another user as owner (when its schema is exposed) | medium |

**3 apps had medium findings that are correct but intended**, and the report says so in its own words: one app where every signed-in user reads every record, another app whose catalog is readable by everyone, and a third app built around one shared tenant (the report's single-workspace heads-up fires on it). These are the cases the `"tenancy": "single"` setting and the "public by design" wording exist for.

**The other 16 were clean or had only low findings:** 11 clean and 5 with low items such as cross-tenant references the victim never sees.

**Coverage.** tenantbleed filled 512 of the 537 tables in the 31 apps (95%) with real test data; 23 of the 29 apps that have tables were covered completely, including a 67-table CRM and an 80-table intranet. Where a table could not be filled, the report names it and gives the database's own error, instead of calling it safe.

**Against the linters, on the same 31 apps.** Supabase's linter (splinter) and an open-source RLS audit kit produced 2,498 warnings about who can reach data. They proved none of them; neither tool sends a request.

- Of the 57 warnings that name a specific misconfiguration (RLS off, `using (true)`, definer views, `user_metadata`, storage policies): tenantbleed proved 21, flagged 3 itself, 12 are on tables shared by design, 1 is on a table it could not fill, and 20 it tested and found nothing (19 of those are "RLS on with no policies", which locks the table).
- The other warnings are inventory: one per privileged function or default grant. tenantbleed called those functions and tried those tables; 1,850 came back not exploitable.
- In the other direction, tenantbleed proved 106 bugs at medium or above where neither linter names a specific problem. These are the logic bugs: injection into another workspace, joining any workspace, impersonation, cross-organization admin edits.

**Precision work during the field test.** First runs over-reported. Each pattern was fixed in the tool, not filtered by hand, and re-checked on all 39 apps:

- functions that echo their input were counted as leaks;
- a trigger that rewrites the owner made a blocked impersonation look accepted;
- rows that point at another tenant but stay invisible to them were reported high (now low);
- adding a user to your own team was called impersonation (now low with clearer wording);
- rows naming two people (blocks, direct messages) were treated as one person's data;
- counters moved by a normal purchase were reported as tampering;
- deliberately public read filters and other users' public profile fields were reported as leaks;
- a single-workspace intranet produced 161 coworker-to-coworker findings; the report now spots this pattern and suggests `"tenancy": "single"`.

**Next step:** disclose the confirmed bugs privately to each project's maintainers before any public mention. Drafts are being prepared; nothing is sent without review.

## Limits today

**Limits**

- Supabase only. Tenancy is inferred from foreign keys; apps that keep the tenant in a JWT claim or a session variable are only partly understood.
- Some tables cannot be filled with test data (multi-column CHECKs, rows that only migrations create, foreign keys into storage objects). The report lists them instead of claiming they are safe.
- Edge functions, Realtime channels and anything outside the database API are not tested.
- The test users are created directly when a signup trigger refuses them, and sessions are signed locally when email login is off; both are noted in the report.

**Roadmap:** see [roadmap.md](roadmap.md) (what is done, then more coverage, adoption and docs).

### Verified fix PRs

The difference from every "AI fix" button: the fix is proven by the same engine that proved the bug.

1. **Write the fix.** Common patterns get a deterministic template: enable RLS, add `TO service_role` to a policy meant for the backend, revoke `EXECUTE` from `anon`, add a `WITH CHECK` that repeats the tenant condition, recreate a view with `security_invoker`, add a caller check to a `SECURITY DEFINER` function, scope a storage policy to the owner's folder. Issues no template can close safely go to "needs a human" with the reason and an AI prompt.
2. **Prove it in two directions.** Apply the migration to a fresh stack and re-run the scan: the original attack must fail, and no new finding may appear. Then a **functionality check**: the owner, a coworker added through the app's own membership tables, and an admin (when the app has that role) must still be able to read, create, update and delete what they could before the fix. A fix that locks out a rightful user is rejected and reported as "needs a human".
3. **Open the PR.** One migration per issue (`supabase/migrations/<timestamp>_tenantbleed_fix_<id>.sql`), with the plain explanation, the request that worked before, proof that it fails after, and the functionality check results. The developer reviews and merges; nothing is applied to production by tenantbleed.

What it will not fix automatically: data that may be public by design (open read policies, shared tables, single-workspace apps), issues that need a product decision (who may see a member list), and abuse with no data effect. Those stay in the report with the AI prompt.

Prototype results on local copies of real apps: 24 of 24 generated fixes verified across the test app and two real apps, closing 81 of 126 proven issues without breaking owner, coworker or admin access. The other 45 are listed as "needs a human" with the reason. Details in [validation](../validation.md#fix-prototype-verified-fix-prs).

## What makes it different

tenantbleed is the proof layer on top of what Supabase already gives away. A linter tells you a policy exists; it cannot tell you the policy isolates. tenantbleed proves exploitability, catches logic bugs no pattern matches, and tells a non-expert what to fix.

- **Accuracy from real apps.** Every edge case the field test surfaced (signup triggers, echo functions, membership tables, regex CHECKs) is fixed once and stays fixed, so the tool does not re-report the false positives already removed.
- **Capability evidence.** Run side by side on 18 known issues across a planted test app and two real apps, tenantbleed proved 16 and flagged the other 2 where other tools proved none. That is proof the dynamic approach works, not a marketing claim.
- **Reproducible evidence.** Each proof carries the request, a `curl`, the fix SQL and an AI fix prompt, so a review has an artifact instead of a hunch.

A static linter proves a policy exists; only a real attack with two tenants proves the policy isolates. That gap is what tenantbleed fills.
