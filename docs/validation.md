# How we validate tenantbleed

A security tool is only useful if its findings are true and its silences are honest. This page describes how tenantbleed is tested, the evidence so far, how it compares with other tools, and what it still cannot do. Numbers are from the full run of 2026-11-20 (build 09843f0) and are refreshed with every full run.

- [Three layers of testing](#three-layers-of-testing)
- [Layer 1: the planted test app](#layer-1-the-planted-test-app)
- [Layer 2: the field-test corpus](#layer-2-the-field-test-corpus)
- [Layer 3: regression on every rule change](#layer-3-regression-on-every-rule-change)
- [How findings are verified by hand](#how-findings-are-verified-by-hand)
- [Results so far](#results-so-far)
- [Comparison with other tools](#comparison-with-other-tools)
- [False-positive patterns found and fixed](#false-positive-patterns-found-and-fixed)
- [Known gaps](#known-gaps)
- [Safety rules for testing other people's code](#safety-rules-for-testing-other-peoples-code)

## Three layers of testing

1. **Planted test apps** (`fixtures/`, five apps) with known bugs, known correct objects and every hard shape the field test has shown, checked locally with `scripts/test-fixtures.sh` after every change (about a minute). There is no hosted CI: the gate runs on the developer's machine.
2. **A field-test corpus** of real open-source Supabase apps, scanned locally and verified by hand against their SQL.
3. **Regression**: every gap found on a real app becomes a planted case first; the full corpus run is the final confirmation, compared app by app with the previous run.

## Layer 1: the planted test app

`fixtures/supabase-vuln` is a small multi-tenant app (organizations, memberships, projects, invoices, documents, notes, settings, products, storage buckets). CI starts it, scans it, and `scripts/check-fixture.mjs` requires:

- **All 20 planted bugs proven**, each with the right kind and actor:

| Planted bug | Expected findings |
| --- | --- |
| `invoices` with RLS never enabled | anon and tenant read, update, insert, delete; tenant reparent |
| `projects` SELECT policy `true` | tenant read |
| `project_overview` view without `security_invoker` | anon read, tenant view leak |
| `get_org_documents(o)` SECURITY DEFINER, no membership check | anon and tenant function leak |
| `org_settings` policy trusts `user_metadata` | tenant metadata escalation |
| `documents` insert policy never checks `owner_id` (found by the tool, not planted on purpose) | tenant impersonation |
| `rename_document(d, title)` SECURITY DEFINER, no caller check | anon and tenant function write |
| `attachments` bucket: read and delete check only the bucket | tenant storage read and delete |

- **No false positives** on the correct objects: `notes`, `orgs`, `memberships`, `products`, `documents` (beyond the planted issue), `archive_document()` (a definer function that checks the caller), the `receipts` bucket (per-folder policies) and the `avatars` bucket (public by design).
- **Latent detection**: the `documents` UPDATE policy `using (true)` is masked by its SELECT policy and must be reported as latent, not as a proven bug.

Current result: 20 of 20 proven, 0 false positives, latent detected.

The other four planted apps hold every shape a real app showed the scan getting wrong, as a copy with neutral names:

| Planted app | Cases | What it holds |
| --- | --- | --- |
| `supabase-hard` | 70 | hard test data (CHECK rules, triggers that refuse rows, tables that link both ways, partitions, hidden schemas) and functions that are hard to call (row state, secrets, ids from one row, maintenance by age) |
| `supabase-team` | 10 | organization tenancy, plus a replay judged as a single-workspace app |
| `supabase-workspaces` | 7 | workspaces with roles and invitations |
| `supabase-regress` | 16 | false alarms fixed once, which must stay fixed |

`scripts/check-rules.mjs` then requires every rule and test-data strategy listed in `scripts/rules.json` (195 today) to be produced by at least one planted case, so no code path is left without a test. Current result: all five apps pass, 195 of 195 rules exercised.

## Layer 2: the field-test corpus

Real open-source apps with `supabase/config.toml` and `supabase/migrations/`, chosen for variety: per-user apps (notes, AI chat, journals, finance), multi-tenant SaaS (organizations, workspaces, teams), marketplaces, course platforms, chat and community apps, booking, and apps generated with AI builders.

| | Count |
| --- | --- |
| Projects in the corpus | 39 (including one multi-tenant starter kit in two configurations) |
| Started and scanned | 31 |
| Could not start from their own migrations | 8 (duplicate migration versions, tables created outside migrations, backfills that break foreign keys) |

### Extended corpus (2026-11-18)

130 more open-source Supabase apps, found by searching public GitHub for repos with `supabase/migrations/`, scanned the same way. Totals across all 169 apps, from the full run of 2026-11-20 (build 09843f0):

| | Count |
| --- | --- |
| Projects in the corpus | 169 (39 regression plus 130 extended) |
| Started and scanned | 119 |
| Could not start from their own migrations | 50 |
| Scanned apps with at least one proven isolation failure | 85 of 119 |
| Proven findings | 1,660: 124 critical, 282 high, 357 medium, 897 low |

Supabase's own linter (splinter, the Security Advisor) on the same 119 apps, every data-access warning matched to what the scan showed for that table or function:

| | Warnings | Share |
| --- | --- | --- |
| Data-access warnings raised | 6,638 | |
| Proven exploitable by tenantbleed | 402 | 6% |
| Shown not to let anyone reach other users' data in the test: attacked or called with no leak (3,876), locked by RLS with no policies (577), not callable by the API (1,340: trigger functions, read-only yes/no helpers, unnamed arguments), shared by design (40), not served by the API (13), part of an extension (9) | 5,855 | 88% |
| Needs someone who knows the app to decide: tenantbleed's own schema check also flags it (44), or not tested (337) | 381 | 6% |

The reverse: of the 763 proven findings at critical, high or medium, 430 (more than half) are on a table or function the linter raised no warning for.

The 337 "not tested" warnings come from 171 functions where even the owner's own call changed nothing, so the scan could not tell a caller check from test values that missed. The largest groups: a secret-like text argument (49 functions: invite codes, tokens), an id plus a value the scan cannot guess (42), and writes that only act on rows in a given state (25, handled by the row-state strategy added after this run).

How the grey zone shrank (same 6,638 warnings): on 2026-11-19 flagged was 1,848 and not tested 43, with 153 proven; on 2026-11-20 morning 622, 22 and 261; on the run above 44 flagged and 402 proven. Not tested rose because the scan now calls functions it used to skip and says when the call proved nothing, instead of counting the call as tested. Each fix started as a case in a planted app.

The extended corpus drove the precision rules added on 2026-11-18 (app-wide role values, staff-list tables, declared-public tables with sensitive columns, backend-only tables, public OR branches). Its findings are proven by the tool, request by request; they have not all been verified by hand yet the way the 39-app set was.

Every scan runs on a throwaway local stack, one project at a time, with its outbound URLs neutralised (see [safety rules](#safety-rules-for-testing-other-peoples-code)). Reports are kept outside this repo.

## Layer 3: regression on every rule change

For each change to the engine or a rule:

1. Plant the shape first and see it fail on the old build; then fix it generically and run `scripts/test-fixtures.sh` (all five apps pass, every rule exercised).
2. When a batch of fixes is in, run the whole corpus on the new build with internal tooling kept outside this repo.
3. Compare each project with its previous result: severity counts, coverage, and the set of proven findings.
4. Any finding that disappeared or dropped is explained before shipping. Two regressions were caught this way: a public-filter rule that briefly hid real write bugs, and a profile rule that briefly lowered a leak of employee emails. Both were fixed and re-verified before release.

## How findings are verified by hand

For each new finding at medium or above in the corpus:

- read the policies, grants and function bodies involved in the app's migrations;
- confirm the attack is possible for a real user, not only for the test data;
- classify it as **real**, **real but by design** (for example a public storefront), or **tool error**;
- for a tool error, fix the rule generically and re-run, never patch the single case.

## Results so far

Confirmed real bugs in 12 of the 31 scanned apps, including:

| App | Issue | Severity |
| --- | --- | --- |
| App A | Without logging in, anyone can read any user's personal records, lists, stored data and analyses through unchecked functions; a "service role" policy without `TO service_role` opens tables to everyone. | critical |
| App B | "Public read" policies that are `FOR ALL USING (true)` with full grants to anon: anyone can rewrite or delete content and payment records; webhook functions callable without login. | critical |
| App D | A user directory with emails readable without login, because a later migration recreated a locked-down function and lost its lock. | critical |
| App C | Without login, a function returns records from every tenant; anyone can join any tenant by id; invite links readable by anyone. | critical |
| App E | Without login, anyone can advance any user's counter. | critical |
| App F | Any tenant's admin can edit every profile in every tenant. | high |
| App G | An invitation can be re-pointed at someone else's group. | high |
| App H | Anyone can post comments and fake activity into other users' tenants. | high |
| App J, App K, App L | Records can be created in another user's name. | medium |
| App I | User names and avatars readable without login (granted only to signed-in users, but Supabase's default grants also opened it to anon). | medium |

The affected projects are not named until their maintainers have been told privately.

Coverage: most scanned apps are fully tested (for example a 46-table CRM: 25 of 25 reachable tables and 3 of 3 buckets). The remaining gaps are listed under [known gaps](#known-gaps).

## Comparison with other tools

### Head-to-head on known issues (planted app plus two real apps)

| Tool | Proven | Flagged only | Missed |
| --- | --- | --- | --- |
| tenantbleed | 16 | 2 | 0 |
| Supabase linter (splinter) | 0 | 16 | 2 |
| supabase-rls-audit-kit | 0 | 15 | 3 |
| supabase-rls-ab-test | 0 | 2 | 16 |
| Autoswagger | 0 | 3 (not marked as issues) | 15 |
| OWASP ZAP | 0 | 0 | 18 |
| Akto | 0 | about 2 at best | 16 |

This was measured on an earlier version of tenantbleed; the test app has grown from 18 to 20 planted issues since.

### Linters on the 31-app corpus

Splinter and supabase-rls-audit-kit were run on the same local stacks and every warning was matched to tenantbleed's result for the same table or function.

- **Warnings that name a specific misconfiguration** (RLS disabled, `using (true)` policies, definer views, `user_metadata`, dynamic SQL, storage policies): 57. tenantbleed proved 21, flagged 3 itself, 12 are on tables shared by design, 1 is on a table it could not test, and 20 it tested and found nothing (19 are "RLS on with no policies", which locks the table).
- **The reverse**: tenantbleed proved 106 bugs at medium or above on tables and functions where neither linter names a specific problem. These are logic bugs: injection into another workspace, joining any workspace, impersonation, cross-organization admin edits.
- **Inventory warnings** ("anon can execute this SECURITY DEFINER function", default grants): thousands, one per function or table. Of splinter's 241 "anon can execute a SECURITY DEFINER function" warnings, tenantbleed proved 8, called 112 and found no leak, and did not call 121: 77 trigger functions (the API cannot call them), 19 read-only yes/no helpers (skipped by design), and 25 functions that change or return data.
- **Linter-only catches** among those 25, now fixed in tenantbleed: a search function in one app that leaks any user's stored records without login, and a function in another app callable without login. Both were missed because tenantbleed could not build their arguments (an embedding vector, an order code, JSON); argument building was extended and both are now proven.
- **What stays the linters' job**: abuse with no data effect (for example a function that sends push notifications to anyone, found in one app), and functions whose inputs cannot be constructed.

Conclusion: use the linter, and use tenantbleed to prove which warnings are real, to find the logic bugs no lint pattern matches, and to know which warnings are latent.

## False-positive patterns found and fixed

Each was a tool error found during hand verification, fixed generically, and re-checked on the whole corpus:

| Pattern | Fix |
| --- | --- |
| Functions that echo their input counted as leaks | Ignore values the attacker sent. |
| A trigger rewrote the owner, so a refused impersonation looked accepted | Read the stored row back. |
| Rows pointing at another tenant but invisible to them reported high | Check visibility as the victim; low if invisible. |
| Admins adding people to their own team called impersonation | Membership tables reported low with consent wording. |
| Single-workspace intranet produced 161 coworker findings | `tenancy: "single"` and an automatic heads-up. |
| Public org branding treated as tenant data | Singleton tables are configuration. |
| A block between two users attributed to the blocked user | Rows naming two test users belong to neither. |
| Buying a course raised the seller's enrollment count | Counter-only changes are low. |
| Active-campaign banner reported as a leak | Caller-independent read filters are lowered, for reads only. |
| Public profile fields (chat partner names) reported high | Profile-only leaks are lowered, unless personal data is present. |
| A marketplace chat readable by both buyer and seller reported as a leak | Person columns are also inferred from `auth.uid() IN (owner_id, member_id)`; rows naming both users stay unowned even when a read receipt points at them. |
| The attacker's own notification mentioning the victim's listing reported as a leak | The attacker's own rows are never evidence. |

## Fix prototype (verified fix PRs)

`tenantbleed fix` writes one migration per proven issue from deterministic templates (no AI). `scripts/verify-fixes.mjs` applies each one to a database rebuilt from migrations and re-scans. It also re-runs an access check as four kinds of user on tenant A's data:

- **owner:** each test user reads, edits, creates and deletes their own rows (50 operations on the test app);
- **coworker:** a new user added to A's workspace through the app's own membership tables, found from the schema and policies;
- **admin:** a new user made admin the way the app's policies expect (a role column, an `app_metadata` role or an admins table), when the app has one;
- **stranger:** tenant B.

A fix is accepted only if the targeted attacks fail, no new issue appears, and every owner, coworker and admin operation that worked before still works. Access that only worked because it was open to everyone (the stranger had it too) is listed for review instead of failing the fix.

Each run writes `fix-report.md` with four sections:

- **fixed and verified**;
- **rejected**;
- **needs a human:** every proven issue with no automatic fix, and why;
- **review**.

Operations that cannot be compared are listed as "could not recheck" rather than counted as broken. That happens when the database rejects the test row itself, or when the table's policy depends on the clock.

Result on the planted test app:

| Fix | Template | Verdict |
| --- | --- | --- |
| `invoices`: RLS on, policies inherit the organization rule through the parent | enable RLS with owner-scoped policies | pass |
| `project_overview` view | `security_invoker = true` | pass |
| `org_settings` trusting `user_metadata` | restrictive policy scoped through the parent | pass |
| `documents` impersonation | restrictive insert: owner must be the caller | pass |
| `get_org_documents()` | run as the caller, revoke from anon | pass |
| `rename_document()` | run as the caller, revoke from anon | pass |
| `attachments` bucket | restrictive policies: own folder only | pass |

7 of 7 fixes pass individually and together; 19 of 20 issues closed. The 20th (`projects` readable by every signed-in user through `using (true)`) is skipped on purpose: it may be public by design and needs a product decision.

**Negative control.** A deliberately naive fix (`enable row level security` on `invoices` with no policies) stops every attack, so a check that only re-runs the attacks would accept it, but it locks both users out of their own invoices (6 owner operations broken). The verifier rejects it. This is the point of the rightful-owner check: closing the hole is not enough, the app must still work.

**On real apps** (local copies, never the projects' own environments):

| App | Fixes verified | Proven issues closed (medium+) | Left for a human |
| --- | --- | --- | --- |
| Planted test app | 7 of 7 | 19 of 20 | 1 (open read on `projects`: product decision) |
| App A | 8 of 8 | 21 of 21 | 0 |
| App B | 9 of 9 | 41 of 85 | 44 |

Every fix passed alone and with all the others applied together. On App B, a self-escalation path let a user become an admin, and a coworker was added through related records. No fix broke owner, coworker or admin access. Several fixes closed "anyone signed in can edit any row" access that the coworker and admin had also been using; these are listed for review. The 44 issues left have reasons in the report:

- 24 need a product decision (some tables readable by everyone, which may be intended);
- 18 are inserts under public records, where who may add rows is an app rule;
- 10 have no owner column or protected parent to scope by.

Three sources of flaky checks were found on real apps and fixed generically in the verifier:

- which tenant's own row is visible can vary between runs, so owners are counted per table and operation;
- strict CHECK constraints can reject the test row;
- clock-based policies change which rows are visible.

**Backend-only policies.** One app had policies named for the service role (`"Service role can manage ..."`, `using (true)`) but missing `to service_role`, so they applied to everyone. The `policy-to-service-role` template limits such a policy to `service_role`. The first version only did that. The verifier rejected it, because the app relied on those policies for users' own inserts and updates. The template now also adds owner-only policies for the commands the open policy covered, and passes. This is the same check as the negative control, on a real app.

## Known gaps

- **Business rules enforced by app triggers**, such as "live sessions only for live courses", "no cycles in a family tree", or rules raised in other languages. The AI scenario builder on the roadmap targets these.
- **Checks that call app functions.**
- **Functions behind a secret** (invite codes, share tokens) where the scan has no valid value, and functions whose arguments it cannot guess (an id plus a free value).
- **Sharing workflows**: rows that only exist after one user shares something with another.
- **Data from outside the database**: rows created by webhooks, payments or email.
- **Abuse without a data effect**: notifications, emails, rate limits.
- **Schemas not exposed in `config.toml`** but exposed in the hosted dashboard: reported as a note, testable with `--schemas`.

## Safety rules for testing other people's code

The corpus is scanned under strict rules:

- Only public repositories, cloned shallowly; nothing is run against anyone's hosted project or GitHub account.
- One local stack at a time on shifted ports, stopped and destroyed after each scan.
- Before starting, every `*.supabase.co` URL in migrations and config, and every URL written inline in an outbound HTTP call from the database, is pointed at a dead local port. Edge functions never run.
- When a seed file or auth hook needs a secret only the author has, the lab copy disables seeding or the hook; the app's own code is not changed.
- Confirmed bugs are disclosed privately to maintainers before any public mention, and apps are described by type until then.
