# 11. Limits, known issues and roadmap

## What the scanner does not test today

| Area | Limit | Where |
| --- | --- | --- |
| Edge functions, Realtime, background workers | outside the database API; not started in scans | roadmap Phase 2 |
| App server code | logic outside SQL is not seen; findings are about the database API | by design |
| Tenancy from JWT claims or session variables | a tenant column scoped by a JWT claim (`auth.jwt() ->> 'org_id' = org_id`) is now read from the policy and reported as tenant-scoped but not attacked (the scan does not mint the claim), so it is no longer mislabelled "shared"; minting the claim to attack it, and reading session variables, are not done | `world.ts` `jwtClaimScope`; roadmap Phase 2 |
| Tables without a primary key | no test data, no write probes | `world.ts:68` |
| Functions with unnamed arguments | cannot be called through PostgREST; listed in notes | `probes.ts:898-909` |
| Non-volatile functions returning boolean or void | skipped as yes/no helpers | `probes.ts:895` |
| GraphQL | `public` only, and only with pg_graphql | `probes.ts:1819` |
| Public buckets | no download test | storage probe |
| Functions needing outside knowledge | values only the app's authors know (a payment code, an outside service) cannot be guessed; such functions are reported as not tested | owner control |
| Regex and CHECK shapes | regex groups and alternation; a simple `CASE x WHEN` | `world.ts:171`, `:1065` |
| Required columns of unsupported types | the table stays unpopulated with the reason | `world.ts:550` |

## Coverage gaps by root cause

On 2026-11-21 every case across the corpus where the scanner could not reach a conclusion was traced to a root cause. The table gives the generic causes, with no app names. The per-cause specs are in the private lab; each becomes a planted case with neutral names when it is built.

| # | Cause | Effect today | Fix in brief | Size |
| --- | --- | --- | --- | --- |
| 1 | A function's owner call changed nothing, but triage still labels it "tested" when a body rule or a static finding applies | many functions shown as tested that were never exercised | label them honestly, as "settled from the body" or "not tested: <reason>"; then settle those a call can | large |
| 2 | The user table is keyed by the auth id as **text**, with no foreign key | nothing has an owner, so every table is "shared" and none is attacked | treat `id::text = auth.uid()::text` as a person key | large |
| 3 | Schemas that are not exposed count as "reachable, not tested" | misleading coverage | count them as not exposed | small |
| 4 | An optional person column points at a profile table whose rows need a tenant first (a cycle) | the tenant row fails, and every child table with it | leave the column empty until the profile exists, then fill it | small |
| 5 | Requests without a schema header go to the first exposed schema, which may not be `public` | objects in `public` look unserved; curl evidence is wrong | always send the profile header | small |
| 6 | Value builder: `DEFAULT NULL` taken for a real default, JSON the app needs as an array, a parent key that breaks a domain rule, a CHECK casting to an enum, `xid8` and range types, a key to `auth.sessions` | tables without test data | one rule each | small |
| 7 | Table order: following an optional link places a child before the parent it needs | tables without test data | order by needed links only | small |
| 8 | Staff lists, partitions and Supabase's own tables are reported as "could not create test data" | noise in coverage | declare them | small |
| 9 | Tenancy without a foreign key: a tenant column scoped through a membership subquery, or a tenant id in the JWT | "shared" | read the scope from the policy | medium |
| 10 | A 404 raised inside a function body is read as "the API does not serve it" | functions skipped | tell the two 404s apart by error code | small |
| 11 | Two keys into one parent share the tenant column, or one column carries several foreign keys | tables without test data | pick parent rows that satisfy every key | medium |
| 12 | A trigger's side insert fails, and the rules-paused fallback does not cover it | tables without test data | extend the fallback | small |
| 13 | A function touches an object the API roles have no grant on: refused for everyone, yet "not tested" | wrong label | "not callable: no grant" | small |
| 14 | Two-person rows (chat, trade, block) are built between tenant A and tenant B | "shared" | build them with the bystander | medium |
| 15 | Tenant B's insert collides on a unique default, then B's failure overwrites A's success in coverage | a wrong gap | keep per-tenant results | small |
| 16 | Apps that never start: duplicate migration versions, writes to the auth or storage schemas, missing config | apps not scanned | lab repairs, else declare | small to medium |
| 17 | A read policy opens rows once a **parent** reaches a state (`published`), and test parents keep their default state | real leaks missed | put the victim's parent in the state the policy checks | small |
| 18 | A policy calls a helper whose body always returns true; and shared tables open to everyone get no line of their own | real leaks missed; silent reports | treat a constant-true helper as an open policy; declare open shared tables | small |
| 19 | An insert check allows "add yourself as admin" without tying the workspace to the caller; the insert probe never sends the privileged value, because columns with a default are skipped | **a critical self-escalation missed** | try the privileged value of role columns in cross-tenant inserts | small |

Causes 17 to 19 were found by checking by hand every attack other tools reported that tenantbleed did not. They are the only real misses among 291 such claims.

**Projection when every spec is built:**
- tables and views: 0 without a stated reason;
- wrongly shared tables: 0;
- unreached functions: 0 without a stated reason.

Functions cannot all reach a conclusion automatically. The aim for them is **zero silent gaps**: each one that remains is declared in the report, with its reason.

## Known issues found in the code

These came up while mapping the code for these documents. Each is small and goes on the board.

| # | Issue | Where |
| --- | --- | --- |
| K1 | The local guard refuses IPv6 localhost (`[::1]`), ignores the database URL, and is skipped by `fix` | `scan.ts:39-46`, `cli.ts:38-60` |
| K2 | `rules.md` says static findings count for `fail-on: low`; the gate counts proven findings only | `docs/rules.md`, `core/findings.ts:71-75` |
| K3 | Dedupe keeps the first observation, so a later, higher-severity duplicate survives only in `alsoRules` | `observations.ts:540-564` |
| K4 | Fix eligibility matches English phrases in finding text, so rewording a title changes which issues get fixes | `fix/generate.ts:115-121` |
| K5 | The generated migration says "Verified" before verification | `fix/generate.ts:307` |
| K6 | `explainDefaultGrants` always names `service_role` in its advice | `repo-rules.ts:75` |
| K7 | Coverage counts 401 and 403 as "reached" | `probes.ts:53` |
| K8 | The insert probe trusts a `201` without reading the stored row back; anon inserts carry the victim's id in person columns | `probes.ts:282-340` |
| K9 | The update marker is cut to 20 characters and loses the attacker's label | `probes.ts:184` |
| K10 | The delete probe re-inserts the parent row but not children removed by `ON DELETE CASCADE`, and it fires INSERT triggers | `probes.ts:1588-1640` |
| K11 | Metadata is cleared, not restored | `probes.ts:1423` |
| K12 | Rules-paused writes leave CHECKs `NOT VALID` in the test database | `world.ts:614-626` |
| K13 | No statement or HTTP timeouts | engine |
| K14 | `ScanResult` has no `schemaVersion` yet (unit M0.2) | `core/scan-result.ts` |
| K15 | The `src/exec/` primitives are built but mostly unused in production | `src/exec/` |
| K16 | Stale numbers and comments: the developer guide's unit test and rule counts, `rules.json`'s planted app count, misplaced doc comments in `world.ts` and `probes.ts`, `trace.ts` naming `scan()` for `collect()` | docs and comments |

## Roadmap and how it changes the architecture

| Item | Source | Architectural effect |
| --- | --- | --- |
| Coverage specs 1 to 19 | lab coverage index; board | engine (world, probes), judge (triage labels), report (declared lines); planted cases for each |
| AI scenario builder | roadmap Phase 2 | AI writes user journeys; the probes and judge still decide (D1, D2 unchanged) |
| JWT and session tenancy | roadmap Phase 2 | ownership beyond foreign keys (D6) |
| Edge functions, Realtime | roadmap Phase 2 | new probes outside PostgREST |
