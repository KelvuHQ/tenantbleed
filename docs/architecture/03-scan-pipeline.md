# 3. Scan pipeline

One scan, from the command to the exit code. The plain-words version of each stage is in [how-it-works.md](../how-it-works.md); this page names the functions, the data handed between stages and what happens on failure.

## Sequence

```
cli.ts supabase  (or ui: the same collect, driven from the local web UI)
   | fromStatus(workdir) | explicit flags
   | assertLocal(stack)
   v
engine/scan.ts collect(opts) ------------------------------------------------+
   1 config: exposed schemas, tenantbleed.json, hints                        |
   2 connect pg + SupabaseApi                                                |
   3 JudgeInput skeleton (target, hints)                                     |
   4 pause pg_cron jobs                                    finally:          |
   5 schema notes, hidden schemas, graphql check             resume cron     |
   6 introspect(db, schemas) -> Schema                       delete users    |
   7 create tenant A, tenant B (+ lazy bystander)            db.end          |
   8 buildWorld(...) -> World                                trace rows      |
   9 runProbes(...) -> observations, coverage, notes                         |
  10 runSplinter(...) -> lint rows                                           |
   returns JudgeInput <------------------------------------------------------+
   |
   +-- judge(input) in process
   v
judge/index.ts judge(input) -> ScanResult
   |
cli.ts finish: <out>.md (toMarkdown), <out>.json (ScanResult), exit = gateExitCode
```

## Stages

| # | Stage | Code | Input | Output | On failure |
| --- | --- | --- | --- | --- | --- |
| 0 | Target | `fromStatus` `scan.ts:32-36`; `assertLocal` `scan.ts:39-46` | workdir or four flags | `Stack` {apiUrl, dbUrl, anonKey, serviceKey, jwtSecret} | non-local API URL: exit 2 unless `--allow-remote` |
| 1 | Config | `exposedSchemasFromConfig` `introspect.ts:237-242`; `scan.ts:52-57` | `config.toml`, `tenantbleed.json` | exposed schemas (default `public`), shared tables, tenancy hint | defaults |
| 2 | Connect | `scan.ts:62-66` | Stack | `pg.Client`, `SupabaseApi` | throws, exit 2 |
| 3 | Skeleton | `scan.ts:71-93`; `scanTarget` `target.ts:24-41`; `repo-hints.ts` | repo | `JudgeInput` with target, hints (seed-only objects, function grants, tenancy, migrations disabled, source index) | partial hints |
| 4 | Pause jobs | `pauseScheduledJobs` `scan.ts:204-214` | pg_cron | active jobs paused | resumed in `finally` |
| 5 | Schema notes | `scan.ts:100-124` | schemas | notes for exposed-but-missing, granted-but-unexposed, GraphQL; unexposed schemas named in function bodies are added and introspected again | notes |
| 6 | Introspect | `introspect` `introspect.ts:88-230`; `inferPersonColumns` `:263-285` | catalogs | `Schema` {relations, policies, functions, helpers} | throws, aborted |
| 7 | Test users | `scan.ts:126-152`; `SupabaseApi.createUser` `api.ts:98-111`; `createUserDirect` `exec/user.ts:29-52` | Auth | `Actor` tenant A and B, lazy bystander | direct insert on a 5xx signup; minted session when password login is off; notes |
| 8 | World | `buildWorld` `world.ts:1243` | api, db, schema, tenants, {shared, bystander} | `World` {owned rows, tokens, unscoped, unpopulated, profile tables and tokens, notes} | per table: the table is marked unpopulated with the error |
| 9 | Probes | `runProbes` `probes.ts:2106` | api, db, schema, world | `ProbeResult` {observations, world summary, notes, coverage, ownerAccess?} | per probe: note "X probe stopped early"; `probesFinished=false` |
| 10 | Linter | `runSplinter` `src/lint/splinter.ts:12-18` | db, schemas | lint rows, trigger functions, extension objects | `lint = {error}` |
| 11 | Cleanup | `scan.ts:193-199` | | cron resumed, test users deleted, connection closed, `durationMs`, `trace` | errors in deletion are swallowed |
| 12 | Judge | `judge` `judge/index.ts:58-97` | JudgeInput | ScanResult | aborted input: proven findings only, `complete=false` |
| 13 | Report and gate | `toMarkdown` `judge/report.ts:174`; `finish` `cli.ts:126-133`; `gateExitCode` `core/findings.ts:71-75` | ScanResult | files and exit code | any exception: exit 2 (`cli.ts:135-138`) |

**Fix generation** is a separate command (`fix --report <scan.json>`, `cli.ts:38-60`): it introspects again, calls `generateFixes(findings, schema)` and writes one migration per fix plus `fixes.json`. Verification is the separate script `scripts/verify-fixes.mjs` ([06-judge.md](06-judge.md#fixes)).

## Probe order

`runProbes` runs these steps one after another, each in its own try/catch (`probes.ts:2123-2135`):

```
read -> graphql -> user_metadata -> self_escalation -> update -> reparent
     -> insert -> impersonation -> rpc -> storage -> delete
```

**Why this order:**
- Reads run first, on untouched data.
- Writes that are restored come before writes that remove.
- Functions run after table writes, so their snapshots see the restored state.
- Delete runs last, walking the tables in reverse foreign-key order, because a deleted parent would hide its children from later probes.

## What a scan writes

| File | Writer | When |
| --- | --- | --- |
| `<out>.md` | `finish` | always, even when the scan stopped early |
| `<out>.json` (ScanResult) | `finish` | always |
| `<out>.input.json` (JudgeInput) | `cli.ts:118-121` | with `TENANTBLEED_SAVE_INPUT=1` (the lab and the planted suite always set it) |
| `~/.tenantbleed/history/<project>/<timestamp>.json` | the UI server | after a scan run from `tenantbleed ui`, for the History screen |
| `<dir>/F00n_<target>.sql`, `fixes.json` | `fix` | on request |

## Exit codes

| Code | Meaning | Source |
| --- | --- | --- |
| 0 | nothing proven at or above `--fail-on` | `gateExitCode` |
| 1 | a **proven** finding at or above `--fail-on` (default `high`); static findings never count | `gateExitCode` |
| 2 | the scan was incomplete and nothing was proven, or the scan could not run (guard, exception) | `gateExitCode`, `cli.ts:135-138` |

A CI step runs the `supabase` command and gates on this exit code directly; there is no separate gating layer.

## Timing

| Kind of app | Wall time of a scan |
| --- | --- |
| planted `supabase-vuln` | about 3 s |
| planted `supabase-hard` | about 26 s |
| a typical corpus app | 30 s to 2 min |

Stack start-up adds 20 to 60 s. Everything is sequential on one database connection, with no statement or HTTP timeouts ([11-limits.md](11-limits.md)).
