# 1. System context

## What the system does

tenantbleed proves tenant-isolation bugs in Supabase apps. Given a running local copy of an app's database, built only from the app's own migrations, it:

1. reads the schema;
2. creates two real test users (tenant A, tenant B), plus an anonymous visitor;
3. builds test data that each user owns;
4. has each actor attack the other's data through the same APIs a browser uses;
5. confirms every effect in the database, then undoes it;
6. reports only what worked, with a request that reproduces it and a fix.

No AI decides anything. The same app at the same commit gives the same findings.

## Context diagram

```
                       +------------------------------------------------------+
                       |  Throwaway Supabase stack (local or CI runner)        |
                       |                                                       |
 app repo              |   Postgres  <---- SQL (pg) ----+                      |
 supabase/ folder ---> |   (migrations + seed)          |                      |
 (migrations,          |   PostgREST /rest/v1  <-- HTTP --+                    |
  config.toml,         |   GoTrue    /auth/v1  <-- HTTP --+-- tenantbleed      |
  seed.sql,            |   Storage   /storage/v1 <- HTTP -+   engine           |
  tenantbleed.json)    |   pg_graphql /graphql/v1 <- HTTP-+                    |
                       +------------------------------------------------------+
                                                         |
                                     JudgeInput (facts)  |  in the same process
                                                         v
                                                  +-------------+
                                                  |   judge     |
                                                  | (rules,     |
                                                  |  triage,    |
                                                  |  report)    |
                                                  +-------------+
                                                         |
                                ScanResult JSON + Markdown report + exit code
                                                         |
                          developer, local web UI, CI gate, fix generator
```

## Actors and external systems

| Who or what | Role | How the system reaches it |
| --- | --- | --- |
| The app's `supabase/` folder | The only input describing the app: migrations, `config.toml` (exposed schemas, ports, auth settings), `seed.sql`, optional `tenantbleed.json` (`name`, `shared`, `tenancy`) | Read from disk (`src/engine/scan.ts:52-57`, `src/supabase/repo-hints.ts`) |
| The local Supabase stack | Postgres, PostgREST, GoTrue, Storage, optionally pg_graphql, started by the Supabase CLI (`supabase start`) | `supabase status -o json` for URLs and keys (`src/engine/scan.ts:32-36`); then SQL over `pg` and HTTP over `fetch` |
| Test users | tenant A, tenant B, a lazy bystander, and for fix checks a coworker and an admin | GoTrue admin API, or direct inserts into `auth.users` when signup is refused (`src/exec/user.ts:29-52`) |
| The anonymous visitor | Requests with only the anon key | `SupabaseApi.headers()` with no token (`src/supabase/api.ts:36-43`) |
| The judge | Turns facts into findings | In the same process as the engine |
| Any CI | Runs the CLI headless, reads the exit code, gates the build | `dist/tenantbleed.mjs supabase --fail-on <severity>` |

The system never contacts the app's hosted project, its domain or any third-party service the app uses. It makes no network calls off the machine it runs on. The lab rewrites every outbound URL in an app's SQL and config to a dead local port before starting it ([07-safety.md](07-safety.md)).

## Deployment modes

| Mode | Status | Engine runs | Judge runs | Entry |
| --- | --- | --- | --- | --- |
| The CLI and the lab | **Built**, used daily | on the user's machine | in the same process | `dist/tenantbleed.mjs supabase` |
| The local web UI | **Built** | on the user's machine | in the same process | `dist/tenantbleed.mjs ui` (loopback 127.0.0.1 only) |

## Trust boundaries

```
 [an app's repo] --(supabase/ folder only)--> [the machine running tenantbleed]
                                                   |  local stack: test data only, no real users
                                                   |  engine and judge in one process, no network off the box
                                                   |
                                     report stays with the code's owner
```

1. **App code to scanner.** tenantbleed reads the `supabase/` folder and nothing else. Migrations are SQL written by the app's authors and run inside the throwaway stack; they are untrusted, which is why the stack is disposable and outbound URLs are neutralised in the lab.
2. **Scanner to stack.** The engine holds the service key, the database URL and the JWT secret of a **local** stack. `assertLocal` refuses a non-local API URL unless `--allow-remote` is given (`src/engine/scan.ts:39-46`). There are no real users or real data in the stack.
3. **Results to people.** A report can name the app and prove an attack, so it stays with the code's owner and nothing is uploaded. For the corpus and disclosures, see [07-safety.md](07-safety.md).

## Quality attributes the shape serves

| Attribute | How the architecture serves it |
| --- | --- |
| **No false proofs** | A finding exists only when an effect was observed and confirmed in the database. Probes record facts; the judge alone decides. Every precision rule lowers a severity with a reason; none deletes a proven finding. |
| **Determinism** | Seeded sampling (`src/core/random.ts`), fixed probe order, no AI in the verdict, a fingerprint per finding (`src/core/report-context.ts:44-58`). |
| **Safety** | Local-only guard, rollbacks for function calls, restores for writes, cron paused, test users deleted, outbound URLs neutralised in the lab. |
| **Explainability** | Every finding carries the request, the proof, a curl command, `evidence.via` (how its test data was built), a rule id and a source location. |
| **Evolvability** | A versioned facts contract (`JudgeInput v:1`), rule and strategy ids checked by a gate, a planted case for every behaviour. |
