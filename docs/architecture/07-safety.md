# 7. Safety and threat model

## Invariants

| # | Invariant | Enforced by | Strength |
| --- | --- | --- | --- |
| I1 | A scan only attacks a throwaway local stack | `assertLocal` (`src/engine/scan.ts:39-46`), called by the CLI and the Action. It allows `127.0.0.1`, `localhost`, `0.0.0.0` and `::1` unless `--allow-remote` is given. | **Partial:** only the API URL is checked, not the database URL; `fix` does not call it; IPv6 never matches (see below) |
| I2 | No real user data is ever read | the stack is built from migrations and seed only; there are no real users | by construction |
| I3 | Function calls that can write never commit | `callRolledBack` (`probes.ts:840`), `rollback: true` in `src/exec/sql.ts:91` | strong |
| I4 | Table writes are undone | update and reparent restored; insert and impersonation rows deleted; delete re-inserted; files restored; metadata cleared | **Best effort:** a failed restore only adds a note; cascaded child deletes are not restored |
| I5 | Scheduled jobs do not run during a scan | `pauseScheduledJobs`, resumed in `finally` (`scan.ts:97-99, 194, 204-218`) | strong |
| I6 | Test users are removed | `deleteUser` in `finally` (`scan.ts:195`) | best effort: errors are swallowed |
| I7 | The local UI server is reachable only from this machine | it binds to `127.0.0.1` and gates every request behind a per-session token in the opened URL (`src/ui/server.ts`); nothing is sent off the box | strong |
| I8 | Reports never print credentials | curl uses `$TOKEN_*` and `$ANON_KEY` variables (`src/supabase/api.ts:85-96`); keys are never written to the report | strong |
| I9 | Lab apps cannot reach the internet | the field-test harness rewrites every `*.supabase.co` and inline outbound URL to a dead local port, and **fails closed**; its tooling and corpus are kept outside this repo | strong for SQL and config. Edge functions are not started (`-x edge-runtime`). |
| I10 | Results with real app names never enter git | lab paths outside the repo; `.gitignore` covers reports, inputs and `market/` | process, plus `.gitignore` |
| I11 | No AI decides a finding | there is no model call anywhere in the engine or the judge | by construction |

## The test database is changed

A scan writes into the database it attacks. That is acceptable because the stack is disposable, but it means **a scanned database is not a clean copy of the app** afterwards:

- **Rules paused.** `insertRelaxed` (`world.ts:614`) commits a row in replica mode (triggers and foreign-key checks off) and re-adds the table's CHECKs as `NOT VALID`.
- **Permissions granted.** `grantOwnPermissions` commits permission grants to the test users' roles.
- **Leftovers.** Test rows and test users can remain when a restore or deletion fails.

The lab always stops stacks with `supabase stop --no-backup`. A one-off scan on a dev machine leaves the stack running for the user to stop or reset.

## Threat model

| Threat | Where | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Scanning someone else's production | operator error, a pasted URL | I1; no production keys are needed; the guard refuses a non-local URL unless `--allow-remote` is given | the database URL and `fix` are not guarded |
| Hostile migrations | the app's SQL runs in the stack | a disposable stack; outbound URLs neutralised in the lab; no edge runtime | SQL can still use local resources inside Docker; the lab runs on the operator's machine |
| Results reaching the wrong person | reports can name the app and include a reproduction | reports stay on the user's machine and are never uploaded; in the lab, disclosures are private and apps are never named publicly | process, not code |
| A false proof harming a maintainer | a finding that is wrong | effects confirmed in the database; precision rules; a planted case for every rule; hand checks of every critical and high finding in the corpus before it counts; a benchmark hand check of every rival claim | judgements of "by design" remain human |
| A silent gap read as safety | a "tested" or "shared" label without a real test | coverage rows with reasons; `complete` false when probes stopped | **known overclaims**, listed in [11-limits.md](11-limits.md) |

## Gaps found in the code while writing this

These go to the board as fixes; each is small.

1. **IPv6 localhost is refused.** `new URL("http://[::1]:54321").hostname` is `"[::1]"`, so the `"::1"` entry in `assertLocal` never matches (`scan.ts:41`).
2. **The database URL is not checked.** A remote `--db-url` with a local `--api-url` passes the guard.
3. **`fix` skips the guard** and ignores `--api-url` and `--db-url`, always using `supabase status` (`cli.ts:38-60`).
4. **The migration header claims verification before it happens.** It says "Verified by re-running the attacks" (`src/fix/generate.ts:307`), though verification is a separate, optional step.
5. **The update marker loses the attacker's label.** It is cut to 20 characters, so both tenants write `tp_overwritten_by_te` (`probes.ts:184`). The database comparison still proves the change, but the marker cannot tell which attacker wrote it.
6. **Insert probes trust a `201`.** They do not read the stored row back, unlike impersonation.
7. **Anon inserts carry the victim's id** in person columns (`probes.ts:299`).
8. **Metadata is not restored**, only cleared.
9. **There are no timeouts.** A function that sleeps or loops holds the scan.
