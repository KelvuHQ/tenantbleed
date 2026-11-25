# tenantbleed developer guide

For everyone who works on the product or the code. It covers how the code is organised, how a change is made and tested, and the rules every change must follow. The structure (components, contracts, safety, decisions, known issues) is in [architecture/](architecture/README.md). The mechanics of a scan are in [how-it-works.md](how-it-works.md), every decision rule in [rules.md](rules.md), the evidence in [validation.md](validation.md). Current state and open work: [project_meta.md](../.claude/project_meta.md).

- [What the tool is](#what-the-tool-is)
- [Ground rules](#ground-rules)
- [Code map](#code-map)
- [Build and bundles](#build-and-bundles)
- [The test gates](#the-test-gates)
- [The change loop: planted case first](#the-change-loop-planted-case-first)
- [Adding a planted case](#adding-a-planted-case)
- [Rules and strategies (rules.json)](#rules-and-strategies-rulesjson)
- [Field testing on real apps](#field-testing-on-real-apps)
- [How functions get a conclusion](#how-functions-get-a-conclusion)
- [Debugging a scan](#debugging-a-scan)
- [Writing style](#writing-style)

## What the tool is

tenantbleed proves tenant-isolation bugs in Supabase apps. It starts the app's own migrations on a local stack, creates two real test users (tenant A, tenant B) and an anonymous visitor, builds test data each user owns, and has each attack the other through the same API a browser uses. A finding exists only when an attack worked, confirmed in the database. Everything is deterministic: no AI decides anything.

Two halves, kept apart in the code:

- **The engine** (`src/supabase/`, `src/engine/`, `src/exec/`): does things. Starts nothing itself, connects to a running local stack, introspects, builds the world, runs probes, records **observations** (plain facts: "tenant A's PATCH changed tenant B's row").
- **The judge** (`src/judge/`, `src/fix/`): decides. Turns observations into findings with severities, applies precision rules, runs static checks, triages linter warnings, writes the report and fix prompts.

Keeping the two apart keeps the judge pure: `judge(input)` takes facts and returns a `ScanResult` with no database or network access, so a saved input can be re-judged in seconds. The engine never imports from `src/judge/` or `src/fix/`; shared helpers live in `src/core/`.

## Ground rules

1. **Generic only.** Every fix follows from the schema, the policies, the function bodies or the data, never from an app's names. A real app only shows where the tool breaks; the shape is copied into a planted app with neutral names. If a fix would only work for one app (a business rule, one table's missing row), it is not a fix.
2. **Never name a scanned app or its owner** in code, fixtures, docs, commits or marketing. Describe apps by type ("a CRM app", "a code-hosting app").
3. **Local only.** We scan open-source apps on this machine, never anyone's hosted project, GitHub account or service. Outbound URLs are neutralised before a scan, failing closed.
4. **Results with real data never go in git.** Reports, inputs, disclosure drafts and market notes are git-ignored and kept outside the repo.
5. **No hosted CI.** There are no GitHub Actions on our repos (free minutes). The gates run locally.
6. **Planted case first, full run last.** See [the change loop](#the-change-loop-planted-case-first).
7. **Lower, never hide.** A precision rule lowers a severity with a reason; it does not delete a proven finding.
8. **One branch and one pull request per board item** (`.claude/project_meta.md`, section 5). Code work happens in the dev worktree `~/Projects/tenantbleed-dev` (its own `npm ci`; a symlinked `node_modules` fails the bundle check), so the main checkout stays on `main` for documentation work. Branch from `main`, or from the open PR's branch while it is not merged yet. The PR description carries what changed for the scan, the planted case, and the gate results; the product owner reviews and merges. Every PR is listed in the PR log in `project_meta.md`.
9. **Commit only your own files, by path**: `git commit -m ... -- <paths>`. Parallel sessions share one working tree and one git index, so a plain `git commit` also takes whatever another session has staged.

## Code map

| Path | Role |
| --- | --- |
| `src/cli.ts` | CLI entry: `supabase` (scan), `judge` (re-judge a saved input), `fix` (generate fix migrations). |
| `src/engine/scan.ts`, `target.ts` | Orchestrates one scan against a target (URLs, keys, schemas); safety guard against non-local URLs. |
| `src/exec/` | The database and HTTP primitives (`sql`, `http`, `user`, `catalog`) as batch functions over plain JSON. |
| `src/supabase/introspect.ts` | Reads the catalogs: relations, columns, keys, CHECKs, policies, grants, functions with bodies. |
| `src/supabase/world.ts` | Test users, building the world (table order, the CHECK solver, retries), ownership (`attribute`), leak markers. |
| `src/supabase/probes.ts` | Every attack: reads, writes, reparent, insert, impersonation, functions (argument building, rolled-back calls, owner control, secret gate, victim removal, row state), storage, GraphQL. Records observations. |
| `src/supabase/api.ts` | PostgREST and Auth clients for the test users. |
| `src/supabase/repo-hints.ts` | Hints read from the repo (exposed schemas, config). |
| `src/core/observation.ts` | The observation type: probe, target, actor, victim, facts, evidence. The contract between engine and judge. |
| `src/core/scan-result.ts`, `judge-input.ts` | What a scan writes (`<out>.input.json`) and what the judge reads. |
| `src/core/trace.ts` | `mark()` and `trace()`: which test-data steps and argument strategies did the work, counted per report. |
| `src/core/job-shape.ts` | Clock-driven function shapes (scheduled jobs, maintenance by age), shared by engine and judge. |
| `src/judge/observations.ts` | One finding per observation: kind, base severity, precision rules, wording. |
| `src/judge/static.ts` | Schema-only checks (RLS off, definer views, open policies, definer functions that run caller SQL or switch isolation off). |
| `src/judge/triage.ts` | Matches every Supabase linter warning to what the scan showed and gives a verdict. |
| `src/judge/report.ts`, `check-prompts.ts`, `context.ts` | Markdown and JSON report, "check it yourself" prompts, customer report fields. |
| `src/lint/` | Vendored splinter SQL (Supabase's linter) and its runner. |
| `src/fix/generate.ts` | Deterministic fix templates. `scripts/verify-fixes.mjs` verifies them on a fresh database. |
| `src/ui/` | The local loopback web UI: an HTTP server on `127.0.0.1` gated by a per-session token, serving the built SPA (`ui/`) and running a scan in process. |
| `ui/` | The web UI source (React, Vite, TypeScript), built to `dist/ui/`. |
| `fixtures/` | Planted apps, each a Supabase project plus `fixture.json`. |
| `scripts/` | Build, fixture checkers, `rules.json` and its gate. |
| `test/` | Unit tests (`node --test`). |

## Build and bundles

```sh
npm install
npm run build      # typecheck, bundle the engine, build the UI
npm test           # unit tests (19 today)
```

`npm run build` runs `tsc --noEmit`, bundles the engine with esbuild, then builds the UI with Vite. **`dist/` is gitignored**: it is built from source on `npm install` of a dependent and on `npm publish` (`prepublishOnly`), and `package.json` ships it through the `files` field.

| Bundle | What | Contains |
| --- | --- | --- |
| `dist/tenantbleed.mjs` | the CLI, the lab build and the local UI server | engine, judge, fix, UI server |
| `dist/ui/` | the built single-page app | the web UI served by `tenantbleed ui` |

The engine never imports from `src/judge/` or `src/fix/`; put shared helpers in `src/core/` (for example `job-shape.ts`).

Reports carry the build version (`0.1.0+<commit>`, `.dirty` when source changed), so every result can be traced to its code.

## The test gates

| Gate | Command | Time | When |
| --- | --- | --- | --- |
| Unit tests | `npm test` | seconds | every change |
| Planted suite | `npm run test:fixtures` | about 1 minute | every engine or judge change, before every commit |
| Everything local | `npm run check` | about 2 minutes | before a commit |

**The planted suite** (`scripts/test-fixtures.sh`) starts the five planted apps in parallel, scans each, and runs its checker. It then runs `scripts/check-rules.mjs`: every rule and strategy in `scripts/rules.json` must have been produced by at least one planted case, and every rule in the code must be listed. It passes only when every app passes and every rule is exercised. Reports go to `$OUT` (default a temp folder), never into the repo:

```sh
OUT=/tmp/tp-fx npm run test:fixtures
# supabase-hard: hard cases: 70 of 70 solved, 0 false positives, 0 tables without test data
# rules: 195 of 195 exercised by the planted apps
# fixtures: PASS in 58s
```

The suite is the gate you rely on day to day. **A full run is not a test**: it confirms that nothing regressed on real apps and feeds the analysis of what is still undecided. If a full run shows a problem, the fix starts as a planted case, so the suite catches it from then on.

A leftover stack from an interrupted run can make the first suite run fail on cases unrelated to your change. Rerun once before investigating.

## The change loop: planted case first

Every change, whether a new strategy, a fixed false alarm or a missed bug, goes through the same loop:

1. **See it on a real app** (a full run or a single-app scan): a finding gone, a false alarm, a function left undecided, a table without test data.
2. **Find the generic shape.** Read the app's SQL. Ask what about the schema, the policy or the body made the tool fail. Write it down without app names.
3. **Plant it.** Add a migration to the right planted app (usually `fixtures/supabase-hard`) that copies the shape with neutral names, and add the expectation to its checker.
4. **See it fail on the current build.** `git stash -q -- src && npm run build && npm run test:fixtures; git stash pop && npm run build`. A planted case that passes on the old build tests nothing.
5. **Fix it generically**, and add any new rule or strategy id to `scripts/rules.json`.
6. **Run the gates**: `npm run check`. Every planted app passes, every rule is exercised, 0 false positives.
7. **Commit** source, `dist/`, fixture and checker together.

## Adding a planted case

A planted app is `fixtures/<name>/` with a Supabase project and a `fixture.json`:

```json
{ "engine": "supabase", "checker": "check-<name>.mjs",
  "replays": [{ "suffix": "single", "hints": { "tenancy": "single" } }] }
```

`test-fixtures.sh` finds every folder with a `fixture.json`; a new planted app needs nothing else. Replays judge the same scan facts again with changed hints (for example as a single-workspace app).

Most cases go into `fixtures/supabase-hard`:

- **Migration**: `supabase/migrations/2026MMDDhhmmss_<what>.sql`, later than the last one. Start with a comment that says what shape it copies, from what kind of app, and why the tool got it wrong. Reuse the planted app's own tables (`studios`, `created_by`) as tenants. Plant both sides: a function or table that must be proven, and a guarded twin that must stay clean.
- **Checker**: `scripts/check-hard.mjs`. Add to:
  - `expected`: a case name and the findings it needs (`kind`, `target`, side `tenant` or `anon`);
  - `mustBeFilled`: tables that must get test data for both tenants;
  - `mustBeClean`: objects that must have no proven finding;
  - the triage verdict checks, when the case is about a verdict (for example "tested, with the owner's check named in the reason").

## Rules and strategies (rules.json)

`scripts/rules.json` lists every decision the judge can make and every strategy the engine can use, with one sentence each:

- `findings`: rule ids with their `severity|side` variants;
- `triage`: linter verdict rules;
- `strategies`: test-data steps (`row/*`, `check/*`, `value/*`), argument strategies (`args/*`), owner controls (`owner-control/*`) and world steps (`world/*`);
- `notes`, `modifiers`, `untestable`.

The engine calls `mark(row, "<id>")` or `trace("<id>", where)` when a strategy contributes; reports list the ids in their trace and on each finding's `evidence.via`. The rules gate fails when an id is never produced by a planted case or when the code produces an id not listed. So a new strategy needs three things: the code, the `rules.json` entry, and a planted case that exercises it.

## Field testing on real apps

tenantbleed was validated against a private corpus of real open-source Supabase apps whose copies and results are kept outside this repo, along with the tooling that runs and analyses them. The runnable, public regression gate is the planted-fixture suite under `fixtures/` (`npm run test:fixtures`). Aggregate field-test results are in [validation.md](validation.md).

## How functions get a conclusion

Functions are the hardest part: a call that changed nothing could mean a working caller check or test values that missed. The scan settles them in this order (`src/supabase/probes.ts`); each step has a rule id:

1. **Attack**: call with the victim's values, built by the argument strategies (`args/*`: ids from one victim row, the column the body compares the argument to, the parent's id, the current month, a scope word). A leak or a change to the victim's rows is proven.
2. **Owner control** (`owner-control/changed`, `returned`, `accepted`, `got-further`): the victim makes the same call on their own data. If that works and the attacker's call did not, the function checks the caller: tested, not exploitable.
3. **Secret gate** (`owner-control/secret-gated`): lookups by a secret value; answered only to the exact value.
4. **Victim removal** (`owner-control/victim-removal`, `victim-independent`): functions that take nothing aimed at a user; the attacker's answer is compared with and without the victim's rows, in a rolled-back transaction.
5. **Row state** (`args/row-state`, `owner-control/row-state`): functions that only act on rows in a given state (`status = 'pending'`, `paid_at is null`, `credits > 0`). The victim's row is put in that state inside the rolled-back transaction, then the owner's and the attacker's calls are repeated. Maintenance by age is excluded (making a row old proves nothing about a cleanup).
6. **Body rules** in the judge: maintenance by age (`triage/function-time-maintenance`), schema risks that need no call (`static/definer-exec-arg`, `static/definer-security-ddl`).
7. Anything left is **not tested** (`triage/function-owner-control-no-effect`) with a "check it yourself" prompt.

## Debugging a scan

| Setting | Effect |
| --- | --- |
| `TENANTBLEED_DEBUG_RPC=1` | every function call, its arguments and its effect, on stderr |
| `TENANTBLEED_DEBUG_WORLD=1` | every test row attempt, refusal and retry, on stderr |
| `TENANTBLEED_SAVE_INPUT=1` | writes `<out>.input.json`: the full scan facts. `node dist/tenantbleed.mjs judge --input <file> --out <prefix>` re-judges it in seconds, without a database. Use this for judge-only changes. |
| `TENANTBLEED_OWNER_CHECK=1` | after the attacks, checks what the owner, a coworker and an admin can still do (used by the fix verifier) |

Useful habits:

- For a judge change, re-judge saved inputs from the last full run instead of rescanning: seconds instead of hours.
- A report's `trace` section shows which strategies did the work; `evidence.via` on a finding shows which ones built it.
- The coverage rows of the JSON report give the exact database error for every table without test data.
- A table listed as "Treated as shared (no path to a user)" in the scan notes was never attacked. When it is clearly tenant data, find out why ownership did not reach it.

## Scanned app names never enter the repo

A scanned app's real name or owner must not appear in code, fixtures, tests, commit messages, docs or marketing. Refer to an app by a generic shape ("a courses app"), never by its real name.

A committed pre-commit hook enforces this: `scripts/hooks/pre-commit` (wired through `git config core.hooksPath scripts/hooks`, shared by every worktree) reads a local name mapping and blocks a commit whose staged additions contain a real name or GitHub owner. It skips `dist/` and a few common words; a genuine false positive is bypassed with `git commit --no-verify`. The hook passes silently when the mapping is absent (CI, another machine), since there is nothing to leak there. After cloning, run `git config core.hooksPath scripts/hooks` once if it is not already set.

## Writing style

- Plain words a customer would use; describe the effect before the mechanism.
- No em or en dashes anywhere (code comments, docs, reports, commits).
- English in code; apps described by type only.
- Commit messages say what changed for the scan, in one line, then why.
