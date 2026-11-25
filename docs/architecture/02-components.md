# 2. Components

## Layers

```
 entry points     src/cli.ts        src/ui/server.ts (local loopback web UI)
                      |                   |
 orchestration    src/engine/scan.ts (collect), src/engine/target.ts
                      |
 engine           src/supabase/{introspect, world, probes, api, repo-hints}
 (does)           src/lint/splinter.ts (runs the vendored linter SQL)
                      |
 primitives       src/exec/{sql, http, user, catalog}
                      |
 shared core      src/core/{observation, judge-input, findings, scan-result,
                            report-context, trace, random, job-shape}
                      ^
 judge            src/judge/{index, observations, static, triage, report,
 (decides)                   context, check-prompts, repo-rules}
                  src/fix/generate.ts
```

**Layering rules:**

1. **The engine never imports from `src/judge/` or `src/fix/`.** Anything both halves need lives in `src/core/` (for example `job-shape.ts`, which the engine uses to skip row-state priming and the judge uses to grade time-based functions). Keeping the two apart is what lets the judge stay pure and re-run saved inputs.
2. **Probes record facts, never verdicts.** An `Observation` has no severity and no wording (`src/core/observation.ts:12-40`). The judge's `draft()` decides both (`src/judge/observations.ts:155-526`).
3. **`src/core/` imports nothing from the other layers.** It holds types, pure helpers and module-level tallies.
4. **The judge is pure.** `judge(input)` takes a `JudgeInput` and returns a `ScanResult` with no database or network access. That is what lets the lab re-judge saved inputs in seconds, without a stack.

## Modules

| Module | Lines | Responsibility | Main exports |
| --- | --- | --- | --- |
| `src/cli.ts` | 138 | The CLI: `supabase` (scan), `ui` (local web UI), `judge --input`, `fix --report` | `finish()` writes `<out>.md` and `<out>.json` and sets the exit code |
| `src/ui/` | | The local loopback web UI: an HTTP server on `127.0.0.1` gated by a per-session token, serving the built SPA and running a scan in process; copy-only remediation | `startUiServer` |
| `src/engine/scan.ts` | 218 | Orchestrates one scan: target, config, connection, cron pause, introspection, users, world, probes, linter, cleanup | `collect(opts) → JudgeInput`, `fromStatus`, `assertLocal` |
| `src/engine/target.ts` | 41 | App name, git commit, branch, dirty flag, migrations hash, tool version | `scanTarget` |
| `src/supabase/introspect.ts` | 285 | Catalog reader; infers person columns from policies | `introspect`, `exposedSchemasFromConfig`, `grantedButUnexposed`, types `Schema`, `Relation`, `Column`, `ForeignKey`, `Policy`, `RpcFunction` |
| `src/supabase/world.ts` | 1,681 | Test data: table order, row building, the CHECK solver, retries, ownership, leak markers, staff gates, privilege demotion | `buildWorld`, `buildRow`, `findProfileTables`, `isUserRef`, types `World`, `OwnedRow` |
| `src/supabase/probes.ts` | 2,174 | Every attack, the effect checks, restores, owner control, argument synthesis, coverage rows | `runProbes → ProbeResult` |
| `src/supabase/api.ts` | 197 | PostgREST, Auth and Storage client as each actor; curl rendering; token minting | `SupabaseApi`, type `Stack`, `Actor` |
| `src/supabase/repo-hints.ts` | 105 | Facts read from the repo: seed-only objects, GRANT and REVOKE statements on functions, a source index of where each object is defined | `seedOnlyObjects`, `functionGrantStatements`, `sourceIndex` |
| `src/lint/` | 44 + SQL | Vendored splinter (Supabase's linter), run in a rolled-back transaction; trigger functions; extension-owned objects | `runSplinter` |
| `src/exec/` | 278 | Batch primitives over plain JSON: `sql` (roles, claims, replica mode, rollback), `http`, `storage`, `users`, `catalog` | `sql`, `sqlOne`, `query`, `createUserDirect` |
| `src/core/` | 500 | Contracts and shared helpers | `Observation`, `JudgeInput`, `Finding`, `ScanResult`, `gateExitCode`, `fingerprint`, `trace`, `mark`, `random` |
| `src/judge/` | 1,665 | Observations to findings, static checks, modifiers, triage, report, prompts, context | `judge`, `toMarkdown` |
| `src/fix/generate.ts` | 312 | Deterministic fix templates | `generateFixes`, `migrationFor` |

Line counts are at `93aca1a`; the source totals about 8,000 lines.

**Note on `src/exec/`.** A set of batch primitives over plain JSON. Today, production code uses only `sql`, `query` and `createUserDirect` from it; the scan reaches PostgREST, Auth and Storage through `SupabaseApi` directly. The other primitives are exercised only by `test/exec.test.ts`.

## Bundles

`npm run build` runs `tsc --noEmit`, then `scripts/build.mjs` (esbuild: bundle, Node 20, ESM, `.sql` loaded as text, `pg-native` external, `TENANTBLEED_VERSION = <version>+<commit>[.dirty]`), then `vite build` for the UI.

| Bundle | Contains | Who runs it |
| --- | --- | --- |
| `dist/tenantbleed.mjs` | engine, judge, fix and the local UI server | the CLI, the lab, the planted suite |
| `dist/ui/` | the built single-page app served by `tenantbleed ui` | the local UI server |
| `dist-test/*.mjs` | one bundle per test file | `node --test` |

`dist/` is gitignored and built from source (on `npm install` of a dependent and on `npm publish`), so a build is reproducible from the commit. Every report carries the version string.

## Dependencies

| Dependency | Why | Notes |
| --- | --- | --- |
| Node 20 or newer | runtime | `engines.node >=20` |
| `pg` ^8.23 | the only runtime package | bytea kept as text by a custom parser (`scan.ts:62-63`) |
| Supabase CLI 2.122.1 | starts and describes the stack | pinned in the lab and `fromStatus` (`TENANTBLEED_SUPABASE_VERSION`) |
| esbuild, TypeScript, Vite | build only | esbuild for the engine bundle, Vite for the UI |
| `node:crypto`, `node:http`, `fetch` | the per-session token, the local UI server, HTTP to the stack | platform first, no framework |

## Where to add things

| To add | Touch | And also |
| --- | --- | --- |
| A probe | `src/supabase/probes.ts` (a step in `runProbes`), an `Observation` variant in `src/core/observation.ts`, a `case` in `src/judge/observations.ts`, wording in `src/judge/report.ts` | rule ids in `scripts/rules.json`, a planted case, a checker expectation |
| A test-data strategy | `src/supabase/world.ts`, with `mark(row, "row/<id>")` or `trace("world/<id>")` | `rules.json` `strategies`, a planted case that needs it |
| A precision rule | `src/judge/observations.ts` or `index.ts`; lower, never delete | `rules.json` `findings` with every `severity\|side` variant, a planted "stays low" case and a "not low" twin |
| A static check | `src/judge/static.ts` | `rules.json`, a planted case |
| A triage verdict rule | `src/judge/triage.ts` | `rules.json` `triage`, or `untestable` with a unit test |
| A fix template | `src/fix/generate.ts` | a run of `scripts/verify-fixes.mjs` on a planted app |
