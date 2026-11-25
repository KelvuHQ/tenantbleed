# Design: open-source tenantbleed with a localhost UI

Status: proposed, 2026-11-22. Supersedes the first/second split and the hosted-judge plan (see
"What the open-source pivot changes" below).

## 1. Goal

Make tenantbleed a polished, fully open-source project that a developer runs on their own machine to
check a Supabase app for tenant-isolation bugs, reads a clear report, and gets a concrete fix and an
AI-fix prompt for each problem. It doubles as a portfolio piece, so the repo and the UI both have to
look and feel finished.

Two product surfaces, one engine:

- the existing CLI (`tenantbleed supabase ...`), unchanged for scripts and CI, and
- a new local web UI (`tenantbleed ui`) that runs a scan, shows the report, and offers fixes.

## 2. What the open-source pivot changes

Everything that existed to protect a paid, hosted product goes away. The repo becomes one honest
codebase with nothing hidden.

Removed or retired:

- The engine/judge split (`dist/action-judge.mjs`, the bundle check in `scripts/check-bundle.mjs`,
  `docs/design/first-split.md`, `second-split.md`, the `src/action.ts` hosted path). The judge runs in
  the same process as the engine; there is no private half.
- The entitlement token (`tenantbleed token`, `mintToken`, `TP_SIGNING_KEYS`). No accounts, no plans.
- The private lab constraints as repo rules. The field-test corpus stays private (it holds other
  people's code), but the planted fixtures (`fixtures/supabase-*`) become first-class, documented
  examples that double as the demo and the test suite. The pre-commit app-name guard stays, because the
  private corpus still must not leak into commits.

Kept:

- The whole scanner, judge, triage, fix generator, planted fixtures, and docs.
- The local-only safety posture: tenantbleed only ever talks to a database the user points it at, and
  the probes write and modify rows, so the UI makes "use a dev or staging database, never production"
  impossible to miss.

Add a short `docs/architecture/` note recording that the split is retired, so the history stays legible.

## 3. Architecture

```
  tenantbleed ui
      |
      v
  Local server (Node, http://127.0.0.1:7171)        bind to loopback only
      |  - serves the built React SPA (static)
      |  - REST + SSE API over the existing engine
      |
      +-- import { collect, runProbes, judge, buildReport, generateFixes } from the engine
                     |
                     v
             user's local Supabase (Docker) or a Postgres connection string
```

- One package, one process. The server imports the engine modules directly (not a shelled-out CLI), so
  a scan is a function call with a progress callback. No second service, no network calls off the box.
- The SPA is built at release time and shipped inside the npm package (`dist/ui/`). `tenantbleed ui`
  serves those static files plus the API, then opens the browser. No build step for the user.
- Loopback only (`127.0.0.1`), random-free fixed port 7171 (overridable with `--port`), a per-run token
  in the URL so another local process cannot drive it.

### Engine change needed: progress events

`runProbes` already runs discrete named steps (`read`, `policy_state_read`, `graphql`, ...). Thread an
optional `onProgress(step, done, total)` callback through `collect` and `runProbes` so the server can
stream progress over SSE. This is additive and the CLI ignores it. Nothing else in the engine changes.

## 4. Server API

Small and boring on purpose. JSON everywhere; one SSE stream for progress.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/target` | What the server can scan: detected local Supabase project (from `supabase/config.toml`), and whether a connection string was passed. |
| `POST` | `/api/scan` | Start a scan. Body: `{ source: "local" | "connection", connectionString?, schemas?, triage? }`. Returns a `scanId`. |
| `GET` | `/api/scan/:id/events` | SSE: `progress`, `note`, `done` (with the `ScanResult`), `error`. |
| `GET` | `/api/scan/:id` | The finished `ScanResult` JSON (same shape the CLI writes). |
| `GET` | `/api/scan/:id/report.md` | The Markdown report (reuses `buildReport`). |
| `GET` | `/api/scan/:id/fixes` | Generated fixes `{ fixes, skipped }` from `src/fix/generate.ts`. |
| `GET` | `/api/scan/:id/report.html` | A self-contained HTML export of the report (for sharing). |

The `ScanResult` already carries everything the UI needs: `findings` (severity, kind, target, title,
detail, `location` "where to fix", `standards` OWASP and CWE, `evidence` with the curl and the proof,
`confidence`), `coverage` rows, `triage` rows (each with a `checkPrompt` for warnings the scan could
not settle), and `notes`. Per-finding AI-fix prompts come from `aiFixPrompt(finding)`.

## 5. UI: information architecture

A single-page app, left nav, one scan in view at a time. Calm, dense, readable in light and dark.

```
+-------------------------------------------------------------------------+
|  tenantbleed            app: my-app @ a1b2c3   schema v.  [ Re-scan ]    |
+-----------+-------------------------------------------------------------+
|  Scan     |   Summary                                                   |
|  Findings |   [ 2 critical ] [ 1 high ] [ 3 medium ]  3 proven, 1 to    |
|  Coverage |   check yourself. 42 of 48 reachable tables tested.         |
|  Check    |                                                             |
|  yourself |   Findings (most severe first)                              |
|  Export   |   +-----------------------------------------------------+   |
|           |   | ! crit  cross-tenant read   public.notes            |   |
|           |   |         Another tenant's rows came back to user B.  |   |
|           |   |         OWASP A01  CWE-639     [ proof ] [ fix ]     |   |
|           |   +-----------------------------------------------------+   |
|           |   | ! crit  self-escalation     public.profiles         |   |
|           |   ...                                                       |
+-----------+-------------------------------------------------------------+
```

Screens:

1. Scan. Pick the target (detected local Supabase project, or paste a Postgres connection string). A
   loud banner: this writes and changes rows, point it at a dev or staging database. A schema picker
   (defaults to what `config.toml` exposes). Start. A live progress list of the probe steps.
2. Findings. The report's heart. Severity-sorted list; click one to open a detail panel:
   - plain-English what and why (`detail`),
   - the evidence (the request, the status, the leaked proof row, the exact `curl` to reproduce),
   - where to fix (`location`: file and line in their migrations),
   - OWASP and CWE tags,
   - a Fix SQL block (from the fix generator) with a copy button,
   - an AI-fix prompt block (`aiFixPrompt`) with a copy button and a "paste into Cursor, Claude,
     Lovable or Bolt" hint.
3. Coverage. What was tested and what was not, and why: reached vs. not, shared-by-design, staff lists,
   tables scoped by a JWT claim the scan does not mint, partitions served through a parent, schemas the
   API does not expose. This is the honesty surface, and a strong trust signal for the brand.
4. Check yourself. The triage warnings the scan could neither prove nor clear, each with its plain
   `checkPrompt`. Grouped, copyable.
5. Export. Download the Markdown report, the self-contained HTML report, or the raw JSON. One click.

### Remediation UX (decided: show and copy)

For every finding the UI shows the generated fix SQL and the AI-fix prompt, each with a copy button.
The UI never writes to the user's project and never touches their database beyond the scan itself. The
report already says where to apply the fix; the user applies it through their own migration flow. (A
future "write a migration file" button is noted in section 10 but is out of scope for v1.)

## 6. Scan target and safety

- Local Supabase project: detect `supabase/config.toml` in the working directory, read the exposed
  schemas and the local DB port, scan the running local stack (the CLI already does this).
- Connection string: accept a `postgresql://...` the user provides. Refuse anything that is not
  loopback or a private host unless the user checks an explicit "I confirm this is not production" box,
  and always show the host being scanned.
- The probes insert, update and delete test rows. This is stated on the Scan screen, in the README, and
  once more in a confirm step before the first scan of a session.
- The server binds to `127.0.0.1` only and gates the API behind a per-session token in the opened URL.

## 7. Repo polish for open source

The code is strong; the wrapping has to match for a portfolio piece.

- `README.md`: a 30-second pitch, an animated demo (GIF of a scan finding a real bug in a planted app),
  quickstart (`npx tenantbleed ui`), what it checks, what it does not, and the honest-coverage story.
- `LICENSE` (AGPL-3.0), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md` (how to report, and the "runs against your own dev DB" model).
- A docs site from the existing `docs/` (the architecture and rules docs are already good). Options:
  the markdown as-is on GitHub, or a small static docs site (VitePress) if we want it to shine.
- CI on GitHub Actions (now that it is open): typecheck, unit tests, and the planted fixture suite on
  push and PR. The fixtures make this a real correctness gate, not a smoke test.
- The planted fixtures reframed as `examples/`: each is a tiny Supabase app with a known bug, runnable,
  and used by the demo and the tests. This is the best possible "trust me" for a security tool.
- Screenshots and a short screencast in the README and on the user's own site.
- Issue and PR templates; a clear `good first issue` set (more checks).

## 8. Packaging and distribution

- `npm publish` the one package. `bin.tenantbleed` stays; add the `ui` subcommand.
- The built SPA ships in the package under `dist/ui/`; `files` in `package.json` includes it.
- `npx tenantbleed ui` with no install is the headline path; a global install also works.
- Keep the only runtime dependency small (`pg`); the server uses Node's built-in `http`. The UI build
  (React, Vite) is a dev dependency only, never shipped as source to the user.

## 9. Build plan (milestones)

1. Retire the split: remove `token`, the action/judge bundle and its check, fold the judge into the
   engine, update docs. Green tests and fixtures throughout. (small)
2. Progress callback through `collect`/`runProbes`; a `report.html` self-contained export. (small)
3. The server: the API in section 4, loopback, token, SSE. No UI yet, test with curl. (medium)
4. The SPA: Scan, Findings, Finding detail with copy buttons, Coverage, Check-yourself, Export. (large)
5. `tenantbleed ui` command: build-and-serve, open browser, `--port`. (small)
6. Repo polish: README, demo GIF, LICENSE, CONTRIBUTING, SECURITY, CI, examples, screenshots. (medium)
7. Optional docs site (VitePress). (medium, can be later)

Each milestone keeps the planted suite and unit tests green; the fixtures are the regression gate.

## 10. Open decisions

- License: resolved. AGPL-3.0 or later, for copyleft protection, with a separate commercial license offered. Switched from Apache-2.0 on 2026-11-25.
- Name: keep `tenantbleed` (descriptive, available as the repo name) unless the user wants a rebrand.
- Docs site now or later (GitHub markdown is fine to start).
- Future, not v1: a "write a migration file" button; "apply to DB"; a GitHub Action users can drop
  into their own CI.

## 11. Visual direction

Developer-tool aesthetic: monospace for code and identifiers, a restrained palette, severity colors
used sparingly (one accent per severity, never a wall of red), generous white space, full dark mode. It
should read like a well-made terminal report that happens to be clickable, not a dashboard. The coverage
and "what we did not test" screens get equal visual weight to the findings, because honesty is the brand.
