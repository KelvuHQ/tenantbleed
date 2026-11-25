# 10. Decision log

Each entry records:
- the decision;
- why it was made;
- what it costs;
- its status.

A decision changes only through a new entry that replaces it. The dates are when the decision was recorded in the design documents or the board.

| # | Decision | Status |
| --- | --- | --- |
| D1 | Prove, never guess | in force |
| D2 | Engine and judge are separate, joined by facts | in force |
| D3 | A hosted engine/judge split was explored, then retired | retired 2026-11-23 |
| D4 | Hiding the planning too (second split) | retired 2026-11-23 |
| D5 | Attack through the real APIs, as real users | in force, one exception |
| D6 | Ownership from the data | in force; the main source of silent gaps |
| D7 | Get test data in, then say how | in force |
| D8 | Lower, never hide | in force |
| D9 | Planted case first | in force |
| D10 | Deterministic, seeded test data | in force, partial |
| D11 | Local only; production is never written | in force |
| D12 | Never name a scanned app | in force |

## D1. Prove, never guess

- **Decision.** A finding is reported as proven only when an attack had an effect that was confirmed in the database, or returned the victim's markers. Schema-only findings are labelled `static`, and linter warnings are triaged, never promoted.
- **Why.** Linters already list what might be wrong. The product's value is the proof, and one false proof costs more trust than ten misses.
- **Cost.** Real bugs that the scanner cannot reach stay silent unless coverage reports them. This is why the coverage programme exists ([11-limits.md](11-limits.md)).
- **Status.** In force.

## D2. Engine and judge are separate, joined by facts

- **Decision.** Probes record `Observation`s: facts with evidence, no severity, no wording. A pure `judge()` decides everything else.
- **Why:**
  - a whole full run can be re-judged in seconds from saved inputs;
  - every decision rule sits in one place.
- **Cost.** Each probe needs a matching case in the judge, and the facts a rule needs must be collected in the engine.
- **Status.** In force. The separation remains useful even now that both halves run in the same process.

## D3. A hosted engine/judge split was explored, then retired

- **Decision (retired).** For a time the plan was to ship a public GitHub Action that ran only the engine, and keep the judgement (severity, precision rules, static checks, triage, report text and fixes) behind a private `POST /v1/judge` API, gated by an entitlement token. A bundle check kept judge and fix code out of the public bundle.
- **Why it was considered.** An Action runs on the customer's runner, so its code can be read, and the judgement was the hard-won part. Keeping it private was a way to sell a hosted service while giving the engine away.
- **Why it was dropped (2026-11-23).** tenantbleed is not a sellable product; it is a fully local, open-source tool. The whole apparatus, the Action, the judging API, the entitlement token, the hosted accounts path and the bundle check, was removed (`src/api/`, `src/action*`, `action.yml`, `scripts/check-bundle.mjs`). The engine and judge now run in the same process, and the judge code is public like the rest.
- **Status.** Retired. See [../design/open-source-ui.md](../design/open-source-ui.md).

## D4. Hiding the planning too (second split)

- **Decision (retired).** A follow-on idea to D3: move the planner behind the API as well, with a generic five-primitive executor (`sql`, `http`, `user`, `storage`, `catalog`) running on the runner and sealed state between steps.
- **Why it was dropped.** It only made sense to protect a paid, hosted product, which no longer exists. It was parked in 2026-11-19 and retired with D3 in 2026-11-23. The `src/exec/` primitives it was built on remain in the tree, used only for `sql`, `query` and `createUserDirect`.
- **Status.** Retired.

## D5. Attack through the real APIs, as real users

- **Decision:** test users have real Auth sessions; reads and table writes go through PostgREST; storage goes through the Storage API; GraphQL through `/graphql/v1`.
- **The one exception.** Volatile functions are called in SQL, the way PostgREST runs them (the API role and the caller's JWT claims), inside a transaction that is always rolled back. A read-only `GET` first confirms that the API serves the function.
- **Why:**
  - the API applies grants, policies, exposed schemas and claims exactly as a browser sees them;
  - the SQL path for volatile functions is the only way to undo a function's writes completely.
- **Cost.** A difference between PostgREST's behaviour and our imitation of it would show up as a wrong verdict on a function.
- **Status.** In force.

## D6. Ownership from the data

- **Decision.** Who owns a row is decided after building, from person columns, memberships and parent links (`attribute`), not from who inserted the row. Tables where no row reaches a user are treated as shared and are not attacked.
- **Why.** Apps model ownership in many ways. The data shows the truth of a schema better than any naming rule.
- **Cost.** **This is the largest source of silent gaps found so far.** Examples:
  - a user table keyed by the auth id as text, with no foreign key;
  - tenancy carried in a JWT claim;
  - an isolation helper that always returns true;
  - rows built between the two test users.

  In each case the tables become "shared" and are never attacked. Fixes are specified ([11-limits.md](11-limits.md)).
- **Status.** In force; being extended.

## D7. Get test data in, then say how

- **Decision.** The world builder escalates step by step until the row goes in:
  1. the API as the user;
  2. the owner with the user's claims;
  3. the CHECK solver and its repairs;
  4. the bystander;
  5. a backend write;
  6. as a last resort, rules paused.

  Every step that contributed is recorded (`via`, `trace`), so a finding shows how its data was built.
- **Why.** A table without test data cannot be attacked. Real apps refuse rows for many reasons that have nothing to do with isolation.
- **Cost:**
  - the test database is changed (`NOT VALID` CHECKs, granted permissions);
  - a row built with rules paused is less realistic, so its findings deserve a closer look.
- **Status.** In force.

## D8. Lower, never hide

- **Decision.** A precision rule may lower a proven finding's severity, with a reason in the finding. No rule deletes one.
- **Why.** False alarms are better shown at low severity with the reason than lost. A wrong precision rule stays visible.
- **Cost.** Reports carry low-severity noise.
- **Status.** In force.

## D9. Planted case first

- **Decision:**
  - every change starts as a planted case that fails on the current build;
  - every rule and strategy id must be produced by a planted case;
  - the gates run locally, and now that the project is open source, GitHub Actions CI runs the typecheck, unit tests and the planted fixture suite on every push;
  - full runs against real apps stay off CI, because those apps cannot go in git.
- **Why:**
  - the planted suite is fast, and it is generic (neutral names);
  - full runs are slow and contain real apps that cannot go in git.
- **Cost.** The full-run evidence depends on discipline: it is produced locally, not on CI.
- **Status.** In force.

## D10. Deterministic, seeded test data

- **Decision.** Sampled values come from one seeded stream per scan (`src/core/random.ts`). Markers, passwords and keys stay random.
- **Why.** Runs can be compared exactly.
- **Cost:**
  - the seed is the constant `tenantbleed` for every app, not one per app;
  - test emails include the time.

  So two runs of one app give the same sampled values but not byte-identical reports.
- **Status.** In force, partial.

## D11. Local only; production is never written

- **Decision:**
  - scans run on throwaway stacks built from migrations;
  - the guard refuses non-local URLs;
  - production is never written or read.
- **Why.** Writing to or reading from someone's production carries risks a local tool should never take on. Everything runs against a disposable local stack built only from the app's own migrations.
- **Cost.** Bugs that depend on production data or configuration are out of reach.
- **Status.** In force.

## D12. Never name a scanned app

- **Decision.** Scanned apps are never named in code, fixtures, documents, commits or marketing. Results with real data stay in the lab. Maintainers are told privately first.
- **Why.** These are real people's projects, and many are side projects. Publishing a bug before a fix exposes their users.
- **Cost.** The evidence for the product's claims has to be given as totals.
- **Status.** In force.
