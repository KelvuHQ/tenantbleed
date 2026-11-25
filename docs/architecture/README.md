# Architecture

> **Note (open-source pivot, 2026-11-23).** tenantbleed is one fully local, open-source
> codebase: the engine and the judge run in the same process, and the only server is a local
> loopback web UI. There is no hosted service. An earlier engine/judge split (a public GitHub
> Action calling a private judging API over `/v1/judge`), an entitlement token, and a hosted
> accounts path were explored and **retired**, along with `src/api/`, `src/action*`, `action.yml`
> and `scripts/check-bundle.mjs`. The current direction is in
> [../design/open-source-ui.md](../design/open-source-ui.md).

These documents describe how tenantbleed is built:
- the parts of the system and how they depend on each other;
- the data that flows between them;
- the safety rules and where the code enforces them;
- how quality is kept up;
- what is built today and what is only designed;
- the decisions behind the shape;
- the known limits.

**State described:** `origin/main` at `93aca1a` (2026-11-21). File and line references (`src/supabase/world.ts:1243`) point at that commit, and line numbers move as the code changes. When a document and the code disagree, the code wins; fix the document in the same pull request.

## Reading order

| # | Document | Read it to learn |
| --- | --- | --- |
| 1 | [System context](01-context.md) | What the system does, who and what it talks to, the deployment modes, and the trust boundaries |
| 2 | [Components](02-components.md) | Every module, the layering rules and the dependencies |
| 3 | [Scan pipeline](03-scan-pipeline.md) | One scan from start to exit code: each stage, its function and what it hands to the next |
| 4 | [Data model and contracts](04-data-model.md) | Schema, World, Observation, JudgeInput, Finding, ScanResult, coverage, triage, trace: fields, owners, versioning, files written |
| 5 | [The engine](05-engine.md) | The world builder (test users, test data, ownership) and the probes (every attack, owner control, argument synthesis), in depth |
| 6 | [The judge, report and fixes](06-judge.md) | How facts become findings, severities and precision rules, static checks, linter triage, the report, the exit gate, fix templates and their verifier |
| 7 | [Safety and threat model](07-safety.md) | The invariants, where each is enforced, what can go wrong, and the gaps found in the code |
| 8 | [Quality and testing](08-quality.md) | Unit tests, the planted suite, the rules gate, full runs, the benchmark and the coverage programme |
| 9 | [Deployment and operations](09-operations.md) | The CLI, the local web UI server, the lab, Docker slots, environment variables and debug switches |
| 10 | [Decision log](10-decisions.md) | The architecture decisions, why each was made, and what it costs |
| 11 | [Limits, known issues and roadmap](11-limits.md) | What the scanner cannot test today, the issues found while writing these documents, and how planned work changes the architecture |

## How these fit with the existing documents

These pages describe the structure. The existing documents keep the detail, and the architecture pages link to them instead of repeating them:

| Existing document | Holds | Architecture pages that rely on it |
| --- | --- | --- |
| [how-it-works.md](../how-it-works.md) | Every stage of a scan in plain words: introspection, test users, world, ownership, probes, static checks, triage, fixes, cleanup | 03, 05, 06 |
| [rules.md](../rules.md) | Every finding kind, severity and precision rule, and why it exists | 06 |
| [developer-guide.md](../developer-guide.md) | Code map, build, gates, the planted-case-first loop, full runs and their analysis, debugging, Docker capacity, lab safety, writing style | 02, 08, 09 |
| [validation.md](../validation.md) | The evidence: planted apps, field tests, comparisons with other tools | 08 |
| [user-guide.md](../user-guide.md) | Using the CLI and the local web UI | 09 |
| [.claude/project_meta.md](../../.claude/project_meta.md) | Current state, the board, open work | 11 |

## Conventions

- **Built** means it is on `main` and exercised by a gate. **Designed** means a design document exists and the ledger says `todo` or `parked`. **Planned** means it is on the roadmap with no design yet.
- Apps are described by type ("a team app"), never by name, as in every other document in this repository.
- The words follow the house style in the developer guide: plain words, effect before mechanism, no em or en dashes.
