# 8. Quality and testing

The scanner's value is that its proofs are right and its silence means something. Quality is held up by five layers, from seconds to hours. How to use each one day to day is in [developer-guide.md](../developer-guide.md#the-test-gates).

| Layer | What it proves | Command | Time | In `npm run check` |
| --- | --- | --- | --- | --- |
| Type check and bundles | the code compiles; the public bundle has no judge or fix code; no absolute paths | `npm run build` | seconds | yes |
| Unit tests | contracts and pure logic | `npm test` | seconds | yes |
| Planted suite | every planted bug proven, every safe twin clean, every table filled, every rule produced | `npm run test:fixtures` | about 1 minute | yes |
| Full run | nothing regressed on real apps; what is still undecided | internal tooling kept outside this repo | under an hour | no |
| Benchmark and hand check | what other tools prove that we miss, settled one by one | internal tooling | hours | no |

There is no hosted CI ([10-decisions.md](10-decisions.md), D9). The gates run on the developer's machine, and the pull request description carries their results.

## Unit tests (`test/`, 19 tests)

| File | Covers |
| --- | --- |
| `judge.test.ts` | extension triage, caller checks through helpers, safe by construction, shared writes, creates in victim, check prompts, unreached and unserved warnings, report fields, the CASE solver, caller SQL |
| `exec.test.ts` | SQL batches and transaction order, http, the staff gate, `buildRow` |

Each test file is bundled by esbuild into `dist-test/` and run with `node --test`.

## Planted suite (`scripts/test-fixtures.sh`)

Five planted apps live in `fixtures/`. Each is a real Supabase project with bugs planted on purpose, guarded twins that must stay clean, and a checker. The suite:

1. takes every Docker slot;
2. freezes the build;
3. starts the five apps in parallel on fixed ports;
4. scans each with debug and saved input;
5. replays the saved input with changed hints (for example `tenancy: single`);
6. runs each checker, then the rules gate.

| App | What it plants | Checker |
| --- | --- | --- |
| `supabase-vuln` | organisations, every bug class | `check-fixture.mjs`, strict: exactly the expected findings, **any unexpected proven finding fails** |
| `supabase-team` | a single-workspace intranet | `check-team.mjs`: staff tables, signup refused, the single-workspace replay |
| `supabase-workspaces` | workspaces with invitations, composite keys | `check-workspaces.mjs` |
| `supabase-hard` | hard test data and functions (31 migrations, plus seed) | `check-hard.mjs`: expected cases, about 30 clean targets, 58 tables that must be filled, "stays low" cases, triage verdicts, tables that must be built without pausing rules |
| `supabase-regress` | shapes copied from real apps where the tool once failed | `check-regress.mjs`: field cases with fixed twins, tables that must be filled, no known gaps allowed |

**Shared checks** (`scripts/lib/fixture-gate.mjs`):

| Check | Fails the suite when |
| --- | --- |
| expected keys | a finding (kind, target, side) is missing |
| `mustBeClean` | anything proven on a clean target: a **false proof** |
| `mustBeFilled` | a table did not get test data |
| `knownGaps` | never; these are reported without failing |
| report context | target metadata, unique fingerprints, standards on every finding, or a location on every proven finding is missing |

**The rule behind the suite:** a planted case must fail on the build before the change ([developer-guide.md](../developer-guide.md#the-change-loop-planted-case-first)). A case that passes on the old build tests nothing.

## Rules gate (`scripts/check-rules.mjs`)

`scripts/rules.json` lists every decision and every strategy, each with one sentence:
- 59 finding rules with 76 severity and side variants;
- 3 modifiers;
- 28 triage rules;
- 13 notes;
- 87 strategies;
- an `untestable` list covered by unit tests or the fix verifier.

The gate fails when:
- an id is never produced by a planted report;
- the code produces an id the file does not list;
- an id in the file no longer exists in the code.

So every behaviour has a name, a sentence and a planted case.

## Full runs on real apps

The corpus is a set of open-source Supabase apps, copied into the lab (outside the repository):

| | Apps |
| --- | --- |
| In the manifests | 169 |
| Start from their own migrations | about 119 |

A full run:
1. freezes the build into the run folder;
2. scans the apps in parallel, one Docker slot each;
3. retries once with the seed or auth hook off;
4. runs the planted suite on the same build;
5. prints the headline numbers.

Internal analysis tooling kept outside this repo answers these questions:

| Question | What it reports |
| --- | --- |
| the headline | proven findings by severity |
| what changed | which findings were added and which disappeared |
| the undecided | what has no conclusion |
| recurring shapes | which shapes of undecided functions recur |
| a hanging scan | what a hanging scan is doing |

**A full run is not a test.** It confirms nothing regressed and finds new shapes. Each new shape becomes a planted case first.

## Benchmark and hand check

Two benchmarks compare tenantbleed with the public RLS testers. Each has its own caveat:

| Benchmark | Run on | Caveat |
| --- | --- | --- |
| Planted ([product/benchmark.md](../product/benchmark.md)) | the five planted apps | the apps are our own regression suite, so the test favours us |
| Corpus | the 119 apps that start | the answer key is tenantbleed's own proven findings, so it measures what the others catch of what tenantbleed proves |

The hand check covers the reverse direction. Every attack another tool reported that tenantbleed did not is checked by reading the policies and helper bodies, and by a live attack when the code leaves it open. Each one gets a verdict:

| Verdict | Means |
| --- | --- |
| real gap | a real problem tenantbleed missed |
| by design | the access is intended |
| not a gap | tenantbleed already flags it |
| not reproduced | the attack does not work for real users |

Each real gap becomes a coverage spec and a planted case.

## Coverage programme

**Goal: zero silent gaps.** Every object ends in one of three states:
1. tested, with an observed effect or refusal;
2. attacked and safe;
3. declared with a reason the report prints.

The first sweep, on 2026-11-21, followed every "could not test" case to a root cause and wrote one spec per cause. The specs live in the private lab, because they name apps; the planted cases built from them use neutral names. The generic causes are summarised in [11-limits.md](11-limits.md#coverage-gaps-by-root-cause).

## Weak points of the gates

- `check-fixture.mjs` passes its triage checks when `report.triage` is absent.
- Static findings have no false-flag accounting in the planted suite.
- The planted suite always starts five stacks on fixed ports, even when Docker has fewer slots.
- `verify-fixes.mjs` is not part of `npm run check`.
- Several checker case labels are reused for two different cases (cosmetic, but the output is ambiguous).
