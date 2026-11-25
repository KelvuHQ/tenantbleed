# 6. The judge, report and fixes

The judge is a pure function from facts to results: `judge(input: JudgeInput): ScanResult` (`src/judge/index.ts:58-97`). It has no database access and no network access. Every decision rule and why it exists is in [rules.md](../rules.md); this page describes the structure.

## 6.1 Pipeline

```
observations --judgeObservations--> proven findings --singleWorkspace--> (tenancy modifier)
                                          |
                    aborted input? ---yes--> proven only, complete = false, stop
                                          |
             downgradeSeedOnly, explainDefaultGrants (repo-rules.ts)
schema --staticChecks--> static findings --downgradeLatent(proven)--> --downgradeSeedOnly-->
                                          |
                          addReportContext (fingerprint, location, data classes, standards)
                                          |
                     complete = probesFinished && schema not empty
                                          |
                lint rows --triage(coverage, findings, schema)--> Triage
                                          v
                                     ScanResult
```

## 6.2 From observation to finding

**One case per probe.** `draft()` (`src/judge/observations.ts:155-526`) has one `case` for each probe value. Each case returns `{rule, kind, severity, title, detail, fix?}`.

**Base severity** depends on the actor: anonymous is worse than signed in.

| Rule | Anonymous | Signed-in user |
| --- | --- | --- |
| read, file-download, update, delete, insert, rpc-leak, rpc-write | critical | high |
| file-upload | high | medium |
| impersonate | n/a | medium |
| metadata | n/a | critical |
| self-escalation | n/a | critical if it unlocked other rows, else medium (`/stored`) |

**Precision rules** lower a severity with an explanation. They never delete a proven finding. The rules in `draft()`:

| Family | Rules |
| --- | --- |
| read | `read/declared-public`, `read/profile-only`, `read/open-policy`, `read/open-policy-sensitive`, `read/backend-only-policy`, `read/view` |
| reparent, insert | `/shared-parent`, `/unseen-parent` |
| impersonate | `/membership` |
| rpc-leak | `/derived-value`, `/ids-only`, `/profile-only` |
| rpc-write | `/shared-counters`, `/shared-recompute`, `/shared-scheduled-job`, `/shared-change`, `/seed-defaults`, `/scheduled-job-creates`, `/creates-in-victim`, `/cache-refresh`, `/time-based-cleanup`, `/counters`, `/change` |
| storage | `file-list/public-bucket`, `file-upload/unseen` |

**Modifiers** run after the precision rules. Each one adds itself to `alsoRules`:

| Modifier | Code | Effect |
| --- | --- | --- |
| `modifier/single-workspace` | `index.ts:20-36` | With `tenancy: "single"`, between-user findings become low. With no tenancy setting, a heads-up suggests it when most tables are readable across users. |
| `modifier/latent` | `index.ts:42-56` | An unconditional UPDATE, DELETE or ALL policy that no probe exploited becomes low and "(latent)". |
| `modifier/seed-only` | `repo-rules.ts:6-18` | Objects created only by the seed file become low. |
| `explainDefaultGrants` | `repo-rules.ts:67-78` | Severity unchanged. It explains that `REVOKE ... FROM PUBLIC` leaves Supabase's direct grants to `anon` and `authenticated`. |

**Dedupe.** There is one finding per (kind, target, side), where side is anon or signed-in, and the first observation wins (`:540-564`). Later duplicates add their rule to `alsoRules` and a line to the detail: "Also reachable through GraphQL", or "Reproduced in both directions".

## 6.3 Static checks (`src/judge/static.ts:30-241`)

These run on the schema alone, in exposed schemas only. Their ids are `S001...` with `confidence: "static"`.

| Rule | Severity |
| --- | --- |
| `static/rls-disabled` | high |
| `static/definer-view` | medium |
| `static/policy-always-true` | high on writes, low on SELECT (an authenticated-only `with check (true)` INSERT is exempt) |
| `static/policy-user-metadata` | high |
| `static/definer-exec-arg` (a definer function that runs SQL built from its arguments) | critical |
| `static/definer-security-ddl` (turns RLS off or grants access, without a caller check) | critical |
| `static/definer-http` | critical with an embedded service-role JWT, else high for anon, medium otherwise |
| `static/definer-vault`, `static/auth-writer` | high for anon, medium otherwise |
| `static/definer-unchecked` | medium for anon, low otherwise |
| `static/definer-yes-no`, `-checks-caller`, `-cannot-target`, `-safe-by-construction`, `static/auth-writer-checked` | info |

**Caller checks.** A caller check is detected by following helper calls up to three levels deep, including into helper bodies from unscanned schemas (`callerChecker` `:269`).

**Safe by construction.** A function counts as safe by construction (`:330`) when it:
- touches no table;
- returns nothing and writes nothing;
- or is gated by a secret argument.

## 6.4 Linter triage (`src/judge/triage.ts:51-189`)

The vendored splinter runs in the engine. The judge then matches every data-access warning (17 lint types) to what the scan showed, and gives each one verdict. The checks run in order, and the first match decides:

1. **`proven`**: there is a proven finding on the target.
2. **`extension`**: the target is owned by an extension.
3. **Functions:**
   - `not-callable`: a trigger, a read-only yes/no helper, unnamed arguments, a body using an object that does not exist, or permission denied;
   - `tested`: owner control proved a caller check, it is secret-gated, victim-independent, or maintenance by age;
   - `flagged`: a definite schema risk;
   - `not-tested`: owner control had no effect, or it was refused for everyone;
   - `no-api`: the API does not serve it.
4. **Tables:**
   - `locked`: RLS on with no policies;
   - `shared`: shared by design;
   - `not-tested`: no test data;
   - `no-api`: not reached;
   - `flagged`: there is a static finding;
   - `tested`: otherwise.

There are 28 triage rule ids. `unflagged` lists the proven findings at medium or above on objects the linter never warned about.

**Linter warnings never change severities or the exit code.**

**Check it yourself.** Rows marked `flagged` or `not-tested` get a "check it yourself" prompt, from one of five templates (`check-prompts.ts`).

> **Known overclaim.** A function whose owner call had no effect, but which a body rule or a static finding settles, is shown as **tested**. The coverage programme found many such rows across the corpus; see [11-limits.md](11-limits.md).

## 6.5 Report (`src/judge/report.ts`)

**JSON** is the `ScanResult`, pretty-printed.

**Markdown** (`toMarkdown` `:174-263`) has these sections, in order:

1. **Headline:** the count of proven failures, or "no proven failures", or "coverage incomplete".
2. **What was scanned:** the app name, commit, migrations hash and tool version.
3. **Counts by severity.**
4. **Heads-up notes.**
5. **"Fix these first":** up to five critical or high findings, in plain words.
6. **"Proven with real accounts":** a table, then one collapsible block per finding with:
   - what happened;
   - where to fix it (file and line);
   - the data involved, by class;
   - the standards it breaks;
   - the request and its status;
   - the proof;
   - a curl command to reproduce it on a local stack;
   - the fix;
   - an AI fix prompt.
7. **Schema findings:** not exploited, but they explain the failures above.
8. **Coverage:** how many reachable tenant tables were tested, what is shared and what has no API, storage, and every gap with its reason.
9. **Linter triage:** the verdict table, what was proven real, the other warnings with the reason for each, up to 15 check-it-yourself prompts, and the unflagged line.
10. **Scan notes.**

**Credentials in curl lines.** Tokens appear in curl commands only as `$TOKEN_<LABEL>` and `$ANON_KEY` variables (`src/supabase/api.ts:85-96`), so a report can be pasted without leaking credentials.

## 6.6 Exit gate

`gateExitCode` (`src/core/findings.ts:71-75`):
- 1 when a **proven** finding is at or above `fail-on`;
- 2 when the scan is incomplete and nothing was proven;
- 0 otherwise.

Static findings never fail the gate. [rules.md](../rules.md) says otherwise for `fail-on: low`; [11-limits.md](11-limits.md) lists this.

## 6.7 Fixes

### Generation

`generateFixes(findings, schema)` (`src/fix/generate.ts:153-300`) maps each eligible finding (proven, medium or above) to a deterministic template. The main tool is a **restrictive** policy: Postgres ANDs restrictive policies with the existing ones, so a fix can only narrow access.

| Template | When |
| --- | --- |
| `table-restrict` | a table read or write. Restrictive policies per command are scoped by a protected parent's visibility, else the owner column; inserts need both. Plus `no_anon`. |
| `table-enable-rls` | RLS is off. Enable it and add owner policies. |
| `policy-to-service-role` | an always-true policy named for the service role. `alter policy ... to service_role`, plus owner-scoped policies. |
| `function-revoke-anon`, `function-security-invoker` | definer functions reachable by anon or by other users |
| `view-security-invoker` | definer views |
| `storage-owner-folder` | restrictive policies on `storage.objects` by owner folder, plus `no_anon` |

Findings no template can close safely are skipped with the reason, for example:
- "needs a check inside its body";
- "no owner column: needs a human";
- "may be public by design".

### Verification

`scripts/verify-fixes.mjs` is a prototype that is run by hand. It is not yet part of `npm run check`. It runs these steps:

1. Reset the database.
2. Run a baseline scan with owner checks.
3. Generate the fixes.
4. For each fix: add it as the next migration, reset, scan again, then remove it.

A fix is accepted only when:
- the attacks it closes fail;
- no new medium-or-above finding appears;
- every owner, coworker and admin operation that worked before still works.

Access lost by a coworker or admin that a stranger also had at baseline goes to "review". Checks that cannot be compared go to "could not recheck". The output is `verify.json` and `fix-report.md`.
