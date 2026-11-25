# 4. Data model and contracts

Three contracts carry a scan from stage to stage:

| Contract | From | To | Versioned |
| --- | --- | --- | --- |
| `Schema` | introspection | world builder, probes, judge (static checks, triage, fixes) | inside `JudgeInput` |
| `Observation[]` | probes | judge | inside `JudgeInput` |
| `JudgeInput` | engine (`collect`) | judge, in process | `v: 1` |
| `ScanResult` | judge | report renderer, exit gate, local web UI, fix generator, lab analysis | not yet: see below |

## Schema (`src/supabase/introspect.ts:4-83`)

| Type | Fields |
| --- | --- |
| `Column` | name, type with modifiers, base type for domains, domain CHECKs, type category, notNull, default, hasDefault, identity, generated, enum labels |
| `ForeignKey` | columns, refSchema, refTable, refColumns, `inferred` (true when added from policies) |
| `Relation` | schema, name, kind `table` or `view`, rlsEnabled, securityInvoker, columns, primaryKey, foreignKeys, checks, uniqueKeys, grants (`Privs` of `anon` and `authenticated` for select, insert, update, delete), partition constraint, `partitionOf` (parent of a partition leaf), `managed` (a Supabase-managed schema the app exposed) |
| `Policy` | schema, table, name, cmd, roles, using, withCheck, permissive |
| `RpcFunction` | schema, name, args (name, type, has default), nArgDefaults, returns, retset, secdef, volatility, body (`prosrc`), execute grants for `anon` and `authenticated` |
| `Schema` | relations, policies, functions, helpers (bodies of functions in schemas that are not scanned, for caller-check analysis) |

**Inferred person columns.** A uuid column that the table's own policy compares with `auth.uid()` gets an `inferred` foreign key to `auth.users` and is treated like a declared one (`inferPersonColumns`, `introspect.ts:263-285`).

## World (`src/supabase/world.ts:13-43`)

| Field | Meaning |
| --- | --- |
| `tenants` | the `Actor`s: label, token, userId, email, minted, appMetadata |
| `owned: OwnedRow[]` | every row a tenant owns: `{table, pk, row, owner, via?}`, where `via` lists the strategy ids that built it |
| `tokens: Map<label, Set<string>>` | **leak markers**: user id, `tp_` marker strings, uuid values in primary and foreign keys, minus values both tenants share |
| `unscoped: Set<table>` | tables treated as shared: declared, singleton, or no row reached an owner |
| `unpopulated: Map<table, reason>` | tables with no test data, with the exact reason (database error, staff list) |
| `profileTables`, `profileTokens` | profile tables, and each profile value with its column, so a leak of only public profile fields can be graded low |
| `notes` | plain-language notes for the report |
| `extra` | `{coworker, admin}` actors, only with `TENANTBLEED_OWNER_CHECK` |

## Observation (`src/core/observation.ts:12-47`)

A discriminated union on `probe`. Each observation is a fact with evidence, never a verdict.

| Field | Meaning |
| --- | --- |
| `probe` | `read`, `graphql-read`, `update`, `reparent`, `insert`, `impersonate`, `rpc-leak`, `rpc-write`, `metadata`, `self-escalation`, `delete`, `file-download`, `file-list`, `file-overwrite`, `file-upload`, `file-delete` |
| `target` | the relation, function or `bucket:<id>` |
| `actor`, `victim` | labels (`anon`, `tenant A`, `tenant B`) |
| `facts` | per probe: for example `{relKind, leaked rows, hits}` for read; `{changed, shared?, primed?}` for rpc-write; `{parentTable, columns, victimCanSee}` for insert |
| `evidence` | `{actor, victim, request {method, path, body}, status, proof, curl, via?}` |

`WorldSummary` travels with the observations: tenant labels and emails, and the profile tokens.

## JudgeInput (`src/core/judge-input.ts:11-55`)

```
{ v: 1, stack: "supabase", startedAt, durationMs, target?,
  schemas, exposed, schema: Schema, tenants, world: WorldSummary,
  observations: Observation[], coverage: CoverageRow[], ownerAccess?,
  notes, probesFinished, trace?, aborted?,
  hints: { seedOnly, functionGrants, tenancy?, migrationsDisabled, sources? },
  lint?: { rows, triggerFunctions, extensionObjects? } | { error } }
```

- **Facts only.** It holds no app code and no real data: the stack contains only test data.
- **Re-judging in seconds.** A saved `<out>.input.json` can be judged again without a database (`tenantbleed judge --input`). This is how judge changes are tested against a whole full run.

## Finding (`src/core/findings.ts:1-61`)

| Field | Values |
| --- | --- |
| `id` | `P001...` proven, `S001...` static |
| `kind` | `cross-tenant-read`, `cross-tenant-update`, `cross-tenant-delete`, `cross-tenant-insert`, `cross-tenant-reparent`, `impersonation-insert`, `anon-read`, `rpc-leak`, `rpc-write`, `view-leak`, `metadata-escalation`, `self-escalation`, `static` |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | `proven` (an effect was observed and confirmed) or `static` (from the schema alone). "Flagged" is a triage verdict, not a confidence. |
| `title`, `detail`, `fix` | plain text |
| `evidence` | as on the observation |
| `rule`, `alsoRules` | the deciding rule id, plus the rules merged into it by dedupe and modifiers (`scripts/rules.json`) |
| `fingerprint` | `TP-` + 10 hex chars of sha256(kind, target, rule, side), with `-2`, `-3` for repeats; stable across runs (`report-context.ts:44-58`) |
| `location` | `[{file, line, what}]` from the source index: the named policy, else the policies for that command, else the object |
| `data` | `{columns, classes}`: columns at stake and their classes (credentials, email, phone, financial, health...) by column name |
| `standards` | `{owasp, cwe}` by kind |

## ScanResult (`src/core/scan-result.ts:10-91`)

```
{ stack, target?, startedAt, durationMs, tenants,
  relationsScanned, functionsScanned,
  findings: Finding[], coverage: CoverageRow[], notes, complete,
  ownerAccess?, triage?, trace? }
```

| Type | Fields |
| --- | --- |
| `CoverageRow` | relation, kind (`table`, `view`, `function`, `bucket`), reached, unreachable, populated, shared?, reason?, notExposed?, staffList?, jwtScoped? (the JWT claim a table is scoped by, not minted so not attacked); for functions also refused, refusedMessage, broken, ownerControl (`guarded`, `no-effect`, `secret-gated`, `victim-independent`), ownerDetail |
| `Triage` | `ran`, error?, rows (`TriageRow`: lint name, target, verdict, rule, reason, prompt?), counts by verdict, `other`, `unflagged` |
| `Verdict` | `proven`, `flagged`, `tested`, `locked`, `shared`, `no-api`, `not-callable`, `extension`, `not-tested` |
| `OwnerAccessRow` | actor (owner, stranger, coworker, admin), relation, op, allowed; used by the fix verifier |
| `trace` | strategy id, count and up to five examples (`src/core/trace.ts`) |

**Versioning.** Only `JudgeInput` carries a version today. The compatibility rule for the ScanResult shape is: adding optional fields is a minor change, and renaming or removing one needs a new version.

## How coverage is counted

| Field | Set by | Rule |
| --- | --- | --- |
| `populated` | `runProbes` init `probes.ts:2117-2120` | false when the table is in `world.unpopulated` |
| `shared` | same | true when the table is in `world.unscoped` |
| `reached`, `unreachable` | `track()` `probes.ts:47` | a 404 or 406 answer counts as unreachable ("not served"); every other status counts as reached, including 401 and 403 |
| `refused`, `broken`, `ownerControl` | the rpc probe | see [05-engine.md](05-engine.md#functions) |

The report renders "could not create test data" for `!populated`, "did not serve it" for `reached == 0 && unreachable > 0`, and "no API access at all" when both counts are 0 (`src/judge/report.ts:225-255`). The tables these lines leave out are listed in [11-limits.md](11-limits.md).

## Strategy ids and marks

The engine tags what did the work:
- `mark(row, "<id>")` (WeakMap marks, read back into `evidence.via`);
- `trace("<id>", where)` (a module-level tally, reset per scan; at most five examples kept).

The ids follow these prefixes: `row/*`, `check/*`, `value/*`, `args/*`, `owner-control/*` and `world/*`.

Every id must be listed in `scripts/rules.json` and produced by a planted case ([08-quality.md](08-quality.md#rules-gate)).
