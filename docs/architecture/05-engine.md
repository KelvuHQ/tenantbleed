# 5. The engine

The engine does three things:
- builds a world in which each test user owns realistic data;
- attacks across that world;
- confirms every effect in the database.

The plain-words description is in [how-it-works.md](../how-it-works.md), sections 3 to 6. This page covers the design: how the parts fit, the rules each one follows, and where they live.

## 5.1 World builder (`src/supabase/world.ts`)

```
buildWorld(api, db, schema, tenants, opts)                       world.ts:1243
  resetSampling("tenantbleed")                                   seeded values
  preexisting rows (3 per table), staff lists excluded           :1251-1262
  uploads per bucket if a table references storage.objects       :1264-1282
  for each table in topoOrder:                                   :78
     adopt existing rows (signup and parent triggers)            existingRows :649
     reconcile composite keys, helper parents                    :1206, :1303
     for each tenant: build a row, insert, repair and retry      buildRow :484, loop :1353-1501
  fill deferred person columns                                   :1529-1542
  attribute ownership from the data                              attribute :1555
  demote privilege flags on profiles                             demoteTestUsers :412
  grant each tenant's roles every catalogued permission          grantOwnPermissions :439
  -> World
```

### Tenancy discovery

| Concept | Rule | Code |
| --- | --- | --- |
| Profile table | single-column primary key that is a foreign key to `auth.users` (`public.users`, `profiles`) | `findProfileTables` `:55` |
| Person column | a foreign key to `auth.users`, declared or inferred, or a single-column foreign key to a profile table | `isUserRef` `:65` |
| Tenant table | a table with a primary key. Tables without one get no test data and no write probes. | `tenantTables` `:68` |
| Staff list | an app-wide list of staff is never filled, so the test users are not made staff. It is detected by name (admins, moderators, staff...) together with every key pointing at users and a mention in a policy or function; or as a leaf table read by a privilege-named gate function (`exists (select ... where col = auth.uid())`) that other code calls. | `:1254-1262`, `staffGate` `:298` |
| Privileged values | role, permission and tier columns avoid app-wide values (`platform_admin`, `super_admin`...); privilege booleans get `false`; after building, privilege booleans on profiles are set back to false ("the first signup becomes admin" triggers) | `firstSafe` `:334`, `:404`, `demoteTestUsers` `:412` |
| Role permissions | junction tables between a role table and a permissions catalogue get every permission for the tenants' own roles, so a tenant is a full owner of its own organization and permission checks can be told apart | `grantOwnPermissions` `:439` |

### Ownership (`attribute`, `:1555`)

Ownership comes from the data, not from who inserted the row:

1. A row names a user in a person column: it belongs to that user.
2. A row names **two different** test users: it belongs to neither.
3. Membership: the person column and the parent column are together in the primary key or one unique key. The membership row then claims its parent for that user.
4. Ownership spreads to child rows through the remaining foreign keys, repeating until nothing changes.
5. A table is **unscoped** (shared) when:
   - it is declared shared;
   - it is a singleton with a boolean primary key;
   - or no row of a populated table reached an owner.

   Unscoped tables are skipped by the read sweep and most other probes. This is the rule behind the largest silent gap found so far ([11-limits.md](11-limits.md)).

**Leak markers.** For each tenant:
- the user id;
- every `tp_` string;
- the uuid values in primary and foreign keys, except keys into shared tables.

Values both tenants hold are removed.

### Row building

`buildRow` (`:484`) fills columns in this order:

1. **Person columns** get the tenant's id. An optional person column pointing at a profile row that does not exist yet is filled later, by an update (`row/person-filled-later`).
2. **Other foreign keys** take the tenant's newest row in the parent table. When an earlier key already fixed a shared column, the parent must agree with it.
3. **Plain columns** come from `sampleValue` (`:339`):
   - values respect CHECK hints, enums, lengths, numeric ranges and regex patterns (a small generator, `:172-286`);
   - text gets a marker `tp_<tenant>_<table>_<col>_<8hex>`.
4. **Defaults and optional columns:**
   - columns with a default are left to the default, except uuid primary keys, which the scan supplies so it can find the row again;
   - optional non-text columns stay empty, so a filled `deleted_at` or lock flag cannot hide the row from policies.

### Insert and repair loop (`:1353-1501`, at most 12 attempts)

**Where each attempt writes:**
1. First through PostgREST as the tenant, when `authenticated` may insert.
2. If refused, as the database owner with the tenant's JWT claims, so triggers and `auth.uid()` defaults behave as for that user (`insertAsService` `:593`).

**Repairs, in order:**

| Refusal | Repair |
| --- | --- |
| exclusion constraint (23P01) | shift dates by a year |
| CHECK (23514) | the **CHECK solver** `solveCheck` `:1141`: CASE to OR, split branches, about 20 atom shapes, `(A) = (B)` equivalences; every candidate is tested by a rolled-back `select (expr) is not false` before inserting |
| CHECK after the solver | leave the optional columns the CHECK mentions empty |
| NOT NULL in another table (a trigger copies a column) | fill the column the trigger needs |
| length rule inside a trigger | short markers `tp_<8hex>` |
| raised error | leave every optional column empty |
| the person must be someone else | use the bystander |
| anything except a unique violation | write as the backend would, with no user claims, and note it |
| CHECK, raised error, or P0001, with no other source of rows | **rules paused** (`insertRelaxed` `:614`): replica mode, CHECKs dropped and re-added `NOT VALID`, committed, and noted |
| still refused | use pre-existing seeded rows as parents (`row/existing-parents`); `attribute` decides their owner |

A failure in one table marks only that table unpopulated, with the exact database error (`:1523`).

## 5.2 Probes (`src/supabase/probes.ts`)

**Who attacks whom.** The attackers are `anon`, tenant A and tenant B. A signed-in attacker's victim is the other tenant; anon's victims are both tenants (`victimsOf` `:69`).

**Grant gating.** A probe that uses a table verb (select, insert, update, delete) only runs when the actor's role holds that grant.

**Effects must be real.** An effect counts only when it is seen in the database, or in victim markers returned in a response. A `204` alone proves nothing.

| Probe | Line | Attack | Proof | Undo |
| --- | --- | --- | --- | --- |
| read sweep | `readSweep :74` | `GET /rest/v1/<rel>?select=*&limit=1000` on every table and view except shared ones | a victim marker in a row the attacker does not own | none needed |
| GraphQL | `:1816` | collection queries by victim primary keys, when pg_graphql is on; `public` only | markers; deduped against REST | none needed |
| user_metadata | `:1387` | for policies reading `user_metadata`, the attacker sets its own metadata to the victim's ids, then reads | victim rows appear | keys set to null |
| self-escalation | `:1441` | on the attacker's **own** row, set a trusted privilege column (`is_admin`, `role`, `access_level`) that a policy or function reads, when an update policy lets the user write their own row | the value is stored; then a new read sweep lists what it unlocked | `restoreColumns` |
| update | `:171` | PATCH the victim's row by primary key on a safe column | before and after compared in the database | restored as the owner |
| reparent | `:237` | point a foreign key on the attacker's own row at the victim's parent | the key changed; `victimCanSee` (a rolled-back read as the victim) sets the severity | restored |
| insert | `:282` | create rows whose foreign keys point at the victim's parents (up to 5 candidates) | `201` | deleted by marker or primary key |
| impersonation | `:344` | create rows that name the victim in the person column | the stored row is read back, so an owner-rewriting trigger does not count | deleted |
| functions | `rpcProbe :891`, `rpcProbeFunction :950` | call every exposed function with the victim's values | markers in the output (values the caller sent are ignored), or snapshot differences | rolled back |
| storage | `:1679` | each tenant uploads where the app would put the file; the other tries download, list, overwrite, upload into the victim's folder, delete | checked with the service role | files restored, test files deleted |
| delete | `:1588` | DELETE the victim's row by primary key, tables in reverse order | the row is gone | re-inserted as the owner |

### Functions

Functions are the hardest part. A call that changed nothing can mean either a working caller check or test values that missed.

**Which functions are called:**
- Skipped: trigger functions, non-volatile functions that return a boolean or nothing, and functions with unnamed arguments (these are listed in the notes).
- Only required arguments are sent.

**How a call is made:**
- **Stable and immutable functions** are called with `POST /rest/v1/rpc/<f>`.
- **Volatile functions** first get a read-only `GET` preflight, to confirm the API serves them. They are then called **in SQL**, the way PostgREST runs them: the API role, the caller's JWT claims, inside a transaction that is always rolled back (`callRolledBack` `:840`).

**How effects are found.** A snapshot is taken before the call and again after it, inside the same transaction (`snapshotStatements` `:725`). It covers:
- the victim's rows;
- rows in tenant tables pointing at the victim (up to 200 per table);
- every row of shared tables the body writes (up to 500).

`diffSnapshots` (`:796`) reports changed, deleted and new rows. It ignores rows that also carry the caller's own id.

**Derived values.** For calls aimed at the victim, the victim's ids are swapped for random ones. If the answer then differs, consistently, the function leaked something derived from the victim's data (`derivedValue` `:1098`).

**Owner control** runs when an attack changed nothing (`ownerControl` `:1355`). The victim makes the same calls on their own data. The function is **guarded** when the owner's call:

| Owner's call | Strategy id |
| --- | --- |
| changed their rows | `owner-control/changed` |
| returned their markers | `returned` |
| was accepted where the attacker was refused | `accepted` |
| failed differently from the attacker's call | `got-further` |

Otherwise the result is **no-effect**, and three follow-ups run:

1. **Secret gate** (`:1132`): the attacker sends the victim's real stored value for a text argument the body compares. An answer only for that exact value means **secret-gated**, which is never a finding.
2. **Victim removal** (`:1168`): for calls not aimed at the victim. Each answer is asked twice with the victim's rows and once without them, rolled back. A difference is a derived leak; no difference in a read-only body means **victim-independent**.
3. **Row state** (`rowStatePrime` `:1236`, `rowState` `:1311`): the scan parses the state the body waits for (`status = 'pending'`, `paid_at is null`, `credits > 0`, `< now()`, `IN` lists) and puts the owner's row in that state inside the rolled-back transaction. If the owner's call then works, the attacker's call is retried:
   - if the attacker's call also works, it is a primed `rpc-write`;
   - if not, the function is **guarded**.

   Maintenance by age is excluded (`timeMaintenance`, `src/core/job-shape.ts`).

Whatever is still open becomes **not tested** in triage, with a "check it yourself" prompt.

### Argument synthesis (`argValues` `:635`)

Each argument gets up to 12 values, with the victim's own values first.

**uuid arguments,** in this order:
1. the victim's user id, when the name looks like a person;
2. values from a column named like the argument;
3. values from columns the body compares the argument to;
4. primary keys of a table named after the argument;
5. ids from tables the body mentions;
6. every other victim id.

**Text arguments:**
- victim strings, but never secrets;
- for volatile functions, only markers and public text;
- well-known formats;
- the words `global` and `all`;
- the current month;
- literals the body compares the argument to.

**Numbers** (volatile functions only): limit and quota arguments get large values.

**Fallbacks by type:** enums, JSON `{}`, ranges, vectors, bytea, and whole rows through `json_populate_record`.

**How a call body is assembled:**
1. Insert tries (`:566`) map the arguments of an `INSERT ... VALUES (p_...)` to the victim's keys.
2. Row tries (`:490`) take coherent values from one victim row and its parents.
3. Then the zipped pools.

Each value's source is recorded as `args/*` marks.

### Observations and coverage

`observe()` (`:59`) records `{probe, target, actor, victim, facts, evidence}`. It fills `evidence.via` from the victim row's build marks when the probe gave none.

`track()` (`:47`) counts each request in coverage, as described in [04-data-model.md](04-data-model.md#how-coverage-is-counted).

### Execution model

**Sequential.** Everything runs on one `pg.Client`, one query at a time; the probes are not parallel.

**No timeouts.** There are no statement timeouts and no HTTP timeouts.

**Limits that bound a scan:**
- reads return at most 1,000 rows;
- ownership reads at most 5,000 rows a table;
- at most 3 pre-existing rows and 20 adopted rows per table;
- snapshots take at most 200 rows a table, and 500 for shared tables;
- at most 5 insert candidates;
- at most 4 owner and row-state tries;
- at most 12 values per argument;
- at most 12 attempts per row.

### Fix verification mode

With `TENANTBLEED_OWNER_CHECK=1`, `runProbes` also measures what each role can still do (`probes.ts:2145-2171`):
- `ownerAccessCheck` (`:2044`): each owner on its own rows;
- `accessAsRole` (`:2005`): a stranger, a coworker (joined with the least privileged role, `joinWorkspace` `:1914`) and an admin (`makeAdmin` `:1954`).

The results are `OwnerAccessRow`s for the fix verifier.

## 5.3 Introspection extras

- **Scanned schemas.** Exposed schemas come from `[api] schemas`, minus `graphql_public` and `storage`. Unexposed schemas named in function bodies are scanned too, so functions that write there can be judged (`scan.ts:115-124`).
- **Granted but unexposed.** Schemas that grant access to the API roles without being exposed get a note: they become reachable the day someone exposes them.
- **Helper bodies.** Bodies of functions in unscanned schemas are kept, so the judge can follow caller checks into them (`schema.helpers`).
