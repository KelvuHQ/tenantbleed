# How tenantbleed works

A scan builds a small, realistic world inside a throwaway copy of your app, with two real users who each own their own data, then has each user (and an anonymous visitor) attack the other's data through the same APIs a browser uses. A finding exists only when an attack worked, confirmed in the database. This page describes every stage; the exact decision rules are in [rules.md](rules.md).

```
supabase start (your migrations)
  -> introspect the schema
  -> create test users
  -> build the world (test data owned by each user)
  -> work out who owns what
  -> run the probes (reads, writes, functions, storage, GraphQL)
  -> verify in the database, undo side effects
  -> static checks, severity rules, report
```

Source map: `src/cli.ts` and `src/engine/scan.ts` (orchestration), `src/supabase/introspect.ts` (schema), `src/supabase/world.ts` (users, test data, ownership), `src/supabase/probes.ts` (attacks, recorded as observations), `src/judge/observations.ts` (findings and severities), `src/judge/static.ts` (schema checks), `src/judge/triage.ts` (linter triage), `src/judge/report.ts` (report). The full code map and the development workflow are in [developer-guide.md](developer-guide.md).

## 1. The stack and the safety guard

- In CI the Action runs `supabase start` from your repo, so the database is exactly what your migrations produce, plus `seed.sql`.
- Connection details come from `supabase status`: API URL, database URL, anon key, service key, JWT secret.
- The scan refuses any API URL that is not local (`127.0.0.1`, `localhost`) unless `--allow-remote` is given for a disposable preview branch. It never needs production keys.

## 2. Introspection

From the Postgres catalogs (`src/supabase/introspect.ts`):

- **Relations** in the scanned schemas: tables and views, columns (type with modifiers, nullability, defaults, identity and generated columns, enum labels including for enum arrays), primary keys, foreign keys, CHECK constraints, and the table privileges of `anon` and `authenticated`.
- **Policies** from `pg_policies`: command, roles, `USING` and `WITH CHECK` expressions.
- **Functions** exposed through the API: argument names and types, how many have defaults, body, volatility, `SECURITY DEFINER`, return type, and whether `anon` and `authenticated` can execute them.
- **Exposed schemas** from `[api] schemas` in `config.toml`. Schemas that grant access to API roles but are not exposed are reported as a note (reachable the day someone exposes them).
- **Person columns from policies.** Many apps store `user_id uuid not null` without a foreign key and enforce ownership only in policies. A uuid column that the table's own policy compares with `auth.uid()`, directly or in a list (`auth.uid() IN (owner_id, member_id)`), and that is not a column of another table inside a subquery, is given an inferred foreign key to `auth.users` and treated exactly like a declared one.

## 3. Test users

- Two tenants, **tenant A** and **tenant B**, created through the Auth admin API and signed in with a password, so they hold real access tokens.
- **Signup refused** (invite-only allowlists, terms of service triggers, email domain rules): the user is created directly in `auth.users` with the signup trigger skipped for that one insert, and the rows that trigger would have created are built in the next stage. Noted in the report.
- **Email login disabled**: the session is signed with the local JWT secret with the same claims the auth server issues. Noted in the report.
- **Bystander**: a third account that is never an attacker or a victim. It is used only when a rule needs "another person", for example "a project owner cannot add themselves as a member". Its id is removed from the leak markers.
- All test users are deleted at the end.

## 4. Building the world

Every table is filled in foreign key order (parents first), once per tenant (`buildWorld` in `world.ts`).

**Reuse before create.** Rows that already exist for the tenant (created by signup or parent triggers) are adopted. Lookup tables that refuse new rows but were filled by migrations lend their pre-existing rows. Before creating a parent row for another person, an existing matching row is reused.

**Value generation** (`buildRow`, `sampleValue`):

- Person columns get the tenant's user id; other foreign keys point at the tenant's own parent rows, or at shared catalog rows.
- Text gets a unique **marker** such as `tp_tenanta_invoices_memo_1a2b3c4d`, so any appearance of it elsewhere is proof of a leak.
- Values respect the schema: varchar lengths, `IN (...)` lists and single-value checks, length checks, numeric ranges, enum labels, regular-expression checks (a generator produces strings that match patterns such as `^[0-9a-f]{64}$` or `^mcpc_[A-Za-z0-9_-]{20,80}$`), JSON, `bytea`, and vectors.
- Optional columns are left empty unless they are text (where markers go), numbers or vectors. A filled `deleted_at`, `archived_at`, lock flag or delete claim would turn a fresh record into an unusual one and hide it from policies or make triggers refuse its children.

**Insert strategy.** First through the API as the tenant (like the real app). If refused, as the database owner but with the tenant's JWT claims set, so triggers and `auth.uid()` defaults behave as for that user.

**When the database refuses a row**, the loop repairs and retries:

| Refusal | Repair |
| --- | --- |
| CHECK constraint (23514) | The **constraint solver**: read the failing constraint's definition, try each OR branch, set the columns that branch needs, and ask Postgres whether the whole constraint holds before inserting. Understood forms: `IS NULL`, `IS NOT NULL`, `col = 'x'`, `col = ANY(ARRAY[...])`, booleans, `a <> b` and `IS DISTINCT FROM`, `a > b` and `a < b` (dates, numbers, ordered id pairs), `(A) = (B)` and `(A) <> (B)` between conditions, regular expressions, `cardinality`, `<@ ARRAY[...]`, `jsonb_typeof`. If a trigger rewrites a column after the check, the next satisfying branch is tried. Last resort: leave optional columns that the constraint mentions empty. |
| Exclusion constraint (23P01) | Shift the row's dates by a year (no overlapping campaigns or bookings). |
| Overlapping multi-column foreign keys | When two composite keys share a column, for example `(project_id, user_id)` and `(workspace_id, user_id)`, each key is tried as the anchor; a matching parent row is reused or created for the pinned person (the bystander's own workspace). |
| A rule needs another person | Use the bystander account in the person column. |
| Triggers that guard user actions | Last resort: write the row as the app's backend would, with no signed-in user. Noted in the report. |
| Unique violation on a singleton | Not a gap: the other tenant already created the one allowed row. |

**Files.** If a table references `storage.objects`, each tenant first uploads a file to each bucket under their own user id; upload triggers run too, which is how some apps create those rows.

Anything that still cannot be filled is listed in the coverage section with the exact database error.

## 5. Who owns what

Ownership is worked out from the data, not from who created a row (`attribute` in `world.ts`):

1. A row with a person column (a foreign key, declared or inferred, to `auth.users` or to a profile table keyed by the user id) belongs to that user.
2. A membership row (person column and parent column both in the primary key) makes the parent belong to that user too.
3. A row that references an owned row belongs to the same owner, repeated until nothing changes.
4. A row that names **two different** test users (a block, a direct message, a chat between buyer and seller) belongs to neither, and no other rule can claim it.
5. Singleton tables (a boolean primary key, `CHECK (id)`) are configuration, not tenant data.
6. Tables with no path to a user, or listed under `shared`, are **shared** (catalogs, lookup tables).

**Leak markers (tokens).** For each tenant: its user id, every marker string in its rows, and the primary and foreign key uuids of its rows. Values both tenants share are removed. Values from a profile row are also tagged with their column, so a leak made only of public profile fields can be recognised.

## 6. Probes

Each probe runs as the anonymous visitor (anon key) and as each tenant against the other. Each probe is isolated: an error becomes a note in the report, never a lost report.

| Probe | What it does | Proof |
| --- | --- | --- |
| Read sweep | `GET` every exposed table and view. | The victim's markers in a row that does not belong to the attacker. |
| user_metadata | For policies that read `user_metadata`, set your own metadata (as any browser can) to the victim's ids and read again. | The victim's rows appear. |
| Update | `PATCH` the victim's row by primary key on a non-key column. | The row is compared in the database before and after (the API answers 204 either way), then restored. |
| Reparent | Rewrite the foreign key on your own row to point at the victim's parent. | The foreign key changed in the database; whether the victim can now see the row decides the severity. Restored. |
| Insert | Create rows whose foreign keys point at the victim's parents (up to five candidate parents). | `201`, plus whether the victim can see the new row. Removed. |
| Impersonation | Create rows that name the victim in the person column. | The stored row is read back, so a trigger that rewrites the owner does not count. Removed. |
| Functions | Call every exposed function with the victim's values. Read-only functions go through the API. Functions that can write run exactly as PostgREST runs them (API role, the caller's JWT claims) inside a transaction that is always rolled back, after a read-only `GET` confirms the API serves them. | Victim markers in the output (values the attacker sent are ignored), or, between snapshots taken before and after the call: victim rows that changed or disappeared, new rows pointing at the victim (unless they carry the caller's own id), and deleted or edited rows of shared tables the function writes. Text arguments get the scan's markers, values anyone can learn (slugs, handles, months), and for scope-like arguments the words `global` and `all`. |
| Storage | Each tenant uploads a file the way the app would (own folder first, with a content type the bucket accepts); the other tenant tries to download, list, overwrite, delete and upload into it. | Checked with the service role; files restored. |
| GraphQL | When `pg_graphql` is on, read every public table through `/graphql/v1` (introspection free). | Same marker check. Also catches `public` hidden from REST but still served by GraphQL. |
| Delete | `DELETE` the victim's row by primary key. | The row is gone in the database; then restored as the owner. |

**Settling functions that changed nothing.** A call that changed nothing can mean a caller check or test values that missed. The scan then makes the same call as the victim on their own data (a working caller check shows as "worked for the owner, not for the attacker"), tries the victim's stored value for lookups by a secret, compares the answer with and without the victim's rows for functions that take nothing aimed at a user, and, for functions that only act on rows in a given state (`status = 'pending'`, `paid_at is null`, `credits > 0`), puts the victim's row in that state inside the rolled-back transaction and repeats both calls. Cleanups by age are left out of that last step: making a row old first proves nothing about a cleanup. What is still open is reported as not tested. The order and rule ids are in [developer-guide.md](developer-guide.md#how-functions-get-a-conclusion).

**Function arguments.** Only required arguments are filled. Values come from the victim's data first (their ids, whole numbers from any column such as an order code, their marker strings), then a default by type: JSON `{}`, arrays of the victim's ids, enum labels, numbers, booleans, timestamps, and a fixed embedding vector that matches the vectors stored in test rows. Text arguments of functions that write get only the scan's own markers, never secrets such as invite tokens. Functions whose arguments have no names cannot be called through the API and are listed in the notes.

## 7. Static checks

From the schema alone (`static.ts`), in exposed schemas only:

- RLS disabled on a table the API roles can reach;
- views that run with their owner's privileges (no `security_invoker`);
- unconditional policies (`true`);
- policies that read `user_metadata`;
- `SECURITY DEFINER` functions callable through the API, graded by whether they check the caller.

An unconditional UPDATE, DELETE or ALL policy that no probe could exploit is marked **latent**: another policy masks it today.

## 8. Severity, report and exit code

- Severity starts from the kind of finding and the actor (anonymous is worse than signed in), then the precision rules in [rules.md](rules.md) adjust it with an explanation in the finding.
- `tenancy: "single"` lowers findings between signed-in users; otherwise a heads-up suggests it when most tables are shared between users.
- The Markdown report and JSON are always written, even if the scan stopped early.
- Exit code: `1` when a proven finding is at or above `fail-on`, `2` when the scan could not test anything, else `0`.

## 9. Linter triage

After the probes, the vendored splinter SQL runs in a rolled-back transaction with `pgrst.db_schemas` set to the scanned schemas. Every data-access warning is matched to the scan by its target (table, view, function or bucket):

1. **Proven:** a proven finding on the target.
2. **Extension:** the target belongs to an extension (PostGIS, pg_trgm), not the app.
3. **Not callable:** a trigger, a read-only yes/no helper, or a function with unnamed arguments.
4. **Locked:** RLS on with no policies.
5. **Shared, not reachable, or not tested:** from the coverage row.
6. **Flagged:** a static finding on the target.
7. **Tested:** none of the above.

Linter warnings never change severities or the exit code; they only order the report.

## 10. Fixes (preview)

`tenantbleed fix` maps each proven issue to a deterministic template. The main tool is a restrictive policy: Postgres ANDs it with the existing ones, so it can only narrow access.

The scope comes from the schema:

- **read, update, delete:** a protected parent's visibility, else the owner column;
- **insert:** both. Parents readable by everyone do not scope.

Issues no template can close safely go to "needs a human" with the reason.

The verifier rebuilds the database from migrations for each fix and re-scans. A fix is accepted only when:

- the attack fails;
- no new issue appears;
- every owner, workspace-member and admin operation that worked before still works.

Lost access that a stranger also had at baseline is listed for review instead of failing the fix. Checks that cannot be compared (the database rejects the test row itself, or the policy depends on the clock) are listed as "could not recheck".

## 11. Cleanup

Rows the probes changed are restored, rows they created are removed, functions that write never commit, test files are deleted, and test users are deleted. In CI the whole stack is destroyed with the runner.
