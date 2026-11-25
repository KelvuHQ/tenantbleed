# tenantbleed rules

Every decision the scan makes, in one place: what counts as a finding, how severe it is, what lowers or raises it, how ownership and coverage are decided, and what is never reported. Each rule exists because a real app in the field test needed it; the case that motivated it is named so the rule can be re-checked. For the mechanics see [how-it-works.md](how-it-works.md); for the evidence behind each rule see [validation.md](validation.md).

## Principles

1. **Proof, not suspicion.** A finding needs a request that worked, confirmed in the database. Status codes are never trusted alone.
2. **Deterministic.** The same app gives the same findings on every run. No AI decides anything.
3. **Never clean by omission.** What could not be tested is listed with the reason.
4. **Lower, never hide.** Precision rules lower a severity and say why; they do not delete a proven finding. The only exceptions are listed under [Not findings](#not-findings).
5. **Generic.** No rule names a specific app, table or column. Rules follow from the schema, the policies and the data.

## Finding kinds and base severity

"Anon" is a visitor with no account (the public anon key). "Tenant" is a signed-in test user attacking the other.

| Kind | Proven when | Anon | Tenant |
| --- | --- | --- | --- |
| `anon-read` / `cross-tenant-read` | A read returns rows carrying the victim's markers. | critical | high |
| `view-leak` | Same, through a view (views run as their owner unless `security_invoker`). | critical | high |
| `cross-tenant-update` | The victim's row changed in the database after a `PATCH` by key. | critical | high |
| `cross-tenant-delete` | The victim's row is gone after a `DELETE` by key. | critical | high |
| `cross-tenant-insert` | A row pointing at the victim's parent was accepted. | critical | high |
| `cross-tenant-reparent` | Your own row's foreign key was moved to the victim's parent (missing `WITH CHECK`). | n/a | high |
| `impersonation-insert` | A stored row names the victim in its owner or author column. | n/a | medium |
| `rpc-leak` | A function returned the victim's markers that the attacker did not send. | critical | high |
| `rpc-write` | A function changed or deleted the victim's rows, or created a row pointing at the victim that does not carry the caller's own id (measured inside a rolled-back transaction). | critical | high |
| `rpc-write` (shared data) | A function deleted or edited existing rows of a table that belongs to no tenant (an audit log, global counters). New rows there (a log entry) are normal and not counted. Time-gated, no-argument cleanups are low. | high | medium |
| `metadata-escalation` | Editing your own `user_metadata` unlocked the victim's rows. | n/a | critical |
| `self-escalation` | A user set a privilege column the app trusts (`is_admin`, `is_staff`, `role`) on their own row through the API, and the stored row kept it. Trusted means a policy on that table, or a policy or function that names the table, reads the column. Critical when other users' rows then become readable; medium when the value is stored but nothing opens to a plain read. The row is put back. | n/a | critical or medium |
| `static/shared-open-write` / `static/shared-anon-read` | A shared table (no path from its rows to a user) whose policies let everyone, or every signed-in user, read or write it. Open write: medium, or high when a visitor can write. Open anon read of personal or financial columns (email, phone, tax id, balance): high. So the access is not silent in the report; confirm it is an intended public or staff-shared table. | n/a | medium or high |
| `read-state` / `read-state/sensitive` | A read a policy opens once a parent row (or the row itself) is in a normal state (`status = 'published'`, `listing.state = 'live'`). The scan set the victim's parent to that state, reread as another tenant and as a visitor, saw the rows, then restored it. Low or medium when the columns are not identifying (a public count may be intended); medium or high when they include person, order, contact or financial fields. | n/a | low to high |
| `self-enrollment` | An insert policy let a user add their own row with a privileged value (`role = 'admin'`, `is_admin = true`) in another tenant, because the self-branch never checked the parent is theirs. Proven by inserting the row as one tenant in another tenant's parent, then reading back. Critical when other tenants' rows then open to a read; high when only the privileged row is stored. The row is removed. | n/a | critical or high |
| Storage read or list (private bucket) | Download or listing returned the victim's file. | critical | high |
| Storage overwrite / delete | The victim's file changed or disappeared (checked with the service role). | critical | high |
| Storage upload into victim folder | An upload into the folder that holds the victim's files succeeded. | high | medium |

GraphQL reads follow the read rules; when REST already proved the same leak, the existing finding is marked "also reachable through GraphQL".

## Precision rules (lower, with the reason in the finding)

| Rule | Effect | Applies to | Why (case) |
| --- | --- | --- | --- |
| **Open read policy**: SELECT policy is `true`, `auth.role() = 'authenticated'`, `auth.uid() IS NOT NULL` or the JWT role check. | Tenant medium, anon high. | Reads. | A stated decision, not a forgotten check (public chat, directory). |
| **Public filter**: a SELECT policy that never looks at the caller (no `auth.*`, JWT, `current_setting`, `current_user`), such as `is_active AND now() BETWEEN starts_at AND ends_at`. | Same as open read policy. | Reads only. Never used to excuse a write. | Active-campaign price banner, published courses. |
| **Shared space parent**: the parent of an insert or reparent is readable by everyone through an open read policy (strict forms only). | Low. | Inserts and reparents. | Posting in a public channel. |
| **Victim cannot see it**: after a cross-tenant insert or reparent, the victim, as themselves, cannot read the resulting row. | Low, "cross-tenant reference, not an injection". | Inserts and reparents. | Chat rows pointing at another user's workspace but only visible to the author (35 cases in one field-test pass). |
| **Profile fields only**: every leaked value comes from another user's profile row (name, avatar, bio, their id) and no field looks personal. | Tenant low, anon medium. | Reads and function leaks. | Chat partner lists, public profiles, author names. Never applies when the response contains the victim's sign-in email or any filled field named like email, phone, mobile, address, street, zip, postal, birth, dob, ssn, tax, passport, national, salary, iban, card, location or geo. |
| **Counters only**: a function's only change to the victim's rows is counters or timestamps (`*_count`, `*_total`, `updated_at`, `last_*`, `*_at`). | Low, "side effect of a normal action". | Function writes. | Buying someone's course raises their enrollment count. |
| **Membership without consent**: impersonation on a membership table (name contains member, participant, collaborator, account_user, team_user, user_role, seat, or the person column and a parent column are in the primary key). | Low. | Impersonation. | Admins adding people to their own team. |
| **Public bucket listing**: listing the victim's files in a public bucket. | Low. | Storage. | Avatars bucket; files are public by URL anyway. |
| **Upload not visible to the victim**: the planted file does not show up when the victim lists their folder. | Low. | Storage uploads. | Upload policies that accept any uuid folder but reads limited to the uploader. |
| **Public by name**: the open read policy's own name says the rows are public ("Public can view all roadmap items", "anyone can read"). | Low. | Reads. | Public roadmaps, published reviews. Never applies when the leaked rows carry a filled field named like email, phone, address, birth, tax, iban, card, location, token, secret, password or key: "Public profiles are viewable by everyone" exposing emails keeps its severity, and the finding names the columns. |
| **Public branch**: one OR branch of a SELECT policy is a plain column filter (`is_active = true OR creator_id = auth.uid()`). | Same as open read policy. | Reads only. | Marketplace of published apps. Branches that call a function, run a subquery or use EXISTS are never treated as public, because they may check the caller inside. For anonymous reads the branch must also say public in its value (public, published, active, visible, listed, approved): `scope = 'workspace'` read by anyone without an account keeps its severity. |
| **Backend-only by name**: an open policy named for the service role or the backend but without `TO service_role`. | No discount: full severity, with the explanation. | Reads. | "Service role can manage API keys" with `USING (true)` for every role. |
| **Seed only**: the table or function is created by the seed file (`[db.seed]`, default `supabase/seed.sql`) and by no migration. | Low, with the reason. | All kinds. | A "reset this app's data" helper defined only in seed.sql; seed files run on local and branch databases, not production. |
| **Time-based cleanup**: a function with no arguments whose writes are gated on the clock (`now()`, intervals) and that never reads the caller. | Low, "can run the cleanup early". | Function writes. Its reads keep their severity. | Clearing expired device codes. The caller cannot choose whose rows change. |
| **Cache refresh**: every row the function changed is in a cache or rollup table (by name), and it takes no argument that could carry a value (only ids, dates or flags). | Low, "can make it refresh cached values". | Function writes on a tenant's rows. Its reads keep their severity. | A usage check that recomputes an organization's cached usage from its own data. The caller cannot choose the numbers. |
| **Ids only**: a function returned only the victim's record ids, none of their data. | Low. | Function leaks. | A membership check that answers with a member id. |
| **Value about the victim** (`rpc-leak/derived-value`): a function's answer for the victim's id differs from its answer for an id that exists nowhere, both asked twice, ids sent in blanked out, refusals ignored. For a function that takes nothing aimed at the victim: the caller's answer changes once the victim's rows are left out (a rolled-back transaction). | Low. | Function leaks with no marker in the answer. | A member count, a plan name, or `is_team_member(team, user)` that anyone can ask about anyone; a total over every account. A random or clock-based answer never counts. |
| **Independent of other users** (`triage/function-victim-independent`): a function that only reads and takes nothing aimed at the victim gives the caller the same answer with and without the victim's rows, twice. | Tested, no finding. | Function warnings with no conclusion. | "My own count" functions. Never for functions that write: a cleanup reaches old rows later. |
| **Latent policy**: an unconditional UPDATE, DELETE or ALL policy that no probe could exploit. | Low, "(latent)". | Static checks. | Masked by a stricter SELECT policy; becomes exploitable the day SELECT is loosened. |
| **Single workspace** (`tenancy: "single"`): findings between signed-in users. | Low. Anon findings keep their severity. | All user-to-user kinds. | Company intranet where coworkers share everything on purpose. |

## Explanations added to findings (no severity change)

- **Default grants**: a function the migrations grant only to some roles (`GRANT EXECUTE ... TO authenticated, service_role`) or revoke from `PUBLIC`, but never revoke from `anon` or `authenticated` by name, keeps Supabase's default EXECUTE grant to both. When a probe proves such a function callable by a role the author left out, the finding says so and gives the exact `revoke`.

## Not findings

These are never reported as leaks, because they are not evidence of one:

- **Echoes**: values the attacker sent coming back in a function's output (formatters, "create" functions returning their input).
- **Shared values**: tokens both tenants share, and the bystander's id.
- **Rows naming both test users** (blocks, direct messages, a chat between buyer and seller): they belong to neither tenant, even if a per-user row such as a read receipt points at them.
- **The attacker's own rows**: a row that belongs to the attacker is never evidence, even when it mentions the victim (a notification about a trade on the victim's listing).
- **Shared tables**: catalogs with no path to a user, singleton configuration tables, and anything listed under `shared` in `tenantbleed.json` (for functions: their reads; writes are still checked).
- **Owner rewritten by a trigger**: an impersonation insert whose stored row names the caller after all.
- **Unreachable objects**: tables with no API grants, schemas not exposed, functions the API does not serve (checked with a read-only `GET`), functions with unnamed arguments, trigger functions, and objects owned by an extension (reported as the extension's in the linter triage).

## Static checks

| Check | Severity |
| --- | --- |
| RLS disabled on a table the API roles can reach | high |
| View without `security_invoker` | medium |
| Unconditional policy (`true`) on a write | high (low when latent) |
| Unconditional SELECT policy | low |
| Policy whose whole condition is a call to a helper that always returns `true` (a placeholder like `is_org_member()` that is `RETURN true`, up to three calls deep): the table looks isolated but is not | high on a write or if anon can read, else medium |
| Policy reads `user_metadata` | high |
| `SECURITY DEFINER` function that writes to `auth.*` | high if anon can call it, else medium |
| `SECURITY DEFINER` function, callable through the API, that runs a text argument as SQL (`EXECUTE q`, glued in with `||`, or `format()` with `%s`; quoted names and values and `USING` binds do not count) | critical, flagged even when no call shows it |
| `SECURITY DEFINER` function, callable through the API with no caller check, that weakens access control (disables or un-forces RLS, drops or alters a policy, grants table rights to anon, authenticated or public), even with a quoted table name | critical, flagged |
| `SECURITY DEFINER` function that sends HTTP requests with no caller check | critical with a service role key in the function, else high if anon can call it, else medium; flagged |
| `SECURITY DEFINER` function that returns a value read from `vault.decrypted_secrets` with no caller check | high if anon can call it, else medium; flagged |
| `SECURITY DEFINER` function that checks the caller or returns a boolean | info. A caller check is `auth.uid()`, `auth.jwt()`, `auth.role()`, `current_setting('role')`, the request JWT claims or headers, `current_user`, or a call (up to three deep, including functions in unscanned schemas such as `private`) to a function that has one. |
| `SECURITY DEFINER` function that only reads and cannot be aimed at one user (no arguments, or a single number behind a login) | info |
| Other `SECURITY DEFINER` function callable through the API | medium if anon can call it, else low |

Static findings explain the proven ones; they never count toward `fail-on` on their own unless you set it to `low`.

## Ownership rules

- **Person column**: a foreign key to `auth.users`, a foreign key to a profile table keyed by the user id, or a uuid column that the table's own policy compares with `auth.uid()`, either directly (`user_id = auth.uid()`) or as one of several allowed people (`auth.uid() IN (owner_id, member_id)`). Inferred columns are treated like declared foreign keys. Multi-column keys are not person columns.
- **Profile table**: a single-column primary key that is a person column.
- **Membership**: person column and parent column both in the primary key; the parent then belongs to that person.
- **Propagation**: a row referencing an owned row belongs to the same owner.
- **Ambiguous rows**: a row naming two different test users belongs to neither, and no other rule (membership, propagation) can give it an owner.
- **Singletons**: a boolean primary key means configuration, never tenant data.
- **Shared**: no path to a user, or listed under `shared`.

## Coverage rules

- A tenant table counts as **tested** when it holds test data for both tenants and at least one API request reached it.
- **Gap**: no valid test data could be created, or the API answered 404/406 for it. Each gap is listed with the exact reason. A report with gaps never says clean.
- **No API access**: neither `anon` nor `authenticated` has any privilege on it. Counted separately; this is the safe outcome.
- **Shared by design**: counted separately.
- **Staff lists are never filled**: a table named like admins, moderators, superusers, staff or operators, keyed only to the user and consulted by the app's own policies or functions, gets no rows for the test users. Making them staff would let them see everyone's data by design. It is listed as a gap with that reason.
- **Nothing to scan**: when the exposed schemas have no tables, views or functions (for example `[db.migrations] enabled = false`), the report says so and exits 2. It never says clean.
- **Buckets**: tested when each tenant holds a file in it.
- **Functions**: tested when the API serves them and the probe could build their required arguments; otherwise listed in the notes.

## Changing a rule

Every rule change is re-run against the planted test app (20 of 20 proven, 0 false positives) and the full field-test corpus, and compared project by project with the previous results before it ships. See [validation.md](validation.md).
