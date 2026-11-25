# tenantbleed

**Prove your Supabase tenants are isolated. Do not guess.**

tenantbleed creates two real tenants in your local Supabase, lets each populate its own
data through the API, then attacks across the boundary (reads, writes, re-parenting,
function calls, self-escalation) and checks the database to see what actually happened.
Every finding comes with the exact request, the leaked row or before/after values, and a
`curl` to reproduce it, plus a suggested fix and a prompt you can paste into an AI coding
tool.

Linters tell you a Row Level Security policy *exists*. tenantbleed tells you whether it
actually *isolates* one customer from another, by trying the attack.

```
npx tenantbleed ui
```

Opens a local web UI at `http://127.0.0.1:7171`. Or run it headless:

```
npx tenantbleed supabase            # scan, write the report, exit non-zero on a finding
```

> **This writes to your database.** The scan creates test users and inserts, updates and
> deletes rows. Point it at a local dev or staging database, never production. tenantbleed
> binds to loopback only and refuses non-local targets.

## What it checks

| Probe | What it tries |
| --- | --- |
| Cross-tenant and anonymous reads | reads every table, view and function as anon, tenant A and tenant B, looking for the other tenant's rows |
| Cross-tenant update / delete | targets the other tenant's row by primary key, then reads the database back (status codes lie) |
| Cross-tenant insert | inserts rows whose foreign keys point at the other tenant's parent rows |
| Re-parenting | rewrites the foreign key on its own row to move it into another tenant (a missing `WITH CHECK`) |
| Impersonation | creates rows that name the other tenant as owner or author |
| Function leaks and writes | calls exposed functions with the other tenant's ids; write functions run exactly as PostgREST runs them, in a transaction that is rolled back |
| Self-escalation / self-enrollment | tries to make itself an admin, or add itself to another organization, by editing its own record |
| `user_metadata`, storage, GraphQL | metadata escalation, cross-tenant bucket access, and `/graphql/v1` reads when `pg_graphql` is on |

Every proof is deterministic: two real accounts, real HTTP requests, and the result checked
in the database. No AI decides whether something leaked.

## What it does not do

- It does not run against production, ever. The probes mutate data; the target must be local.
- It does not test application-server logic, edge functions or realtime (database API only).
- It does not mint JWT claims or session variables yet: a table scoped by a claim is reported
  as tenant-scoped but not attacked, so it is never silently called "safe".
- It is honest about all of this. The report's Coverage section lists what was tested and what
  was not, and why. A report never says "clean" when coverage is incomplete.

## The UI

`tenantbleed ui` serves a local single-page app:

- **Scan** the detected local project, with a live probe-by-probe progress view.
- **Status**: where the project stands right now, in two columns. What is holding (tested and
  not crossed into) and what needs fixing, each object described by its most serious finding.
- **Findings**, most severe first. Each row leads with a plain-language title over the exact
  evidence (the leaked status code, verb, who reached whom, and the object), and opens to the
  full request and response, where to fix, standards tags, the fix SQL and an AI-fix prompt
  (copy only; the UI never writes to your project or database). Search, filter by severity or
  verb, copy every fix at once, and deep-link to a single finding.
- **Coverage**: every reachable object with a clean or breached result, what was and was not
  tested, and why.
- **Check yourself**: linter warnings the scan could not settle, each with a plain prompt.
- **Export**: download the report as HTML, Markdown or JSON.
- **History**: every scan of a project is saved on your machine, so you can reopen an old
  report and watch the proven count move as you fix things.

A light/dark toggle sits in the masthead. Everything runs on your machine. There are no
accounts and no network calls off the box.

## Install

```
npm install -g tenantbleed     # or use npx, no install
tenantbleed ui
```

Requires Node 20+ and a local Supabase project (a folder with `supabase/config.toml`) with
the local stack running.

## Configuration

Optional `tenantbleed.json` next to your `supabase/` folder:

```json
{ "shared": ["public.channels", "public.messages"], "tenancy": "multi" }
```

- `shared` lists tables and functions that are public by design (a chat, a directory, a
  storefront). They still get test data but are not treated as tenant data.
- `tenancy` is `"multi"` (default) or `"single"` for one-workspace apps where every signed-in
  user is a coworker.

Schemas default to the `[api] schemas` in `supabase/config.toml`. Each scan also triages
Supabase's own linter (splinter), labeling every data-access warning with what the attacks
showed. Turn it off with `--triage off`. splinter is vendored under its PostgreSQL License
(`src/lint/SPLINTER-LICENSE`).

## How it is verified

tenantbleed ships a suite of planted-bug fixtures under `fixtures/`: tiny Supabase apps with
known isolation bugs, plus clean objects that must produce no finding. Every release must find
every planted bug, raise zero false positives, and exercise every judge rule. See
[CONTRIBUTING.md](CONTRIBUTING.md) to run the suite.

## Documentation

- [Installation guide](docs/installation.md)
- [User guide](docs/user-guide.md)
- [How it works and the architecture](docs/architecture/)
- [The open-source design](docs/design/open-source-ui.md)
- [Security model](SECURITY.md)

## License

[GNU AGPL v3.0 or later](LICENSE.md). Copyright 2026 The tenantbleed Authors. tenantbleed is
free and open source: use, study, modify and share it. If you run a modified version as a
network service or distribute it, the AGPL requires you to make your source available under
the same license.

Commercial licensing, to use tenantbleed in a closed product or service without the AGPL
obligations, is available: kelvu.sec@gmail.com.

Contributions welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

The vendored splinter linter keeps its own PostgreSQL License
(`src/lint/SPLINTER-LICENSE`).
