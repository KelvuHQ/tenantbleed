# Contributing to tenantbleed

Thanks for your interest. tenantbleed is a security tool, so correctness and honesty come
before features: a single false positive costs more trust than many real findings earn.

## Setup

```
npm ci
npm run build          # typecheck, bundle the CLI, build the UI
npm test               # unit tests (no database needed)
```

Node 20+ is required. The engine's only runtime dependency is `pg`; React and Vite are dev
dependencies that build the UI into static files.

## The planted-fixture suite is the gate

Every behavior change must be backed by a fixture. The suite lives in `fixtures/`: each
folder is a tiny Supabase app with a `fixture.json` and a checker that asserts what must be
found and what must stay clean.

```
npm run test:fixtures   # scans every planted app in parallel and checks the results
```

This needs Docker and the Supabase CLI (it starts a local stack per fixture). The gate also
checks that every judge rule and test-data strategy in `scripts/rules.json` is exercised by at
least one planted case. A change cannot land if it misses a planted bug, raises a false
positive on a clean object, or leaves a rule unexercised.

When you fix a bug found on a real app, reproduce it as a planted fixture first, with neutral
names. Never add a real app's data or code.

## House rules

- **No real scanned-app names.** A pre-commit hook blocks any commit whose staged changes
  contain a scanned app's name or owner. Use neutral names (`acme`, `App-N`).
- **No em-dash or en-dash characters** in code or docs.
- Code identifiers and comments in English.
- Keep the runtime dependency surface small.

## Working on the UI

```
npm run dev:ui          # Vite dev server, proxies /api to a running `tenantbleed ui` on 7171
```

Run `tenantbleed ui` in one terminal (the API) and `npm run dev:ui` in another (the app with
hot reload). The UI shows and copies fixes; it never writes to the user's project or database.

## Pull requests

Keep each PR to one logical change. Describe what you changed and how you verified it (unit
tests and, for engine or judge changes, the fixture suite). Green `npm run check` is the bar.

## License of contributions

tenantbleed is licensed under the [GNU AGPL v3.0 or later](LICENSE.md). By submitting a
contribution, you agree that it is your own work and that it is licensed under the same AGPL,
with no additional terms (inbound equals outbound). The maintainer also offers tenantbleed
under a separate commercial license; by contributing, you agree your contribution may be
offered under those commercial terms as well.
