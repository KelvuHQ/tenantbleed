# tenantbleed roadmap

Status as of 18 November 2026. tenantbleed is a free, open-source, fully local tool. The roadmap is about coverage, adoption and docs, not monetization. Each item says whether it is done, next or later.

## Done

| Capability | Where | Notes |
| --- | --- | --- |
| **Proof engine** | CLI | Logs in as two real test users plus an anonymous visitor on a local stack and attacks each other's data: read, update, delete, insert, move rows between owners, impersonate, views, functions (read and write, rolled back) and storage buckets. Every finding is a working request, confirmed in the database. |
| **Local web UI** | CLI | Opens the report at a loopback URL (`http://127.0.0.1:7171/?token=...`) with a per-session token. Everything stays on the box. |
| **Test data that fits real schemas** | CLI | Solves CHECK constraints (equalities, ranges, NOT IN, regexes), signup triggers, membership tables and chains of foreign keys. 516 of 537 tables filled across the 39-app field test. |
| **Precision rules** | CLI | Shared-by-design tables, public filters, profile-only leaks, single-workspace apps and latent policies are recognised and reported at the right severity ([rules.md](../rules.md)). |
| **Linter triage** | CLI (on by default) | Runs Supabase's own linter (splinter) on the same database and labels every data-access warning: proven, tested and not exploitable, locked, shared, not reachable, or not tested with the reason. Example: 422 warnings on one app, 149 about data access, 17 proven. |
| **Fix generator (prototype)** | `tenantbleed fix` | One migration per fixable proven issue from deterministic templates: enable RLS with owner policies, restrictive owner-scoped policies, backend-only policy limited to `service_role`, `security_invoker` views, functions run as the caller or revoked from anonymous visitors, storage folders per owner. |
| **Fix verifier (prototype)** | `scripts/verify-fixes.mjs` | Applies each fix to a fresh local database and re-runs the attacks, then checks that the owner, a workspace member and an admin keep all their access. Writes a fix report: fixed and verified, rejected, needs a human (with reasons), review. 24 of 24 fixes verified on three apps, closing 81 of 126 proven issues. |
| **Field test** | Local lab | 39 open-source Supabase apps, 31 built, 12 with real proven bugs. Evidence in [validation.md](../validation.md). |

## Before any public benchmark

- **Private disclosures** to the 12 projects with proven bugs (drafts ready, not sent). Required before any public mention. All 12 notified; fixes or acknowledgements tracked. Apps are described by type only until then.

## Next: depth

1. **Verified fix pull requests.** Grow the fix prototype so it opens one pull request per verified fix in the user's own repo, showing the request that worked before, proof that it fails after, and the access check. Issues without a safe automatic fix stay in the report with the reason and an AI prompt. The developer reviews and merges; nothing is applied to production by tenantbleed.
2. **AI scenario builder.** An agent reads the app's code and writes the steps a real user goes through (accept an invite, share a project, replay a payment webhook). tenantbleed runs them with real accounts; the same deterministic probes decide what is a bug. AI builds the scenario; code proves the finding.
3. **Tenancy from JWT claims and session variables**, for apps that keep the tenant outside foreign keys.
4. **Edge functions and Realtime channels**, which are outside the database API today.

## Later: adoption and docs

5. **Adoption and docs.** A public benchmark (after disclosures), a two-minute getting-started guide, and worked examples, so more multi-tenant builders can run it on their own apps.

## Not planned

- Scanning hosted or production projects. tenantbleed creates users and writes data, so it only runs against local or disposable stacks.
- AI-written fixes applied without verification. Every proposed fix is re-attacked and access-checked first.
