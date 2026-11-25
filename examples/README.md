# Examples

The best examples of what tenantbleed finds are the planted-bug fixtures it tests itself
against, under [`../fixtures/`](../fixtures/). Each is a tiny, self-contained Supabase app
with known isolation bugs (and known-safe objects that must produce no finding), so you can
see a real leak get caught end to end.

| Fixture | Shows |
| --- | --- |
| `fixtures/supabase-vuln` | a spread of planted cross-tenant leaks across reads, writes and functions |
| `fixtures/supabase-hard` | harder cases: re-parenting, state-gated reads, constant-true helpers |
| `fixtures/supabase-team` | team and membership tenancy |
| `fixtures/supabase-workspaces` | two-person rows (chat, membership) built with a bystander |
| `fixtures/supabase-schemas` | tenancy and exposure across multiple schemas |
| `fixtures/supabase-managed` | a Supabase-managed schema the app exposed (and what the scan must not touch) |
| `fixtures/supabase-regress` | a regression set, including JWT-claim-scoped tenancy |

## Run one

With Docker and the Supabase CLI installed:

```
cd fixtures/supabase-vuln
supabase start
tenantbleed ui --workdir .        # then open the printed URL
# or headless:
tenantbleed supabase --workdir . --fail-on none
```

These apps carry deliberate bugs. They are for testing tenantbleed, not for copying into a
real project.
