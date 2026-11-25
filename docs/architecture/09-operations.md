# 9. Deployment and operations

## 9.1 CLI (`dist/tenantbleed.mjs`)

```sh
supabase start                                # in the app's folder
node dist/tenantbleed.mjs supabase --workdir . --out tenantbleed-report --fail-on high
node dist/tenantbleed.mjs ui --workdir .      # the local web UI on 127.0.0.1
node dist/tenantbleed.mjs judge --input tenantbleed-report.input.json --out rejudged
node dist/tenantbleed.mjs fix --report tenantbleed-report.json --out tenantbleed-fixes
```

**Flags:**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--workdir` | `.` | the app folder |
| `--api-url`, `--db-url`, `--anon-key`, `--service-key`, `--jwt-secret` | | an explicit stack; otherwise the CLI uses `supabase status` |
| `--schemas` | | the schemas to scan |
| `--config` | | the config file to read |
| `--out` | `tenantbleed-report` | the report file prefix |
| `--fail-on` | `high` | the severity that fails the gate |
| `--triage` | `on` | `on` or `off` |
| `--allow-remote` | off | allow a non-local API URL, for a disposable preview branch |
| `--port` | `7171` | the loopback port for `ui` |
| `--report`, `--input` | | for `fix` and `judge` |

Any CI can run the `supabase` command headless and gate on its exit code; there is no hosted
service and no token.

## 9.2 The lab

Field-testing against real apps uses internal tooling and a corpus of open-source Supabase apps kept outside this public repo. It is not shipped.

## 9.3 Docker capacity (`scripts/lib/docker-lock.sh`)

Too many stacks at once has wedged Docker, so every job that starts stacks takes slots:

- The slot count is Docker's memory divided by 1.5 GiB, between 1 and 6. `TENANTBLEED_DOCKER_SLOTS` overrides it.
- A slot is an atomic `mkdir DOCKER.slots/<i>` with an owner file. A slot whose process is gone is taken over.
- Each slot has its own port prefix (`603 623 633 643 653 523`), so jobs never collide on ports.
- Taking `all` slots sets a drain marker, so the planted suite is not starved by single-app jobs.
- A legacy `DOCKER.lock` is kept in step for older scripts. A lock written by an older script blocks every slot.
- A status helper lists who holds what.

**Rules for operators:**
- Never remove another job's lock.
- Stop your own stacks with `supabase stop --no-backup`.
- Do not restart the Docker engine without the machine owner: it also restarts unrelated containers.
- Keep long runs awake. Nothing in the scripts calls `caffeinate`, and a sleeping Mac has hung the Docker engine for most of an hour. Run them under `caffeinate -i`.

## 9.4 Environment variables and debug switches

| Variable | Effect |
| --- | --- |
| `TENANTBLEED_SAVE_INPUT=1` | write `<out>.input.json` for re-judging |
| `TENANTBLEED_DEBUG_RPC=1` | log every function call, its arguments and its effect |
| `TENANTBLEED_DEBUG_WORLD=1` | log every test-row attempt, refusal and retry |
| `TENANTBLEED_OWNER_CHECK=1` | measure owner, coworker and admin access (for the fix verifier) |
| `TENANTBLEED_SUPABASE_VERSION` | the Supabase CLI version for `supabase status` |
| `TENANTBLEED_LAB` | the lab folder |
| `TENANTBLEED_DOCKER_SLOTS` | the slot count |
