# Installation

tenantbleed runs entirely on your machine. There are no accounts, no API keys, and no network
calls off the box. This guide gets you from nothing to a first scan.

- [What you need](#what-you-need)
- [Install tenantbleed](#install-tenantbleed)
- [Point it at a project](#point-it-at-a-project)
- [Run your first scan](#run-your-first-scan)
- [Updating](#updating)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

## What you need

| Requirement | Why | Check |
| --- | --- | --- |
| Node 20 or newer | tenantbleed is a Node CLI | `node --version` |
| Docker | the Supabase CLI starts your local stack in containers | `docker info` |
| The Supabase CLI | starts and stops the local database and API | `supabase --version` |
| A local Supabase project | a folder with `supabase/config.toml` and your migrations | `ls supabase/config.toml` |

tenantbleed never touches a remote or production database. It needs a **local** Supabase
stack because it creates real test users and writes, updates and deletes rows to prove what a
real attacker could do.

If you do not have the Supabase CLI yet, follow Supabase's own install guide, then run
`supabase start` once inside your project to confirm the stack comes up.

## Install tenantbleed

You do not have to install anything. The fastest path is `npx`, which fetches and runs the
latest version:

```
npx tenantbleed ui
```

To install it once and keep it on your `PATH`:

```
npm install -g tenantbleed
tenantbleed --version
```

Either way you now have one command, `tenantbleed`, with these subcommands:

| Command | What it does |
| --- | --- |
| `tenantbleed ui` | opens the local web UI (recommended for a first look) |
| `tenantbleed supabase` | runs a scan headless, writes the report, exits non-zero on a finding |
| `tenantbleed fix` | prints the fix SQL for a saved report |
| `tenantbleed judge` | re-judges a saved scan's facts without touching the database |

## Point it at a project

Run tenantbleed from inside your Supabase project, or pass the path with `--workdir`:

```
cd my-app                        # the folder that contains supabase/
supabase start                   # bring the local stack up first
tenantbleed ui                   # then scan it
```

tenantbleed reads which schemas to scan from the `[api] schemas` line in your
`supabase/config.toml`. You can add an optional `tenantbleed.json` next to the `supabase/`
folder to mark shared tables or switch to single-workspace mode. See the
[user guide](user-guide.md#configuration) for the full set of options.

## Run your first scan

```
supabase start
tenantbleed ui
```

This prints a local URL with a one-time token and opens it in your browser:

```
tenantbleed UI is running at:
  http://127.0.0.1:7171/?token=...
```

Click **Start scan**. In a few seconds you get the Findings, Coverage, Check-yourself and
Export screens described in the [user guide](user-guide.md). Nothing leaves your machine, and
the UI never writes to your project or database: it only reads the scan result and shows you
fix SQL to copy.

Prefer the terminal? Run it headless:

```
supabase start
tenantbleed supabase --out tenantbleed-report
```

This writes `tenantbleed-report.md`, `.html` and `.json`, and exits non-zero if it proved a
finding, so it drops straight into a pre-push hook or a local CI step.

## Updating

With `npx` you always get the latest version, so there is nothing to update. With a global
install:

```
npm install -g tenantbleed@latest
```

## Uninstalling

```
npm uninstall -g tenantbleed
```

tenantbleed keeps no global state, config or cache outside your project folder, so that is all
there is to remove.

## Troubleshooting

**`tenantbleed: command not found`** after a global install. Your npm global `bin` directory
is not on your `PATH`. Run `npm bin -g` to find it, or just use `npx tenantbleed` instead.

**`no local Supabase project found`**. Run tenantbleed from the folder that contains
`supabase/config.toml`, or pass `--workdir path/to/project`.

**The scan cannot connect to the database.** Start the stack first with `supabase start`, and
confirm Docker is running with `docker info`.

**It refuses the target as non-local.** tenantbleed binds to loopback and only scans a local
stack. This is deliberate: the probes mutate data and must never run against a shared or
production database. Point it at your local Supabase stack.

**The UI shows "the interface is not built".** You are running from a source checkout without
a built SPA. Run `npm run build` first, or use the published package where the UI ships built.

See the [user guide](user-guide.md) for how to read a report, and
[CONTRIBUTING.md](../CONTRIBUTING.md) to run the planted-fixture suite.
