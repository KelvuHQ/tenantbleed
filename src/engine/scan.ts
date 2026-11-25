import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";
import type { JudgeInput } from "../core/judge-input.js";
import { traceReset, traceRows, trace } from "../core/trace.js";
import { query } from "../exec/sql.js";
import { createUserDirect } from "../exec/user.js";
import { extensionObjects, runSplinter, triggerFunctions } from "../lint/splinter.js";
import { SupabaseApi, type Actor, type Stack } from "../supabase/api.js";
import { exposedSchemasFromConfig, grantedButUnexposed, introspect } from "../supabase/introspect.js";
import { runProbes, PROBE_STEP_COUNT } from "../supabase/probes.js";
import type { ScanProgress } from "../core/progress.js";
import { functionGrantStatements, seedOnlyObjects, sourceIndex } from "../supabase/repo-hints.js";
import { scanTarget } from "./target.js";
import { buildWorld } from "../supabase/world.js";

/**
 * The scan as the engine runs it: start from a local stack, attack, collect facts. It decides
 * nothing; the judge turns these facts into findings in the same process.
 */

export interface ScanOptions {
  stack: Stack;
  workdir: string;
  /** Comma-separated schemas; default: [api] schemas from config.toml. */
  schemas?: string;
  /** tenantbleed.json path; default: <workdir>/tenantbleed.json. */
  config?: string;
  triage: boolean;
  /** Optional progress signal for a UI; ignored by the CLI. */
  onProgress?: ScanProgress;
}

// Coarse phases before and after the probe steps, for an overall progress bar.
const PROGRESS_PRE = 3; // introspect, create test users, build world
const PROGRESS_TOTAL = PROGRESS_PRE + PROBE_STEP_COUNT + 1; // + triage

export function fromStatus(workdir: string): Stack {
  const raw = execFileSync("npx", ["-y", `supabase@${process.env.TENANTBLEED_SUPABASE_VERSION ?? "2.122.1"}`, "status", "-o", "json"], { cwd: workdir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  const s = JSON.parse(raw.slice(raw.indexOf("{")));
  return { apiUrl: s.API_URL, dbUrl: s.DB_URL, anonKey: s.ANON_KEY, serviceKey: s.SERVICE_ROLE_KEY, jwtSecret: s.JWT_SECRET };
}

/** tenantbleed creates users and writes data: only local stacks, unless explicitly allowed. */
export function assertLocal(stack: Stack, allowRemote: boolean): void {
  const host = new URL(stack.apiUrl).hostname;
  if (!["127.0.0.1", "localhost", "0.0.0.0", "::1"].includes(host) && !allowRemote) {
    console.error(`Refusing to scan ${stack.apiUrl}: tenantbleed mutates data and only runs against local stacks. Pass --allow-remote for a disposable preview branch.`);
    process.exit(2);
  }

}

export async function collect(opts: ScanOptions): Promise<JudgeInput> {
  const started = Date.now();
  const { workdir } = opts;
  const progress = opts.onProgress;
  const configToml = join(workdir, "supabase", "config.toml");
  const exposedList = existsSync(configToml) ? exposedSchemasFromConfig(readFileSync(configToml, "utf8")) : undefined;
  const exposed = new Set(exposedList ?? ["public"]);
  const schemas = opts.schemas ? opts.schemas.split(",").map((s) => s.trim()) : [...exposed];
  const configPath = opts.config ?? join(workdir, "tenantbleed.json");
  const userConfig: { name?: string; shared?: string[]; tenancy?: "multi" | "single" } = existsSync(configPath) ? JSON.parse(readFileSync(configPath, "utf8")) : {};
  const shared = new Set((userConfig.shared ?? []).map((t) => (t.includes(".") ? t : `public.${t}`)));

  const stack = opts.stack;
  // bytea comes back in Postgres's own text form (\x followed by hex), not as raw bytes: test values
  // are compared and sent as text, and raw bytes with a zero byte make every such query fail.
  const db = new pg.Client({ connectionString: stack.dbUrl, types: { getTypeParser: (oid: number, format?: string) => (oid === 17 ? (v: string) => v : pg.types.getTypeParser(oid, format as "text")) } as pg.CustomTypesConfig });
  await db.connect();
  const api = new SupabaseApi(stack);
  const notes: string[] = [];
  const tenants: Awaited<ReturnType<SupabaseApi["createUser"]>>[] = [];
  const helpers: Actor[] = [];
  const toml = existsSync(configToml) ? readFileSync(configToml, "utf8") : "";
  // What the judge receives: facts only. Filled in as the scan goes; sent even if it aborts.
  traceReset();
  const input: JudgeInput = {
    v: 1,
    stack: "supabase",
    startedAt: new Date(started).toISOString(),
    durationMs: 0,
    target: scanTarget(workdir, join(workdir, "supabase", "migrations"), userConfig.name),
    schemas,
    exposed: [...exposed],
    schema: { relations: [], policies: [], functions: [] },
    tenants: [],
    world: { tenants: [], profileTokens: [] },
    observations: [],
    coverage: [],
    notes,
    probesFinished: false,
    hints: {
      seedOnly: seedOnlyObjects(workdir),
      functionGrants: functionGrantStatements(workdir),
      tenancy: userConfig.tenancy,
      migrationsDisabled: /^\[db\.migrations\][^[]*?^\s*enabled\s*=\s*false/m.test(toml),
      sources: sourceIndex(workdir),
    },
  };

  // The app's scheduled jobs (pg_cron) are paused while the scan runs: a job firing mid-scan could
  // change the test data, or send requests to the app's real services from the developer's machine.
  const paused = await pauseScheduledJobs(db);
  if (paused.length) trace("world/cron-paused", `${paused.length} job(s)`);
  if (paused.length) notes.push(`Paused ${paused.length} scheduled job(s) (pg_cron) while the scan ran, so none could change the test data or send requests; they were turned back on afterwards.`);

  try {
    for (const s of schemas) if (!exposed.has(s)) notes.push(`Schema "${s}" is not in [api] schemas of supabase/config.toml, so the Data API does not serve it. Its tables cannot be reached from a browser today; dynamic probes against it will show as unreachable.`);
    const unexposed = await grantedButUnexposed(db, schemas);

    // pg_graphql reflects the public schema through graphql_public even when REST does not expose public.
    const graphqlOn = (await query(db, "select 1 from pg_extension where extname = 'pg_graphql'")).rowCount;
    const graphqlExposed = !exposedList || /schemas\s*=\s*\[[^\]]*"graphql_public"/.test(readFileSync(configToml, "utf8"));
    if (graphqlOn && graphqlExposed && !exposed.has("public"))
      notes.push('The public schema is not exposed to REST, but /graphql/v1 still serves its tables (pg_graphql is installed and graphql_public is exposed). Scan with --schemas public to test what GraphQL can reach, or drop pg_graphql if unused.');

    let schema = await introspect(db, schemas);
    // Exposed functions often wrap tables in a schema the API does not serve (public.rename_account
    // over ledger.accounts). Those tables get test data too, so the functions can be called with real
    // ids; the API still cannot reach the tables themselves, so they are not attacked directly.
    const bodies = schema.functions.map((f) => f.body).join("\n");
    const wrapped = unexposed.filter((s) => new RegExp(`\\b"?${s}"?\\.`, "i").test(bodies));
    for (const s of unexposed)
      notes.push(
        wrapped.includes(s)
          ? `Schema "${s}" is not exposed, but functions the API serves use its tables, so the scan filled them with test data to call those functions. The tables themselves are not reachable from a browser today.`
          : `Schema "${s}" grants table access to API roles but is not exposed. Not reachable today; scan it with --schemas ${[...schemas, s].join(",")} after exposing it in a local copy of config.toml to see what would leak if it ever is.`,
      );
    for (const w of wrapped) trace("world/hidden-schema", w);
    if (wrapped.length) schema = await introspect(db, [...schemas, ...wrapped]);
    input.schema = schema;
    progress?.({ step: "inspect schema", done: 1, total: PROGRESS_TOTAL });
    for (const label of ["tenant A", "tenant B"]) {
      try {
        tenants.push(await api.createUser(label));
      } catch (e) {
        const msg = (e as Error).message;
        if (!/cannot create test user: 5\d\d/.test(msg)) throw e;
        tenants.push(await createUserDirect(db, api, label));
        if (!notes.some((n) => n.startsWith("Signup"))) trace("world/users-created-directly");
        if (!notes.some((n) => n.startsWith("Signup")))
          notes.push(`Signup refused the test users (${msg.replace(/^cannot create test user: /, "").slice(0, 160)}), so they were created directly in auth.users with the signup trigger skipped. Rows that trigger normally creates were built by the scan instead.`);
      }
    }
    if (tenants.some((t) => t.minted)) trace("world/session-signed-locally");
    if (tenants.some((t) => t.minted))
      notes.push("Email login is disabled in this project, so the test users' sessions were signed with the local JWT secret (same claims the auth server issues).");
    input.tenants = tenants.map((t) => t.label);
    progress?.({ step: "create test users", done: 2, total: PROGRESS_TOTAL });
    let bystanderId: Promise<string | undefined> | undefined;
    const bystander = () =>
      (bystanderId ??= (async () => {
        try {
          const b = await api.createUser("bystander").catch(() => createUserDirect(db, api, "bystander"));
          helpers.push(b);
          return b.userId;
        } catch {
          return undefined;
        }
      })());
    const world = await buildWorld(api, db, schema, tenants, { shared, bystander });
    progress?.({ step: "build world", done: PROGRESS_PRE, total: PROGRESS_TOTAL });
    if (process.env.TENANTBLEED_DEBUG_RPC) {
      const count = new Map<string, number>();
      for (const o of world.owned) count.set(`${o.owner} ${o.table}`, (count.get(`${o.owner} ${o.table}`) ?? 0) + 1);
      process.stderr.write(`WORLD ${[...count].map(([k, n]) => `${k}=${n}`).join(", ")}\nUNSCOPED ${[...world.unscoped].join(", ")}\n`);
    }
    if (process.env.TENANTBLEED_OWNER_CHECK) {
      const extra = async (label: string) => {
        try {
          const a = await api.createUser(label).catch(() => createUserDirect(db, api, label));
          helpers.push(a);
          return a;
        } catch {
          return undefined;
        }
      };
      world.extra = { coworker: await extra("coworker"), admin: await extra("admin") };
    }
    // The bystander's id shows up in both tenants' data by design; it is never evidence of a leak.
    const bid = bystanderId && (await bystanderId);
    if (bid) for (const set of world.tokens.values()) set.delete(bid);
    const probes = await runProbes(api, db, schema, world, progress, PROGRESS_PRE, PROGRESS_TOTAL);
    notes.push(...world.notes, ...probes.notes);
    for (const u of world.unscoped) trace("world/shared-table", u);
    if (world.unscoped.size) notes.push(`Treated as shared (no path to a user${shared.size ? ", or listed in tenantbleed.json" : ""}): ${[...world.unscoped].join(", ")}`);
    input.world = probes.world;
    input.observations = probes.observations;
    input.coverage = probes.coverage;
    if (probes.ownerAccess) input.ownerAccess = probes.ownerAccess;
    input.probesFinished = !probes.notes.some((n) => n.includes("stopped early"));
    progress?.({ step: "triage linter warnings", done: PROGRESS_PRE + PROBE_STEP_COUNT, total: PROGRESS_TOTAL });
    if (opts.triage) {
      try {
        input.lint = { rows: await runSplinter(db, schemas), triggerFunctions: await triggerFunctions(db), extensionObjects: await extensionObjects(db) };
      } catch (e) {
        input.lint = { error: (e as Error).message.split("\n")[0] };
      }
    }
  } catch (e) {
    notes.push(`Scan aborted: ${(e as Error).message}. Findings above are partial.`);
    input.aborted = true;
  } finally {
    await resumeScheduledJobs(db, paused);
    for (const t of [...tenants, ...helpers]) await api.deleteUser(t);
    await db.end().catch(() => {});
    input.durationMs = Date.now() - started;
    input.trace = traceRows();
    progress?.({ step: "done", done: PROGRESS_TOTAL, total: PROGRESS_TOTAL });
  }
  return input;
}

/** Active pg_cron jobs, paused; their ids, to turn back on. None when pg_cron is not installed. */
async function pauseScheduledJobs(db: pg.Client): Promise<number[]> {
  try {
    if (!(await query(db, "select to_regclass('cron.job') is not null as ok")).rows[0].ok) return [];
    const r = await query(db, "select jobid from cron.job where active order by jobid");
    const ids = r.rows.map((x) => Number(x.jobid));
    for (const id of ids) await query(db, "select cron.alter_job($1, active := false)", [id]);
    return ids;
  } catch {
    return [];
  }
}

async function resumeScheduledJobs(db: pg.Client, ids: number[]): Promise<void> {
  for (const id of ids) await query(db, "select cron.alter_job($1, active := true)", [id]).catch(() => {});
}
