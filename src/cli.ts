#!/usr/bin/env node
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { gateExitCode, type Severity } from "./core/findings.js";
import type { ScanResult } from "./core/scan-result.js";
import { assertLocal, collect, fromStatus } from "./engine/scan.js";
import { generateFixes, migrationFor } from "./fix/generate.js";
import { judge } from "./judge/index.js";
import { toMarkdown } from "./judge/report.js";
import { toHtml } from "./judge/html.js";
import { startServer } from "./ui/server.js";
import type { Stack } from "./supabase/api.js";
import { exposedSchemasFromConfig, introspect } from "./supabase/introspect.js";
import pg from "pg";

const USAGE = `tenantbleed supabase [options]   run a scan and write the report
tenantbleed ui [--port 7171] [--no-open]   open the local web UI
tenantbleed fix --report <scan.json>        write fix migrations for a scan
tenantbleed judge --input <facts.json>      re-judge saved facts (no database)

Proves tenant isolation on a LOCAL or CI Supabase stack. It creates test users, writes,
updates and deletes data, so never point it at production.

  --workdir <dir>      project dir; reads connection details from "supabase status" (default: .)
  --api-url, --db-url, --anon-key, --service-key   explicit connection instead of --workdir
  --jwt-secret <s>     local JWT secret, used only when the app disables email login
  --schemas <list>     comma-separated schemas to scan (default: [api] schemas from supabase/config.toml)
  --config <file>      tenantbleed.json with { "shared": ["public.channels"] } (default: <workdir>/tenantbleed.json)
  --out <prefix>       write <prefix>.md and <prefix>.json (default: tenantbleed-report)
  --fail-on <sev>      exit 1 when a proven finding is at least this severe (default: high; "none" to never fail)
  --triage <on|off>    run Supabase's linter (splinter) on the same database and label each
                       data-access warning with what the scan proved (default: on)
  --allow-remote       allow a non-local API URL (only for disposable preview branches)
`;

/**
 * tenantbleed fix --report <scan.json> [--out <dir>]: write one migration per fixable proven issue,
 * plus fixes.json describing what each closes and what was skipped and why. Verification (re-scan
 * with the rightful-owner check) is done per fix by applying the migration to a fresh stack.
 */
async function fixCommand(workdir: string, reportPath: string | undefined, outDir: string, schemasOpt?: string) {
  if (!reportPath) {
    console.error("tenantbleed fix: --report <scan.json> is required");
    process.exit(2);
  }
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as ScanResult;
  const stack = fromStatus(workdir);
  const configToml = join(workdir, "supabase", "config.toml");
  const exposed = (existsSync(configToml) ? exposedSchemasFromConfig(readFileSync(configToml, "utf8")) : undefined) ?? ["public"];
  const schemas = schemasOpt ? schemasOpt.split(",").map((x) => x.trim()) : exposed;
  const db = new pg.Client({ connectionString: stack.dbUrl });
  await db.connect();
  try {
    const schema = await introspect(db, schemas);
    const { fixes, skipped } = generateFixes(report.findings, schema);
    mkdirSync(outDir, { recursive: true });
    for (const f of fixes) writeFileSync(join(outDir, `${f.id}_${f.target.replace(/[^a-z0-9]+/gi, "_")}.sql`), migrationFor(f));
    writeFileSync(join(outDir, "fixes.json"), JSON.stringify({ fixes, skipped }, null, 2));
    console.log(`${fixes.length} fix(es) written to ${outDir}; ${skipped.length} finding(s) skipped`);
  } finally {
    await db.end().catch(() => {});
  }
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      workdir: { type: "string", default: "." },
      "api-url": { type: "string" },
      "db-url": { type: "string" },
      "anon-key": { type: "string" },
      "service-key": { type: "string" },
      "jwt-secret": { type: "string" },
      schemas: { type: "string" },
      config: { type: "string" },
      out: { type: "string", default: "tenantbleed-report" },
      "fail-on": { type: "string", default: "high" },
      "allow-remote": { type: "boolean", default: false },
      triage: { type: "string", default: "on" },
      help: { type: "boolean", default: false },
      report: { type: "string" },
      input: { type: "string" },
      port: { type: "string" },
      "no-open": { type: "boolean", default: false },
    },
  });
  if (positionals[0] === "ui") {
    const running = await startServer({ workdir: values.workdir!, port: values.port ? Number(values.port) : undefined });
    process.stdout.write(
      `\ntenantbleed UI is running at:\n  ${running.url}\n\n` +
        `This scan creates test users and writes, updates and deletes rows.\n` +
        `Point it at a LOCAL dev or staging database, never production.\n\n` +
        `Press Ctrl+C to stop.\n`,
    );
    if (!values["no-open"]) openBrowser(running.url);
    return; // the listening server keeps the process alive
  }
  if (positionals[0] === "judge") {
    // Re-judge a saved facts file (written by a scan run with TENANTBLEED_SAVE_INPUT). Judging
    // runs in the same process as the engine; this command lets a judge change be replayed
    // against saved facts without a database, and backs the judge tests.
    if (!values.input) throw new Error("tenantbleed judge --input <file.input.json> [--out <prefix>] [--fail-on <sev>]");
    finish(judge(JSON.parse(readFileSync(values.input, "utf8"))), values.out!, values["fail-on"] as Severity | "none");
    return;
  }
  if (positionals[0] === "fix") {
    await fixCommand(values.workdir!, values.report, values.out === "tenantbleed-report" ? "tenantbleed-fixes" : values.out!, values.schemas);
    return;
  }
  if (values.help || positionals[0] !== "supabase") {
    process.stdout.write(USAGE);
    process.exit(values.help ? 0 : 2);
  }

  const stack: Stack =
    values["api-url"] && values["db-url"] && values["anon-key"] && values["service-key"]
      ? { apiUrl: values["api-url"], dbUrl: values["db-url"], anonKey: values["anon-key"], serviceKey: values["service-key"], jwtSecret: values["jwt-secret"] }
      : fromStatus(values.workdir!);

  assertLocal(stack, !!values["allow-remote"]);

  const input = await collect({ stack, workdir: values.workdir!, schemas: values.schemas, config: values.config, triage: values.triage !== "off" });
  // Lab runs keep the collected facts, so judging changes can be replayed with `tenantbleed judge --input`.
  if (process.env.TENANTBLEED_SAVE_INPUT) {
    mkdirSync(dirname(values.out!) || ".", { recursive: true });
    writeFileSync(`${values.out}.input.json`, JSON.stringify(input));
  }
  finish(judge(input), values.out!, values["fail-on"] as Severity | "none");
}

/** Write the report, print it, and set the exit code from the build gate. */
function finish(result: ScanResult, out: string, threshold: Severity | "none") {
  const md = toMarkdown(result);
  mkdirSync(dirname(out) || ".", { recursive: true });
  writeFileSync(`${out}.md`, md);
  writeFileSync(`${out}.html`, toHtml(result));
  writeFileSync(`${out}.json`, JSON.stringify(result, null, 2));
  process.stdout.write(md + "\n");
  process.exitCode = gateExitCode(result, threshold);
}

/** Open a URL in the default browser; best effort, never fatal. */
function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    execFile(cmd, args, () => {});
  } catch {
    /* the URL is printed; the user can open it by hand */
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.stack : e);
  process.exit(2);
});
