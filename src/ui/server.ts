import { createHash, randomBytes } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { homedir } from "node:os";
import { dirname, extname, join, normalize, resolve } from "node:path";
import type { JudgeInput } from "../core/judge-input.js";
import type { ScanProgress } from "../core/progress.js";
import type { ScanResult } from "../core/scan-result.js";
import { collect, fromStatus } from "../engine/scan.js";
import { generateFixes } from "../fix/generate.js";
import { judge } from "../judge/index.js";
import { toHtml } from "../judge/html.js";
import { aiFixPrompt, toMarkdown } from "../judge/report.js";
import type { Stack } from "../supabase/api.js";
import { exposedSchemasFromConfig } from "../supabase/introspect.js";

/**
 * The local UI server: a small REST + SSE API over the engine, run in the same process. It binds to
 * loopback only and gates the API behind a per-session token carried in the opened URL, so no other
 * process (local or remote) can drive a scan. It serves the built SPA (dist/ui) as static files when
 * present. There are no network calls off the machine.
 */

export interface ServerOptions {
  /** Project directory to scan (holds supabase/config.toml). Default: process.cwd(). */
  workdir?: string;
  /** Port to bind on 127.0.0.1. Default: 7171. */
  port?: number;
  /** Directory of the built SPA to serve. Default: <dist>/ui next to this module. */
  uiDir?: string;
}

type ProgressEvent = { step: string; done: number; total: number };
type ScanEvent =
  | { type: "progress"; data: ProgressEvent }
  | { type: "note"; data: string }
  | { type: "done"; data: ScanResult }
  | { type: "error"; data: string };

interface ScanState {
  id: string;
  status: "running" | "done" | "error";
  events: ScanEvent[];
  listeners: Set<(e: ScanEvent) => void>;
  input?: JudgeInput;
  result?: ScanResult;
  error?: string;
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".map": "application/json; charset=utf-8",
};

export interface RunningServer {
  server: Server;
  url: string;
  token: string;
  port: number;
  close: () => Promise<void>;
}

export async function startServer(opts: ServerOptions = {}): Promise<RunningServer> {
  const workdir = resolve(opts.workdir ?? process.cwd());
  const port = opts.port ?? 7171;
  const uiDir = opts.uiDir ?? new URL("./ui", import.meta.url).pathname;
  const token = randomBytes(24).toString("hex");
  const scans = new Map<string, ScanState>();

  const server = createServer((req, res) => handle(req, res, { workdir, uiDir, token, scans }).catch((e) => fail(res, 500, (e as Error).message)));

  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  const actual = server.address();
  const boundPort = typeof actual === "object" && actual ? actual.port : port;
  const url = `http://127.0.0.1:${boundPort}/?token=${token}`;
  return {
    server,
    url,
    token,
    port: boundPort,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

interface Ctx {
  workdir: string;
  uiDir: string;
  token: string;
  scans: Map<string, ScanState>;
}

async function handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  const u = new URL(req.url ?? "/", "http://127.0.0.1");
  const path = u.pathname;

  if (path.startsWith("/api/")) {
    const given = req.headers["x-tp-token"] ?? u.searchParams.get("token");
    if (given !== ctx.token) return fail(res, 401, "bad or missing session token");
    return api(req, res, ctx, path, u);
  }

  // Static SPA. Everything that is not an API call and not a real file falls back to index.html
  // (client-side routing). Path traversal is refused.
  return serveStatic(res, ctx.uiDir, path);
}

async function api(req: IncomingMessage, res: ServerResponse, ctx: Ctx, path: string, u: URL): Promise<void> {
  if (path === "/api/target" && req.method === "GET") return target(res, ctx, u);
  if (path === "/api/projects" && req.method === "GET") return projects(res, ctx);
  if (path === "/api/history" && req.method === "GET") return history(res, ctx, u);
  if (path === "/api/scan" && req.method === "POST") return startScan(req, res, ctx);

  const hm = /^\/api\/history\/([A-Za-z0-9T:_-]+)\/open$/.exec(path);
  if (hm && req.method === "GET") return openHistory(res, ctx, u, hm[1]);

  const m = /^\/api\/scan\/([A-Za-z0-9_-]+)(\/events|\/report\.md|\/report\.html|\/fixes)?$/.exec(path);
  if (m && req.method === "GET") {
    const scan = ctx.scans.get(m[1]);
    if (!scan) return fail(res, 404, "no such scan");
    switch (m[2]) {
      case "/events":
        return events(res, scan);
      case "/report.md":
        return scan.result ? text(res, 200, "text/markdown; charset=utf-8", toMarkdown(scan.result)) : fail(res, 409, "scan not finished");
      case "/report.html":
        return scan.result ? text(res, 200, "text/html; charset=utf-8", toHtml(scan.result)) : fail(res, 409, "scan not finished");
      case "/fixes":
        return fixes(res, scan);
      default:
        return scan.result ? json(res, 200, scan.result) : scan.error ? fail(res, 500, scan.error) : json(res, 200, { status: scan.status });
    }
  }
  return fail(res, 404, "not found");
}

/** A chosen folder: an absolute path is taken as given; a typed relative path is resolved against the
 * directory tenantbleed was launched from (process.cwd()), which is what a person typing one expects. */
function resolveWorkdir(ctx: Ctx, given?: string | null): string {
  return given ? resolve(process.cwd(), given) : ctx.workdir;
}

/** Read what a folder looks like as a scan target: does it hold a Supabase project, and which schemas. */
function detectAt(workdir: string): { hasLocalProject: boolean; workdir: string; name?: string; exposedSchemas?: string[] } {
  const configToml = join(workdir, "supabase", "config.toml");
  if (!existsSync(configToml)) return { hasLocalProject: false, workdir };
  const toml = readFileSync(configToml, "utf8");
  const exposed = exposedSchemasFromConfig(toml) ?? ["public"];
  const name = /project_id\s*=\s*"([^"]+)"/.exec(toml)?.[1];
  return { hasLocalProject: true, workdir, name, exposedSchemas: exposed };
}

function target(res: ServerResponse, ctx: Ctx, u: URL): void {
  json(res, 200, detectAt(resolveWorkdir(ctx, u.searchParams.get("workdir"))));
}

/**
 * Scan history lives under the user's home, keyed per project, never in the scanned repo. Each
 * completed scan is one JSON file so past reports can be reopened and an app tracked over time. The
 * data stays on this machine; it is read and written only through the same loopback, token-gated API.
 */
function projectKey(workdir: string, name?: string): string {
  const base = (name ?? workdir.split(/[\\/]/).pop() ?? "project").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 40) || "project";
  return `${base}-${createHash("sha256").update(workdir).digest("hex").slice(0, 6)}`;
}
function historyDir(workdir: string): string {
  return join(homedir(), ".tenantbleed", "history", projectKey(workdir, detectAt(workdir).name));
}

/** Persist one finished scan. Best effort: a write failure never breaks the scan. */
function saveHistory(workdir: string, scanId: string, input: JudgeInput, result: ScanResult): void {
  try {
    const dir = historyDir(workdir);
    mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    writeFileSync(join(dir, `${stamp}.json`), JSON.stringify({ id: scanId, savedAt: new Date().toISOString(), workdir, name: result.target?.name, result, input }), "utf8");
  } catch {
    /* history is a convenience; do not fail the scan on a write error */
  }
}

function history(res: ServerResponse, ctx: Ctx, u: URL): void {
  const dir = historyDir(resolveWorkdir(ctx, u.searchParams.get("workdir")));
  let files: string[] = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch {
    files = [];
  }
  const scans: unknown[] = [];
  for (const f of files) {
    try {
      const rec = JSON.parse(readFileSync(join(dir, f), "utf8")) as { savedAt: string; name?: string; result: ScanResult };
      const r = rec.result;
      const proven = r.findings.filter((x) => x.confidence === "proven");
      const counts: Record<string, number> = {};
      for (const x of proven) counts[x.severity] = (counts[x.severity] ?? 0) + 1;
      scans.push({ id: f.replace(/\.json$/, ""), savedAt: rec.savedAt, name: rec.name, proven: proven.length, counts, durationMs: r.durationMs, relations: r.relationsScanned, functions: r.functionsScanned });
    } catch {
      /* skip an unreadable record */
    }
  }
  scans.sort((a, b) => String((b as { savedAt: string }).savedAt).localeCompare(String((a as { savedAt: string }).savedAt)));
  json(res, 200, { scans });
}

/** Load a saved scan back into memory so the existing scan routes (report, fixes) serve it. */
function openHistory(res: ServerResponse, ctx: Ctx, u: URL, id: string): void {
  const dir = historyDir(resolveWorkdir(ctx, u.searchParams.get("workdir")));
  const file = join(dir, `${id}.json`);
  if (!file.startsWith(dir) || !existsSync(file)) return fail(res, 404, "no such saved scan");
  const rec = JSON.parse(readFileSync(file, "utf8")) as { id?: string; savedAt: string; result: ScanResult; input: JudgeInput };
  const sid = rec.id ?? id;
  ctx.scans.set(sid, { id: sid, status: "done", events: [{ type: "done", data: rec.result }], listeners: new Set(), input: rec.input, result: rec.result });
  json(res, 200, { scanId: sid, result: rec.result, savedAt: rec.savedAt });
}

/**
 * Candidate projects to offer in the folder picker: the launch folder, its immediate subdirectories,
 * and its siblings. Only folders that actually hold a supabase/config.toml are returned. This reads
 * directory names on the local machine only, through the same loopback, token-gated API.
 */
function projects(res: ServerResponse, ctx: Ctx): void {
  const seen = new Set<string>();
  const out: { name?: string; workdir: string }[] = [];
  const consider = (dir: string) => {
    const abs = resolve(dir);
    if (seen.has(abs) || out.length >= 50) return;
    seen.add(abs);
    const d = detectAt(abs);
    if (d.hasLocalProject) out.push({ name: d.name, workdir: abs });
  };
  consider(ctx.workdir);
  for (const base of [ctx.workdir, dirname(ctx.workdir)]) {
    let names: string[] = [];
    try {
      names = readdirSync(base, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
    } catch {
      names = [];
    }
    for (const name of names) consider(join(base, name));
  }
  json(res, 200, { projects: out });
}

async function startScan(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  const body = (await readJson(req)) as { schemas?: string; triage?: boolean; stack?: Stack; allowRemote?: boolean; workdir?: string };
  const workdir = resolveWorkdir(ctx, body.workdir);
  if (!existsSync(join(workdir, "supabase", "config.toml"))) return fail(res, 400, `no supabase/config.toml in ${workdir}`);
  const id = randomBytes(8).toString("hex");
  const scan: ScanState = { id, status: "running", events: [], listeners: new Set() };
  ctx.scans.set(id, scan);
  json(res, 202, { scanId: id });

  const emit = (e: ScanEvent) => {
    scan.events.push(e);
    for (const l of scan.listeners) l(e);
  };
  const onProgress: ScanProgress = (e) => emit({ type: "progress", data: e });

  // Run the scan in the background; the client follows it over SSE.
  (async () => {
    try {
      const stack: Stack = body.stack ?? fromStatus(workdir);
      assertLocalOrThrow(stack, !!body.allowRemote);
      const input = await collect({ stack, workdir, schemas: body.schemas, triage: body.triage !== false, onProgress });
      scan.input = input;
      const result = judge(input);
      scan.result = result;
      scan.status = "done";
      saveHistory(workdir, id, input, result);
      emit({ type: "done", data: result });
    } catch (e) {
      scan.status = "error";
      scan.error = (e as Error).message;
      emit({ type: "error", data: scan.error });
    } finally {
      for (const l of scan.listeners) scan.listeners.delete(l);
    }
  })();
}

/** Like assertLocal but throws instead of exiting the process (the server must stay up). */
function assertLocalOrThrow(stack: Stack, allowRemote: boolean): void {
  const host = new URL(stack.apiUrl).hostname;
  if (!["127.0.0.1", "localhost", "0.0.0.0", "::1"].includes(host) && !allowRemote)
    throw new Error(`Refusing to scan ${stack.apiUrl}: tenantbleed mutates data and only runs against local stacks.`);
}

function events(res: ServerResponse, scan: ScanState): void {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  const send = (e: ScanEvent) => res.write(`event: ${e.type}\ndata: ${JSON.stringify(e.data)}\n\n`);
  for (const e of scan.events) send(e); // replay what already happened
  if (scan.status !== "running") return void res.end();
  const listener = (e: ScanEvent) => {
    send(e);
    if (e.type === "done" || e.type === "error") res.end();
  };
  scan.listeners.add(listener);
  res.on("close", () => scan.listeners.delete(listener));
}

function fixes(res: ServerResponse, scan: ScanState): void {
  if (!scan.result || !scan.input) return fail(res, 409, "scan not finished");
  const { fixes, skipped } = generateFixes(scan.result.findings, scan.input.schema);
  // Per-finding AI-fix prompt, so the UI can offer a copyable prompt next to each finding.
  const prompts = Object.fromEntries(scan.result.findings.map((f) => [f.id, aiFixPrompt(f)]));
  json(res, 200, { fixes, skipped, prompts });
}

function serveStatic(res: ServerResponse, uiDir: string, path: string): void {
  if (!existsSync(uiDir)) return text(res, 503, "text/plain; charset=utf-8", "The tenantbleed UI has not been built. Run the build, or use the CLI (tenantbleed supabase).");
  const rel = normalize(path === "/" ? "/index.html" : path).replace(/^(\.\.(\/|\\|$))+/, "");
  let file = join(uiDir, rel);
  if (!file.startsWith(uiDir)) return fail(res, 403, "forbidden");
  if (!existsSync(file) || !statSync(file).isFile()) file = join(uiDir, "index.html"); // SPA fallback
  if (!existsSync(file)) return fail(res, 404, "not found");
  res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(res);
}

// Small helpers.
function json(res: ServerResponse, status: number, body: unknown): void {
  text(res, status, "application/json; charset=utf-8", JSON.stringify(body));
}
function text(res: ServerResponse, status: number, type: string, body: string): void {
  res.writeHead(status, { "content-type": type });
  res.end(body);
}
function fail(res: ServerResponse, status: number, message: string): void {
  if (res.headersSent) return void res.end();
  json(res, status, { error: message });
}
async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}
