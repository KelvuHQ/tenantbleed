import { existsSync, readdirSync, readFileSync } from "node:fs";
import type { SourceRef } from "../core/report-context.js";
import { join, relative, resolve } from "node:path";

/**
 * Facts read from the app's repo, sent to the judge: what the seed files create, and every
 * GRANT or REVOKE on a function in the migrations. No verdicts here.
 */

/**
 * Objects created only by the seed files (supabase/seed.sql by default) exist on local and branch
 * databases, where `db reset` loads the seed, but not on production, where only migrations run.
 * A dev helper there (a "reset this app's data" function, a demo table) is real on the scanned
 * stack but usually absent from the live app, so it is reported as low with the reason.
 */
const CREATE = /create\s+(?:or\s+replace\s+)?(?:function|procedure|table|view|materialized\s+view)\s+(?:if\s+not\s+exists\s+)?(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?/gi;

function created(sql: string): Set<string> {
  const out = new Set<string>();
  for (const m of sql.replace(/--[^\n]*/g, "").matchAll(CREATE)) out.add(`${(m[1] ?? "public").toLowerCase()}.${m[2].toLowerCase()}`);
  return out;
}

function seedPaths(supabaseDir: string): string[] {
  const toml = join(supabaseDir, "config.toml");
  const text = existsSync(toml) ? readFileSync(toml, "utf8") : "";
  const section = /^\[db\.seed\]([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(text)?.[1] ?? "";
  if (/^\s*enabled\s*=\s*false/m.test(section)) return [];
  const list = /^\s*sql_paths\s*=\s*\[([^\]]*)\]/m.exec(section)?.[1];
  const globs = list ? [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]) : ["./seed.sql"];
  const files: string[] = [];
  for (const g of globs) {
    const p = resolve(supabaseDir, g);
    if (!g.includes("*")) {
      if (existsSync(p)) files.push(p);
      continue;
    }
    // Only the common "dir/*.sql" shape; anything fancier is skipped rather than guessed.
    const dir = resolve(supabaseDir, g.slice(0, g.lastIndexOf("/") + 1) || ".");
    if (existsSync(dir)) for (const f of readdirSync(dir).sort()) if (f.endsWith(".sql")) files.push(join(dir, f));
  }
  return files;
}

/** Objects created by the seed files and by no migration. */
export function seedOnlyObjects(workdir: string): string[] {
  const dir = join(workdir, "supabase");
  const seeds = seedPaths(dir);
  if (!seeds.length) return [];
  const fromSeed = new Set<string>();
  for (const f of seeds) for (const o of created(readFileSync(f, "utf8"))) fromSeed.add(o);
  const migDir = join(dir, "migrations");
  const fromMigrations = new Set<string>();
  if (existsSync(migDir)) for (const f of readdirSync(migDir)) if (f.endsWith(".sql")) for (const o of created(readFileSync(join(migDir, f), "utf8"))) fromMigrations.add(o);
  return [...fromSeed].filter((o) => !fromMigrations.has(o));
}

/** Every GRANT or REVOKE on a function in the migrations, in migration order, comments removed. */
export function functionGrantStatements(workdir: string): string[] {
  const migDir = join(workdir, "supabase", "migrations");
  if (!existsSync(migDir)) return [];
  const sql = readdirSync(migDir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => readFileSync(join(migDir, f), "utf8").replace(/--[^\n]*/g, ""))
    .join("\n");
  return [...sql.matchAll(GRANT_OR_REVOKE)].map((m) => m[0]);
}

/** Shared with the judge, which parses the same statements: one pattern, one place. */
export const GRANT_OR_REVOKE = /\b(grant|revoke)\s+(?:execute|all)[^;]*?on\s+function\s+([^;]+?)\s+(to|from)\s+([^;]+);/gi;

const DEFINE = /create\s+(?:or\s+replace\s+)?(function|procedure|table|view|materialized\s+view)\s+(?:if\s+not\s+exists\s+)?(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?|create\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?|drop\s+policy\s+(?:if\s+exists\s+)?(?:"([^"]+)"|(\w+))\s+on\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?/gi;

/**
 * Where each policy, function, table and view is defined in the migrations, for the report's "where
 * to fix it". The last definition wins, as in the database; a dropped policy is forgotten.
 */
export function sourceIndex(workdir: string): SourceRef[] {
  const migDir = join(workdir, "supabase", "migrations");
  const migrations = existsSync(migDir) ? readdirSync(migDir).filter((x) => x.endsWith(".sql")).sort().map((f) => join(migDir, f)) : [];
  // Seed files run after the migrations on a local stack, so they come last.
  const files = [...migrations, ...seedPaths(join(workdir, "supabase"))];
  const out = new Map<string, SourceRef>();
  for (const path of files) {
    // Comments blanked to the same length, so offsets still give the right line.
    const sql = readFileSync(path, "utf8").replace(/--[^\n]*/g, (c) => " ".repeat(c.length));
    const lineAt = (i: number) => sql.slice(0, i).split("\n").length;
    const file = relative(resolve(workdir), path);
    for (const m of sql.matchAll(DEFINE)) {
      if (m[1]) {
        const kind = m[1].toLowerCase().replace(/\s+/g, " ").replace("materialized view", "view").replace("procedure", "function");
        const object = `${(m[2] ?? "public").toLowerCase()}.${m[3].toLowerCase()}`;
        out.set(`${kind}|${object}`, { kind, object, file, line: lineAt(m.index!) });
      } else if (m[4] || m[5]) {
        const name = m[4] ?? m[5].toLowerCase();
        const object = `${(m[6] ?? "public").toLowerCase()}.${m[7].toLowerCase()}`;
        out.set(`policy|${object}|${name}`, { kind: "policy", object, name, file, line: lineAt(m.index!) });
      } else {
        out.delete(`policy|${(m[10] ?? "public").toLowerCase()}.${m[11].toLowerCase()}|${m[8] ?? m[9].toLowerCase()}`);
      }
    }
  }
  return [...out.values()];
}
