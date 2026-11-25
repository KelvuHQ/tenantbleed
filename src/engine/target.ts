import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { ScanTarget } from "../core/report-context.js";

declare const TENANTBLEED_VERSION: string;
/** Set by scripts/build.mjs: package version and the tenantbleed commit it was built from. */
export const TOOL_VERSION = typeof TENANTBLEED_VERSION === "string" ? TENANTBLEED_VERSION : "dev";

const git = (cwd: string, args: string[]) => {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return undefined;
  }
};

/**
 * Which app and version a scan ran against, for any engine: the project's name, its git commit, and
 * the schema version from the engine's migrations folder (count, newest file, and a hash of all of
 * them in order, so two scans of the same schema match). No network, nothing sent anywhere.
 */
export function scanTarget(workdir: string, migrationsDir: string | undefined, name?: string): ScanTarget {
  const dir = resolve(workdir);
  const target: ScanTarget = { name: name || basename(dir), tool: TOOL_VERSION };
  const commit = git(dir, ["rev-parse", "HEAD"]);
  if (commit) {
    target.commit = commit;
    const branch = git(dir, ["rev-parse", "--abbrev-ref", "HEAD"]);
    if (branch && branch !== "HEAD") target.branch = branch;
    target.dirty = !!git(dir, ["status", "--porcelain", "--untracked-files=no"]);
  }
  if (migrationsDir && existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort();
    const hash = createHash("sha256");
    for (const f of files) hash.update(f).update("\0").update(readFileSync(join(migrationsDir, f))).update("\0");
    target.schemaVersion = { migrations: files.length, latest: files.at(-1), hash: hash.digest("hex").slice(0, 12) };
  }
  return target;
}
