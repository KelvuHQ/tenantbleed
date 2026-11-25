// One set of bundle options, one bundle per entry point.
//   dist/tenantbleed.mjs   the CLI: engine and judge in one process
//   dist-test/*.test.mjs   tests (node --test), not shipped
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { build } from "esbuild";

// The version reports carry: package version plus the commit it was built from (+dirty when changed).
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const sh = (args) => { try { return execFileSync("git", args, { encoding: "utf8" }).trim(); } catch { return ""; } };
const commit = sh(["rev-parse", "--short", "HEAD"]);
const version = `${pkg.version}${commit ? `+${commit}${sh(["status", "--porcelain", "--untracked-files=no", "--", ".", ":!dist", ":!dist-test"]) ? ".dirty" : ""}` : ""}`;

const common = {
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  external: ["pg-native"],
  loader: { ".sql": "text" },
  define: { TENANTBLEED_VERSION: JSON.stringify(version) },
  banner: { js: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);" },
};

const entries = {
  "src/cli.ts": "dist/tenantbleed.mjs",
  "test/exec.test.ts": "dist-test/exec.test.mjs",
  "test/judge.test.ts": "dist-test/judge.test.mjs",
};
await Promise.all(Object.entries(entries).map(([entry, outfile]) => build({ ...common, entryPoints: [entry], outfile })));
console.log(`built ${Object.values(entries).join(", ")}`);
