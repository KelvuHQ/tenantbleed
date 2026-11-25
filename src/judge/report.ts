import { SEVERITY_ORDER, type Finding } from "../core/findings.js";
import type { ScanResult, Triage, TriageRow, Verdict } from "../core/scan-result.js";

/** Prompts printed in the report; the JSON report keeps all of them. */
const CHECK_PROMPTS_SHOWN = 15;

const VERDICT: Record<Verdict, string> = {
  proven: "Proven: fix this",
  flagged: "Not exploited; schema check agrees it is risky",
  tested: "Tested: not exploitable",
  locked: "Locked: RLS on, no policies",
  shared: "Shared by design",
  "no-api": "Not reachable through the API",
  "not-callable": "Not callable through the API",
  extension: "Part of an extension, not the app's code",
  "not-tested": "Not tested",
};
const VERDICT_ORDER: Verdict[] = ["proven", "flagged", "not-tested", "tested", "locked", "shared", "no-api", "not-callable", "extension"];

/** The linter's warnings, sorted by what the scan proved. */
export function triageMarkdown(t: Triage): string[] {
  if (!t.ran) return ["### Linter warnings", "", `Supabase's linter could not run: ${t.error ?? "unknown error"}.`, ""];
  const access = t.rows.length;
  const lines = ["### Linter warnings, triaged", ""];
  if (!access) {
    lines.push(`Supabase's linter (the Security Advisor) raised no data-access warnings${t.other ? ` (${t.other} about performance or hygiene, not tested by tenantbleed)` : ""}.`, "");
  } else {
    const n = (v: Verdict, inv?: boolean) => t.rows.filter((r) => r.verdict === v && (inv === undefined || r.inventory === inv)).length;
    const specific = t.rows.filter((r) => !r.inventory);
    const inventory = t.rows.filter((r) => r.inventory);
    lines.push(
      `Supabase's linter (the Security Advisor) raised ${t.total} warning(s); ${access} are about who can reach data${t.other ? ` (the other ${t.other} are performance or hygiene, not tested here)` : ""}. tenantbleed attacked each one:`,
      "",
      "| | Specific warnings | One-per-object warnings |",
      "|---|---|---|",
      ...VERDICT_ORDER.filter((v) => n(v)).map((v) => `| ${VERDICT[v]} | ${n(v, false)} | ${n(v, true)} |`),
      `| **Total** | **${specific.length}** | **${inventory.length}** |`,
      "",
      "One-per-object warnings (\"anon can run this SECURITY DEFINER function\") are raised for every such function, whether or not anything is wrong.",
      "",
    );
    const proven = t.rows.filter((r) => r.verdict === "proven");
    if (proven.length) {
      lines.push("**Proven real** (the findings above show the request and the fix):", "", "| Warning | Target | Proof |", "|---|---|---|");
      for (const r of proven) lines.push(`| ${r.title} | \`${r.target}\` | ${r.findings.join(", ")} |`);
      lines.push("");
    }
    const rest = t.rows.filter((r) => r.verdict !== "proven").sort((a, b) => VERDICT_ORDER.indexOf(a.verdict) - VERDICT_ORDER.indexOf(b.verdict) || Number(a.inventory) - Number(b.inventory));
    if (rest.length) {
      lines.push(`<details><summary>The other ${rest.length} warning(s), with why each was not proven</summary>`, "", "| Verdict | Warning | Target | Why |", "|---|---|---|---|");
      for (const r of rest) lines.push(`| ${VERDICT[r.verdict]} | ${r.title} | \`${r.target}\` | ${r.reason} |`);
      lines.push("", "</details>", "");
    }
  }
  const open = t.rows.filter((r) => r.checkPrompt);
  if (open.length) {
    // Signed-out callers and writers first: those are the ones worth checking today.
    const rank = (r: TriageRow) => (/anon_/.test(r.lint) ? 0 : 1) + (r.verdict === "flagged" ? 0 : 2);
    const shown = [...open].sort((a, b) => rank(a) - rank(b) || a.target.localeCompare(b.target)).slice(0, CHECK_PROMPTS_SHOWN);
    lines.push(
      `**Check it yourself** (${open.length} warning(s) tenantbleed could neither prove nor clear; paste a prompt into Lovable, Bolt, Cursor or Claude):`,
      "",
      `<details><summary>${shown.length === open.length ? "All" : `The first ${shown.length} of ${open.length}`} prompt(s)</summary>`,
      "",
    );
    for (const r of shown) lines.push(`\`${r.target}\``, "```text", r.checkPrompt!, "```", "");
    lines.push("</details>", "");
  }
  if (t.unflagged.length) lines.push(`tenantbleed proved ${t.unflagged.length} issue(s) at medium or above on tables and functions the linter raised no warning for: ${t.unflagged.join(", ")}.`, "");
  return lines;
}

const ICON: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };

const sort = (f: Finding[]) =>
  [...f].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.target.localeCompare(b.target));

const nameOf = (target: string) => target.replace(/^public\./, "");

/** One sentence a non-security person understands. */
export function plain(f: Finding): string {
  const t = nameOf(f.target);
  if (t.startsWith("bucket:")) {
    const b = t.slice(7);
    const anyone = f.evidence?.actor === "anon" ? "Anyone on the internet, without logging in," : "Any logged-in user";
    if (f.title.includes(" list ")) return `${anyone} can see the names of other users' files in the "${b}" storage bucket.`;
    const verb: Record<string, string> = {
      "anon-read": "download",
      "cross-tenant-read": "download",
      "cross-tenant-update": "replace",
      "cross-tenant-delete": "delete",
      "cross-tenant-insert": "upload files into the folders of",
    };
    return f.kind === "cross-tenant-insert"
      ? `${anyone} can upload files into other users' folders in the "${b}" storage bucket.`
      : `${anyone} can ${verb[f.kind] ?? "access"} other users' files in the "${b}" storage bucket.`;
  }
  const anon = f.evidence?.actor === "anon";
  const someone = anon ? "Anyone on the internet, without logging in," : "Any logged-in user";
  switch (f.kind) {
    case "anon-read":
      return `Anyone on the internet can read your users' "${t}" data, no login needed.`;
    case "cross-tenant-read":
      return `${someone} can see other users' "${t}".`;
    case "view-leak":
      return `The "${t}" view shows every user's data to anyone who asks.`;
    case "cross-tenant-update":
      return `${someone} can change other users' "${t}".`;
    case "cross-tenant-delete":
      return `${someone} can delete other users' "${t}".`;
    case "cross-tenant-insert":
      return `${someone} can add records into another user's account ("${t}").`;
    case "cross-tenant-reparent":
      return `A user can move their own "${t}" records into someone else's account.`;
    case "impersonation-insert":
      return `A user can create "${t}" records in someone else's name (as if another user made or owns them).`;
    case "rpc-leak":
      return `The function "${t}" hands out other users' data when called with their id.`;
    case "rpc-write":
      return `${someone} can change or delete other users' data by calling the function "${t}".`;
    case "metadata-escalation":
      return `Users can unlock other accounts' "${t}" just by editing their own profile settings.`;
    case "self-escalation":
      return `Any user can make themselves an admin by editing their own "${t}" record.`;
    case "self-enrollment":
      return `Any user can add themselves as an admin to another organization through "${t}".`;
    default:
      return f.title;
  }
}

/** A prompt the user can paste into Lovable, Bolt, Cursor or Claude to get a migration that fixes it. */
export function aiFixPrompt(f: Finding): string {
  const t = f.target;
  if (t.startsWith("bucket:")) {
    const op: Record<string, string> = { "anon-read": "SELECT", "cross-tenant-read": "SELECT", "cross-tenant-update": "UPDATE", "cross-tenant-delete": "DELETE", "cross-tenant-insert": "INSERT" };
    return [
      `My Supabase app has a storage security bug: ${plain(f)}`,
      `Proof: ${f.evidence ? `${f.evidence.request.method} ${f.evidence.request.path} returned ${f.evidence.status}.` : f.detail}`,
      `Write a new SQL migration that fixes the ${op[f.kind] ?? ""} policy on storage.objects for bucket '${t.slice(7)}' so users can only touch files in their own folder, for example (storage.foldername(name))[1] = auth.uid()::text, or the folder of an organization they are a member of.`,
      `Do not break access for the rightful owner. Explain the change in one paragraph.`,
    ].join("\n");
  }
  const hint: Record<string, string> = {
    "anon-read": `Make sure row level security is enabled on ${t} and that no policy grants SELECT to the anon role on rows that belong to a user or organization.`,
    "cross-tenant-read": `Change the SELECT policy on ${t} so a row is visible only to its owner or to members of the organization it belongs to (for example using auth.uid() or a memberships lookup). Enable row level security on ${t} if it is off.`,
    "view-leak": `Recreate the view ${t} with (security_invoker = true) so it respects the row level security of the tables it reads.`,
    "cross-tenant-update": `Give ${t} an UPDATE policy whose USING and WITH CHECK both restrict rows to the owner or the owner's organization. Enable row level security if it is off.`,
    "cross-tenant-delete": `Give ${t} a DELETE policy whose USING restricts rows to the owner or the owner's organization. Enable row level security if it is off.`,
    "cross-tenant-insert": `Give ${t} an INSERT policy whose WITH CHECK verifies the caller belongs to the organization or parent record the new row points at.`,
    "cross-tenant-reparent": `Add a WITH CHECK to the UPDATE policy on ${t} that repeats the ownership condition, so a row cannot be moved to a parent the user does not belong to.`,
    "impersonation-insert": `Change the INSERT policy on ${t} so its WITH CHECK requires the owner or author column to equal auth.uid().`,
    "rpc-leak": `Inside the function ${t}, check that auth.uid() is allowed to access the requested record before returning anything, or revoke EXECUTE on it from anon and authenticated.`,
    "rpc-write": `Inside the function ${t}, check that auth.uid() owns or is a member of the record it changes before changing it, or make it SECURITY INVOKER so row level security applies. Revoke EXECUTE from anon if it is not meant for signed-out users.`,
    "metadata-escalation": `Stop using user_metadata in policies on ${t}. Users can edit user_metadata themselves. Use app_metadata or a memberships table instead.`,
    "self-escalation": `Users must not be able to change their own role or admin flag in ${t}. Revoke UPDATE on that column from authenticated (grant UPDATE only on the columns users may edit), or add a trigger that refuses changes to it unless the caller is already an admin.`,
    "self-enrollment": `The INSERT policy on ${t} lets a user add their own privileged row (role admin, is_admin) without checking the parent is theirs. Limit the self-insert branch to the parent's own members or creator, or create the first privileged row from a SECURITY DEFINER trigger on the parent instead of a client insert.`,
  };
  return [
    `My Supabase app has a security bug: ${plain(f)}`,
    `Proof: ${f.evidence ? `${f.evidence.request.method} ${f.evidence.request.path} returned ${f.evidence.status}.` : f.detail}`,
    `Write a new SQL migration that fixes it. ${hint[f.kind] ?? f.fix ?? ""}`,
    `Do not break access for the rightful owner. Explain the change in one paragraph.`,
  ].join("\n");
}

/** Finding id, where to fix it, the data involved and the standards (src/judge/context.ts). */
function contextLines(f: Finding): string[] {
  const out: string[] = [];
  if (f.fingerprint) out.push(`**Finding id:** \`${f.fingerprint}\` (stays the same between scans)`, "");
  if (f.location?.length) out.push(`**Where to fix:** ${f.location.map((l) => `\`${l.file}:${l.line}\` ${l.what}`).join("; ")}`, "");
  if (f.data?.classes.length) out.push(`**Data involved:** ${f.data.classes.join(", ")} (columns: ${f.data.columns.join(", ")})`, "");
  if (f.standards) out.push(`**Standards:** ${[...f.standards.owasp, ...f.standards.cwe].join("; ")}`, "");
  return out;
}

export function toMarkdown(r: ScanResult): string {
  const proven = sort(r.findings.filter((f) => f.confidence === "proven"));
  const stat = sort(r.findings.filter((f) => f.confidence === "static"));
  const count = (s: string) => proven.filter((f) => f.severity === s).length;
  const gaps = r.coverage.filter((c) => !c.notExposed && !c.staffList && (!c.populated || (c.reached === 0 && c.unreachable > 0)));
  const lines: string[] = [];

  const headline = proven.length
    ? `${proven.length} proven isolation failure(s)`
    : r.relationsScanned === 0 && r.functionsScanned === 0
      ? "nothing to scan: no tables, views or functions in the exposed schemas (see below)"
      : r.complete && !gaps.length
      ? "no proven isolation failures"
      : "no proven failures, but coverage is incomplete (see below)";
  lines.push(`## tenantbleed: ${headline}`, "");
  const t = r.target;
  if (t) {
    const code = t.commit ? ` at commit ${t.commit.slice(0, 12)}${t.branch ? ` (${t.branch})` : ""}${t.dirty ? " with uncommitted changes" : ""}` : "";
    const db = t.schemaVersion ? ` · schema: ${t.schemaVersion.migrations} migration(s), latest ${t.schemaVersion.latest ?? "none"} (hash ${t.schemaVersion.hash})` : "";
    lines.push(`Scanned **${t.name}**${code}${db} · tenantbleed ${t.tool} · ${r.startedAt}`, "");
  }
  lines.push(`${r.stack} · tenants: ${r.tenants.join(", ") || "none"} · ${r.relationsScanned} relations, ${r.functionsScanned} functions · ${(r.durationMs / 1000).toFixed(1)}s`);
  if (proven.length) lines.push("", SEVERITY_ORDER.filter(count).map((s) => `${ICON[s]} ${count(s)} ${s}`).join(" · "));
  for (const n of r.notes.filter((x) => x.startsWith("Heads-up:"))) lines.push("", `> **${n.slice(0, 8)}**${n.slice(8)}`);

  const urgent = proven.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  if (urgent.length) {
    lines.push("", "### Fix these first", "");
    urgent.forEach((f, i) => lines.push(`${i + 1}. ${ICON[f.severity]} ${plain(f)} (${f.id})`));
  }

  if (proven.length) {
    lines.push("", "### Proven with real accounts", "", "| | Target | What happened | Actor |", "|---|---|---|---|");
    for (const f of proven) lines.push(`| ${ICON[f.severity]} | \`${f.target}\` | ${f.title} | ${f.evidence?.actor ?? ""} |`);
    lines.push("");
    for (const f of proven) {
      const e = f.evidence!;
      lines.push(`<details><summary>${ICON[f.severity]} <b>${f.id}</b> ${plain(f)}</summary>`, "");
      lines.push(`**Technical:** ${f.title}. ${f.detail}`, "");
      lines.push(...contextLines(f));
      lines.push(`**Request:** \`${e.request.method} ${e.request.path}\` returned **${e.status}**`, "");
      lines.push("**Proof:**", "```", e.proof, "```");
      lines.push("**Reproduce (local stack):**", "```sh", e.curl, "```");
      if (f.fix) lines.push(`**Fix:** ${f.fix}`, "");
      lines.push("**Fix it with your AI assistant** (paste into Lovable, Bolt, Cursor or Claude):", "```text", aiFixPrompt(f), "```");
      lines.push("</details>", "");
    }
  }

  if (stat.length) {
    lines.push("### Schema findings (not exploited, explain the failures above)", "", "| | Target | Finding | Where | Id |", "|---|---|---|---|---|");
    for (const f of stat) lines.push(`| ${ICON[f.severity]} | \`${f.target}\` | ${f.title} | ${f.location?.map((l) => `\`${l.file}:${l.line}\``).join(", ") ?? ""} | \`${f.fingerprint ?? f.id}\` |`);
    lines.push("");
  }

  if (r.coverage.length) {
    const tables = r.coverage.filter((c) => c.kind !== "function" && c.kind !== "bucket");
    const buckets = r.coverage.filter((c) => c.kind === "bucket");
    const ok = tables.filter((c) => c.populated && c.reached > 0).length;
    const sharedCount = tables.filter((c) => c.shared).length;
    // Filled only to call functions in a schema the API does not expose: never served, so not a gap.
    const notExposed = tables.filter((c) => c.notExposed).length;
    // App-wide staff lists, left empty on purpose (a test user there would see everyone): not a gap.
    const staffLists = tables.filter((c) => c.staffList).length;
    // Tenancy carried by a JWT claim the scan does not mint: tenant-scoped, but could not be attacked.
    const jwtScopedRows = tables.filter((c) => c.jwtScoped);
    // No API role has any privilege on it: unreachable from a browser, which is the safe outcome.
    const noAccess = tables.filter((c) => c.populated && !c.shared && !c.notExposed && !c.jwtScoped && c.reached === 0 && c.unreachable === 0).length;
    const extras = [
      sharedCount && `${sharedCount} shared by design`,
      noAccess && `${noAccess} with no API access at all, so unreachable`,
      notExposed && `${notExposed} in schemas the API does not expose (filled only to call functions)`,
      staffLists && `${staffLists} app-wide staff list(s), left empty on purpose`,
      jwtScopedRows.length && `${jwtScopedRows.length} scoped by a JWT claim the scan does not mint, so not attacked`,
    ].filter(Boolean);
    lines.push(
      tables.length - sharedCount - notExposed === 0
        ? "### Coverage: no tenant tables are exposed through the API in the scanned schemas"
        : `### Coverage: ${ok} of ${tables.length - sharedCount - noAccess - notExposed - staffLists - jwtScopedRows.length} reachable tenant tables and views tested through the API${extras.length ? ` (plus ${extras.join(", ")})` : ""}`,
      "",
    );
    if (jwtScopedRows.length) {
      lines.push("Tenant tables scoped by a JWT claim (not minted by the scan, so not attacked): verify the claim is set from app_metadata (server-controlled), never user_metadata.", "", "| Relation | JWT claim |", "|---|---|");
      for (const c of jwtScopedRows) lines.push(`| \`${c.relation}\` | \`${c.jwtScoped}\` |`);
      lines.push("");
    }
    if (buckets.length) lines.push(`Storage: ${buckets.filter((c) => c.populated).length} of ${buckets.length} bucket(s) tested with a file owned by each test user.`, "");
    if (gaps.length) {
      lines.push("| Relation | Why it was not fully tested |", "|---|---|");
      for (const c of gaps) {
        const why = !c.populated
          ? `could not create test data: ${c.reason ?? "unknown"}`
          : c.broken
            ? `every call failed inside it: ${c.broken}`
            : `the REST API did not serve it (${c.unreachable} request(s) answered 404/406)`;
        lines.push(`| \`${c.relation}\` | ${why} |`);
      }
      lines.push("");
    }
  }

  if (r.triage) lines.push(...triageMarkdown(r.triage));

  const rest = r.notes.filter((x) => !x.startsWith("Heads-up:"));
  if (rest.length) lines.push("<details><summary>Scan notes</summary>", "", ...rest.map((n) => `- ${n}`), "", "</details>");
  return lines.join("\n");
}
