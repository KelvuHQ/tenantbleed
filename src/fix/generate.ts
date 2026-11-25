// Fix generator: one migration per proven issue, from deterministic templates.
//
// The main tool is a RESTRICTIVE policy: Postgres ANDs it with the existing permissive policies,
// so a fix can only narrow access, never widen it. Whether it narrowed too much is checked by
// re-running the scan with the rightful-owner ("still works") check.

import type { Finding } from "../core/findings.js";
import { qualified, type Policy, type Relation, type RpcFunction, type Schema } from "../supabase/introspect.js";
import { findProfileTables, isUserRef } from "../supabase/world.js";

export interface Fix {
  id: string;
  /** The findings this fix should close: `${kind} ${target} ${anon|tenant}`. */
  closes: string[];
  target: string;
  template: string;
  title: string;
  sql: string;
}

export interface Skipped {
  finding: string;
  /** The finding's plain title, for the report. */
  title?: string;
  severity?: string;
  reason: string;
}

const id = (s: string) => `"${s.replace(/"/g, '""')}"`;
const qid = (r: { schema: string; name: string }) => `${id(r.schema)}.${id(r.name)}`;
const side = (f: Finding) => (f.evidence?.actor === "anon" ? "anon" : "tenant");
const key = (f: Finding) => `${f.kind} ${f.target} ${side(f)}`;
const slug = (s: string) => s.replace(/[^a-z0-9]+/gi, "_").toLowerCase().slice(0, 40);

/**
 * A parent anyone can read (a published course, a public catalog): "the caller can see it" says
 * nothing about who may add rows under it. True when some permissive SELECT policy for a client role
 * does not depend on the caller (no auth.*, no function that could check membership).
 */
export function publicParent(parent: Relation, schema: Schema): boolean {
  return schema.policies.some(
    (p) =>
      p.schema === parent.schema &&
      p.table === parent.name &&
      p.permissive !== false &&
      (p.cmd === "SELECT" || p.cmd === "ALL") &&
      p.roles.some((r) => ["public", "anon", "authenticated"].includes(r)) &&
      !/auth\.|current_setting|current_user|session_user|\w\(/.test(p.using ?? "true"),
  );
}

/** The first parent whose own RLS limits who sees it (an organization, a workspace), and the join. */
function protectedParent(t: Relation, schema: Schema, profiles: Set<string>): string | undefined {
  for (const fk of t.foreignKeys) {
    if (isUserRef(fk, profiles)) continue;
    const parent = schema.relations.find((r) => r.schema === fk.refSchema && r.name === fk.refTable);
    if (!parent || parent.kind !== "table" || !parent.rlsEnabled || qualified(parent) === qualified(t) || publicParent(parent, schema)) continue;
    const on = fk.columns.map((c, i) => `p.${id(fk.refColumns[i])} = ${qid(t)}.${id(c)}`).join(" and ");
    return `exists (select 1 from ${qid(parent)} p where ${on})`;
  }
  return undefined;
}

/**
 * The condition that says "this row is the caller's to touch", per command. Membership first: the
 * caller can see the protected parent (its own RLS applies inside the subquery, so an organization's
 * membership rule is inherited without restating it, and coworkers keep access). Without one, the
 * row's own person column. New rows need both: the caller is the person, and the parent is theirs.
 */
export function scopePredicate(t: Relation, schema: Schema, cmd: string = "select"): string | undefined {
  const profiles = findProfileTables(schema);
  const person = t.foreignKeys.find((f) => isUserRef(f, profiles) && f.columns.length === 1);
  const mine = person && `${id(person.columns[0])} = (select auth.uid())`;
  const parent = protectedParent(t, schema, profiles);
  if (cmd === "insert") return [mine, parent].filter(Boolean).join(" and ") || undefined;
  return parent ?? mine;
}

/** Adding rows under someone else's parent can only be closed when a parent limits who sees it. */
function canCloseInjection(t: Relation, schema: Schema): boolean {
  return !!protectedParent(t, schema, findProfileTables(schema));
}

/** Commands to restrict for a finding kind. */
function commandsFor(kind: string): ("select" | "insert" | "update" | "delete")[] {
  switch (kind) {
    case "anon-read":
    case "cross-tenant-read":
    case "metadata-escalation":
      return ["select"];
    case "cross-tenant-update":
    case "cross-tenant-reparent":
      return ["update"];
    case "cross-tenant-delete":
      return ["delete"];
    case "cross-tenant-insert":
    case "impersonation-insert":
      return ["insert"];
    default:
      return [];
  }
}

function restrictive(t: Relation, cmd: string, role: string, pred: string, name: string): string {
  const using = cmd === "insert" ? "" : ` using (${pred})`;
  const check = cmd === "insert" || cmd === "update" ? ` with check (${pred})` : "";
  return `create policy ${id(name)} on ${qid(t)} as restrictive for ${cmd} to ${role}${using}${check};`;
}

function fnSignature(f: RpcFunction): string {
  return `${qid(f)}(${f.args.map((a) => a.type).join(", ")})`;
}

/** Only issues worth an automatic fix: proven, medium or worse, not lowered as "public by design". */
function fixable(f: Finding): string | undefined {
  if (f.confidence !== "proven") return "not proven";
  if (!["critical", "high", "medium"].includes(f.severity)) return "low severity";
  if (/allows it\)|readable by every signed-in user|profile fields came back|counters or timestamps/.test(`${f.title} ${f.detail}`))
    return "may be public by design: needs a product decision";
  return undefined;
}

const ALWAYS = (e: string | null) => (e ?? "").replace(/[()\s]/g, "").toLowerCase() === "true";
const covers = (p: Policy, cmd: string) => p.cmd === "ALL" || p.cmd.toLowerCase() === cmd;

/**
 * A policy written for the backend (named for the service role) that is always true but not limited
 * to `service_role`: Postgres applies it to everyone. The service role bypasses RLS anyway, so the
 * intended meaning is kept by granting the policy to `service_role` only.
 */
export function backendPolicies(schema: Schema, target: string): Policy[] {
  return schema.policies.filter(
    (p) =>
      `${p.schema}.${p.table}` === target &&
      p.permissive !== false &&
      /service[\s_-]*role/i.test(p.name) &&
      !p.roles.every((r) => r === "service_role") &&
      (ALWAYS(p.using) || ALWAYS(p.withCheck)),
  );
}

/** Whether a finding is explained by the backend policies alone: no other always-true policy opens that command. */
function explainedByBackend(f: Finding, schema: Schema, backend: Policy[]): boolean {
  const cmds = commandsFor(f.kind);
  if (!cmds.length) return false;
  return cmds.every(
    (c) =>
      backend.some((p) => covers(p, c)) &&
      !schema.policies.some((p) => `${p.schema}.${p.table}` === f.target && p.permissive !== false && !backend.includes(p) && covers(p, c) && (ALWAYS(p.using) || ALWAYS(p.withCheck))),
  );
}

export function generateFixes(findings: Finding[], schema: Schema): { fixes: Fix[]; skipped: Skipped[] } {
  const fixes: Fix[] = [];
  const skipped: Skipped[] = [];
  const byTarget = new Map<string, Finding[]>();
  const toBackend = new Map<string, Finding[]>();
  for (const f of findings) {
    // Open through a backend-only policy: fixable even when the read looks "public by design".
    if (f.confidence === "proven" && ["critical", "high", "medium"].includes(f.severity)) {
      const backend = backendPolicies(schema, f.target);
      if (backend.length && explainedByBackend(f, schema, backend)) {
        toBackend.set(f.target, [...(toBackend.get(f.target) ?? []), f]);
        continue;
      }
    }
    const why = fixable(f);
    if (why) {
      if (f.confidence === "proven") skipped.push({ finding: key(f), title: f.title, severity: f.severity, reason: why });
      continue;
    }
    byTarget.set(f.target, [...(byTarget.get(f.target) ?? []), f]);
  }
  let n = 0;
  const next = () => `F${String(++n).padStart(3, "0")}`;

  // ---------------------------------------------------------------- backend-only policies
  for (const [target, group] of toBackend) {
    const rel = schema.relations.find((r) => qualified(r) === target)!;
    const policies = backendPolicies(schema, target);
    const lines = policies.map((p) => `alter policy ${id(p.name)} on ${qid(rel)} to service_role;`);
    // The app may have relied on the open policy for users' own rows: give each owner back exactly
    // their own rows for the commands it covered (narrower than before, which was everyone).
    const cmds = (["select", "insert", "update", "delete"] as const).filter((c) => policies.some((p) => covers(p, c)));
    const owned = scopePredicate(rel, schema);
    if (owned)
      for (const c of cmds) {
        const pr = scopePredicate(rel, schema, c) ?? owned;
        const using = c === "insert" ? "" : ` using (${pr})`;
        const check = c === "insert" || c === "update" ? ` with check (${pr})` : "";
        lines.push(`create policy ${id(`tp_${slug(rel.name)}_owner_${c}`)} on ${qid(rel)} for ${c} to authenticated${using}${check};`);
      }
    fixes.push({
      id: next(),
      closes: group.map(key),
      target,
      template: "policy-to-service-role",
      title: `Limit ${policies.map((p) => `policy "${p.name}"`).join(", ")} on ${target} to the service role${owned ? ", and let each user keep their own rows" : ""}`,
      sql: lines.join("\n"),
    });
  }

  for (const [target, group] of byTarget) {
    // ---------------------------------------------------------------- storage buckets
    if (target.startsWith("bucket:")) {
      const bucket = target.slice(7).replace(/'/g, "''");
      const lines: string[] = [];
      const cmds = new Set(group.flatMap((f) => commandsFor(f.kind)));
      const own = `bucket_id <> '${bucket}' or (storage.foldername(name))[1] = (select auth.uid())::text or owner_id = (select auth.uid())::text`;
      for (const cmd of cmds) {
        const using = cmd === "insert" ? "" : ` using (${own})`;
        const check = cmd === "insert" || cmd === "update" ? ` with check (${own})` : "";
        lines.push(`create policy ${id(`tp_${slug(bucket)}_owner_${cmd}`)} on storage.objects as restrictive for ${cmd} to authenticated${using}${check};`);
      }
      if (group.some((f) => side(f) === "anon")) lines.push(`create policy ${id(`tp_${slug(bucket)}_no_anon`)} on storage.objects as restrictive for all to anon using (bucket_id <> '${bucket}') with check (bucket_id <> '${bucket}');`);
      fixes.push({ id: next(), closes: group.map(key), target, template: "storage-owner-folder", title: `Limit bucket "${bucket.replace(/''/g, "'")}" to each user's own folder`, sql: lines.join("\n") });
      continue;
    }

    // ---------------------------------------------------------------- functions
    const fn = schema.functions.find((f) => `${f.schema}.${f.name}` === target);
    if (fn) {
      const lines: string[] = [];
      const anon = group.some((f) => side(f) === "anon");
      const tenant = group.some((f) => side(f) === "tenant");
      if (anon) lines.push(`revoke execute on function ${fnSignature(fn)} from anon, public;`);
      if (tenant && fn.securityDefiner) lines.push(`alter function ${fnSignature(fn)} security invoker;`);
      if (!lines.length) {
        for (const f of group) skipped.push({ finding: key(f), title: f.title, severity: f.severity, reason: "function already runs as the caller; needs a check inside its body" });
        continue;
      }
      fixes.push({
        id: next(),
        closes: group.map(key),
        target,
        template: tenant && fn.securityDefiner ? "function-security-invoker" : "function-revoke-anon",
        title: tenant && fn.securityDefiner ? `Run ${target}() as the caller so RLS applies${anon ? ", and revoke it from anonymous visitors" : ""}` : `Revoke ${target}() from anonymous visitors`,
        sql: lines.join("\n"),
      });
      continue;
    }

    const rel = schema.relations.find((r) => qualified(r) === target);
    if (!rel) {
      for (const f of group) skipped.push({ finding: key(f), title: f.title, severity: f.severity, reason: "target not found in the schema" });
      continue;
    }

    // ---------------------------------------------------------------- views
    if (rel.kind === "view") {
      fixes.push({ id: next(), closes: group.map(key), target, template: "view-security-invoker", title: `Make view ${target} respect RLS`, sql: `alter view ${qid(rel)} set (security_invoker = true);` });
      continue;
    }

    // ---------------------------------------------------------------- tables
    // Planting rows under another user's parent (cross-tenant insert, reparent) is closed only by a
    // protected parent. When every parent is public (a published course), who may add rows is an app
    // rule (enrollment, invitation): leave it to a human and fix the rest.
    const injection = (f: Finding) => f.kind === "cross-tenant-insert" || f.kind === "cross-tenant-reparent";
    if (rel.rlsEnabled && !canCloseInjection(rel, schema)) {
      for (const f of group.filter(injection))
        skipped.push({ finding: key(f), title: f.title, severity: f.severity, reason: "rows can be added under another user's record, and no parent limits who sees it (it is public): who may add rows here is an app rule, such as enrollment or membership" });
      group.splice(0, group.length, ...group.filter((f) => !injection(f)));
      if (!group.length) continue;
    }
    const pred = scopePredicate(rel, schema);
    if (!pred) {
      for (const f of group) skipped.push({ finding: key(f), title: f.title, severity: f.severity, reason: "no owner column or protected parent to scope rows by: needs a human" });
      continue;
    }
    const lines: string[] = [];
    let template = "table-restrict";
    if (!rel.rlsEnabled) {
      // RLS off: turn it on with owner-scoped permissive policies, so the owner keeps access.
      template = "table-enable-rls";
      lines.push(`alter table ${qid(rel)} enable row level security;`);
      lines.push(`create policy ${id(`tp_${slug(rel.name)}_owner_select`)} on ${qid(rel)} for select to authenticated using (${pred});`);
      lines.push(`create policy ${id(`tp_${slug(rel.name)}_owner_insert`)} on ${qid(rel)} for insert to authenticated with check (${scopePredicate(rel, schema, "insert") ?? pred});`);
      lines.push(`create policy ${id(`tp_${slug(rel.name)}_owner_update`)} on ${qid(rel)} for update to authenticated using (${pred}) with check (${pred});`);
      lines.push(`create policy ${id(`tp_${slug(rel.name)}_owner_delete`)} on ${qid(rel)} for delete to authenticated using (${pred});`);
    } else {
      const cmds = new Set<string>();
      for (const f of group) for (const c of commandsFor(f.kind)) cmds.add(`${c}`);
      for (const cmd of cmds) {
        // Impersonation: the person column itself must be the caller.
        const imp = group.find((f) => f.kind === "impersonation-insert");
        const profiles = findProfileTables(schema);
        const personCols = rel.foreignKeys.filter((f) => isUserRef(f, profiles) && f.columns.length === 1).map((f) => f.columns[0]);
        const p =
          cmd === "insert" && imp && personCols.length
            ? [...personCols.map((c) => `${id(c)} = (select auth.uid())`), protectedParent(rel, schema, profiles)].filter(Boolean).join(" and ")
            : (scopePredicate(rel, schema, cmd) ?? pred);
        lines.push(restrictive(rel, cmd, "authenticated", p, `tp_${slug(rel.name)}_scope_${cmd}`));
      }
      if (group.some((f) => side(f) === "anon")) lines.push(`create policy ${id(`tp_${slug(rel.name)}_no_anon`)} on ${qid(rel)} as restrictive for all to anon using (false) with check (false);`);
    }
    fixes.push({ id: next(), closes: group.map(key), target, template, title: rel.rlsEnabled ? `Scope ${target} to its owner` : `Enable RLS on ${target} with owner-scoped policies`, sql: lines.join("\n") });
  }
  return { fixes, skipped };
}

/** A migration file for one fix, with its explanation as a header comment. */
export function migrationFor(fix: Fix): string {
  return [
    `-- tenantbleed fix ${fix.id}: ${fix.title}`,
    `-- Closes: ${fix.closes.join("; ")}`,
    `-- Template: ${fix.template}. Verified by re-running the attacks and the rightful-owner check.`,
    "",
    fix.sql,
    "",
  ].join("\n");
}
