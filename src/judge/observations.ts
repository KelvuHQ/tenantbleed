import type { Finding, FindingKind } from "../core/findings.js";
import type { Observation, Row, WorldSummary } from "../core/observation.js";
import type { Policy, RpcFunction, Schema } from "../supabase/introspect.js";
import { scheduledJob, timeMaintenance } from "../core/job-shape.js";

export { timeMaintenance };

/**
 * Turns what the probes observed into findings: severity, title, detail and fix. Every precision
 * rule that decides how serious a proven result is lives here (see docs/rules.md); the probes only
 * report what happened.
 */

type Draft = Omit<Finding, "id" | "confidence" | "evidence">;

const ANON = "anon";
const isAnon = (actor: string) => actor === ANON;
const who = (actor: string) => (isAnon(actor) ? "Anyone without an account" : actor);
const short = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}...` : s);
const roleOf = (actor: string) => (isAnon(actor) ? "anon" : "authenticated");

// ---------------------------------------------------------------------------------------------
// Rules shared by several probes

/** Profile columns that are personal data even in an app where profiles are public (substring match). */
const SENSITIVE_PROFILE = /email|phone|mobile|address|street|zip|postal|birth|dob|ssn|tax|passport|national|salary|iban|card|ip_|location|lat|lng|geo/i;
/**
 * Contact or secret columns that keep a "public by name" table at full severity (whole-word match).
 * Differs from SENSITIVE_PROFILE on purpose (word boundaries, secrets); unifying them is a rule change
 * for a field test, not a refactor.
 */
const SENSITIVE_COLUMN = /(^|_)(e?mail|email_address|phone|mobile|address|street|zip|postal|postcode|birth|dob|ssn|tax|tax_id|passport|national|salary|iban|card|location|geo|token|secret|password|api_key|private_key|key_hash|ip_address)($|_)/i;

const PROFILE_NOTE = " Only another user's profile fields came back (name, avatar, bio or their id), which is normal for chat partners, authors and member lists. A leak if profiles are meant to be private.";

/**
 * A leak made only of another user's public profile fields (name, avatar, bio, their user id) is
 * normal in social apps: chat partners, authors, member lists. Report it lower and say why.
 * Any sensitive profile field (email, phone, address, birth date) keeps the full severity.
 */
function profileOnly(world: JudgeWorld, hits: string[], response: string, victim: string): boolean {
  // The victim's real sign-in email, or any filled field named like personal data (email, phone,
  // address...), means more than a public profile came back, even when no scan marker is in it.
  const email = world.emails.get(victim);
  if (email && response.includes(email)) return false;
  const sensitiveKey = new RegExp(`"[^"]*(?:${SENSITIVE_PROFILE.source})[^"]*"\\s*:\\s*"[^"]+"`, "i");
  if (sensitiveKey.test(response)) return false;
  return hits.length > 0 && hits.every((h) => {
    const col = world.profileTokens.get(h);
    return col !== undefined && !SENSITIVE_PROFILE.test(col);
  });
}

/**
 * A SELECT policy that lets every signed-in user (or everyone) read every row: `true`,
 * `auth.role() = 'authenticated'`, `auth.uid() IS NOT NULL`. The scan still proves the read, but
 * it is a stated design decision, not a forgotten check, so it is reported one level lower.
 */
const OPEN = [
  /^\s*\(?\s*true\s*\)?\s*$/i,
  /^\s*\(?\s*auth\.role\(\)\s*=\s*'authenticated'(::text)?\s*\)?\s*$/i,
  /^\s*\(?\s*auth\.uid\(\)\s+is\s+not\s+null\s*\)?\s*$/i,
  /^\s*\(?\s*\(?\s*\(?auth\.jwt\(\)\s*->>\s*'role'(::text)?\)?\s*=\s*'authenticated'(::text)?\s*\)?\s*$/i,
];

// For anonymous readers a plain filter only counts as public when its value says so; "scope = 'workspace'"
// is a sharing choice between signed-in users, not an invitation to the whole internet.
const PUBLIC_WORD = /public|publish|active|visible|listed|open|live|approved|enabled/i;

export function openReadPolicy(schema: Schema, table: string, role: "anon" | "authenticated", forReads = false): Policy | undefined {
  const [s, name] = table.split(".");
  return schema.policies.find(
    (p) =>
      p.schema === s &&
      p.table === name &&
      (p.cmd === "SELECT" || p.cmd === "ALL") &&
      (p.roles.includes(role) || p.roles.includes("public")) &&
      !!p.using &&
      (OPEN.some((re) => re.test(p.using!)) ||
        // A SELECT filter that never looks at the caller (is_active, published, visibility = 'public')
        // shows the same rows to everyone on purpose: a storefront, a price banner, a public profile.
        (forReads && p.cmd === "SELECT" && !/auth\.|current_setting|current_user|session_user|jwt|uid\(\)/i.test(p.using!)) ||
        // One OR branch is a plain column filter (is_active = true OR creator_id = auth.uid()): rows
        // matching it are public on purpose. Only literal comparisons count; a branch that calls a
        // function or runs a subquery may look at the caller inside and is not treated as public.
        (forReads && p.cmd === "SELECT" && topLevelOr(p.using!).length > 1 && topLevelOr(p.using!).some((b) => publicFilter(b) && (role === "authenticated" || PUBLIC_WORD.test(b))))),
  );
}

export function topLevelOr(expr: string): string[] {
  let e = expr.trim();
  const wrapped = (x: string) => {
    if (!x.startsWith("(") || !x.endsWith(")")) return false;
    let d = 0;
    for (let i = 0; i < x.length; i++) {
      if (x[i] === "(") d++;
      else if (x[i] === ")" && --d === 0 && i < x.length - 1) return false;
    }
    return true;
  };
  while (wrapped(e)) e = e.slice(1, -1).trim();
  const parts: string[] = [];
  let d = 0, q = false, start = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") q = !q;
    if (q) continue;
    if (c === "(") d++;
    else if (c === ")") d--;
    else if (d === 0 && /^ OR /i.test(e.slice(i, i + 4))) {
      parts.push(e.slice(start, i).trim());
      start = i + 4;
    }
  }
  parts.push(e.slice(start).trim());
  return parts;
}

export function publicFilter(branch: string): boolean {
  if (/auth\.|current_setting|current_user|session_user|jwt|uid\(\)|\bselect\b|\bexists\b/i.test(branch)) return false;
  // Any call other than a type cast ("::text") may consult the caller.
  if (/\b(?!(?:in|any|array)\b)[a-z_][\w.]*\s*\(/i.test(branch.replace(/::[\w\s\[\]"]+/g, ""))) return false;
  return /=|\bis\s+(true|not\s+null)\b|\bin\s*\(/i.test(branch);
}

/** An open read policy, unless it is named for the backend: "Service role can manage X" applies to every role. */
function readPolicyVerdict(schema: Schema, table: string, relKind: string, actor: string) {
  const openPolicy = relKind === "table" ? openReadPolicy(schema, table, roleOf(actor), true) : undefined;
  const backendOnly = !!openPolicy && /service[\s_-]*role|backend|server[\s_-]*side/i.test(openPolicy.name) && !openPolicy.roles.every((r) => r === "service_role");
  return { openPolicy, backendOnly, open: backendOnly ? undefined : openPolicy };
}

const readKind = (actor: string, relKind: string): FindingKind => (isAnon(actor) ? "anon-read" : relKind === "view" ? "view-leak" : "cross-tenant-read");

const DANGLING = (actor: string, victim: string, parent: string) =>
  `Accepted, but ${victim} cannot see the resulting row: it stays in ${actor}'s own data and only points at ${victim}'s ${parent}. A cross-tenant reference, not an injection; it matters if anything joins through it (reports, totals, triggers). Add a check that the referenced record belongs to the caller.`;

/** Only counters and timestamps moved (enrollment_count, updated_at). */
const COUNTER = /(^|_)(count|counts|total|totals|tally|views|likes)$|_at$|^updated|^last_/;
/** Tables that only hold values derived from other data: dropping or recomputing them loses nothing. */
const DERIVED_STORE = /(^|_)(cache|caches|cached|rollup|rollups)($|_)/i;
/** An argument that carries a value the function could write (not an id, date or flag). */
const VALUE_ARG = /^(text|character varying|jsonb?|numeric|integer|bigint|smallint|real|double precision)$/;
const HOW_ROLLED_BACK = " It was run the way the API runs it (same role, same JWT claims) inside a transaction that was rolled back, so the scan changed nothing.";
const DEFINER = (f?: RpcFunction) => (f?.securityDefiner ? "SECURITY DEFINER: runs as its owner and skips RLS. " : "");

// ---------------------------------------------------------------------------------------------
// One finding per observation kind

interface JudgeWorld {
  emails: Map<string, string>;
  profileTokens: Map<string, string>;
}

function draft(o: Observation, schema: Schema, world: JudgeWorld): Draft {
  const { actor, victim, target } = o;
  switch (o.probe) {
    case "read": {
      const { relKind, leaked, hits } = o.facts;
      const { openPolicy, backendOnly, open } = readPolicyVerdict(schema, target, relKind, actor);
      const profile = profileOnly(world, hits, JSON.stringify(leaked), victim);
      // The policy's own name says the rows are public on purpose ("Public can view all roadmap items").
      // Never for rows that carry contact or secret columns: "public profiles" that include emails are a leak.
      const sensitiveCols = [...new Set(leaked.flatMap((r: Row) => Object.keys(r).filter((c) => SENSITIVE_COLUMN.test(c) && r[c] != null && r[c] !== "")))];
      const declared = open && !sensitiveCols.length && /\b(public(ly)?|anyone|everyone|all users|anon(ymous)?)\b/i.test(open.name);
      const tenant = !isAnon(actor);
      return {
        rule: declared ? "read/declared-public" : profile ? "read/profile-only" : open ? (sensitiveCols.length ? "read/open-policy-sensitive" : "read/open-policy") : backendOnly ? "read/backend-only-policy" : relKind === "view" ? "read/view" : "read",
        kind: readKind(actor, relKind),
        severity: declared ? "low" : profile ? (tenant ? "low" : "medium") : open ? (tenant ? "medium" : "high") : tenant ? "high" : "critical",
        target,
        title: open ? `${who(actor)} can read ${victim}'s rows in ${target} (policy "${open.name}" allows it)` : `${who(actor)} can read ${victim}'s rows in ${target}`,
        detail: declared
          ? `${leaked.length} row(s) belonging to ${victim} came back because policy "${open!.name}" is \`${open!.using}\`. The policy name says this table is public on purpose, so this is reported as low. Check that no column in it is private (emails, internal notes); if all is intended, list ${target} under "shared" in tenantbleed.json.`
          : open && sensitiveCols.length
            ? `${leaked.length} row(s) belonging to ${victim} came back because policy "${open.name}" is \`${open.using}\`, including ${sensitiveCols.join(", ")}. Even if the table is meant to be public, those columns are not: move them to a private table or expose a view without them.`
            : open
              ? `${leaked.length} row(s) belonging to ${victim} came back because policy "${open.name}" is \`${open.using}\`. Fine for data that is public by design (chat, directories); a leak for tenant data. If intended, list ${target} under "shared" in tenantbleed.json.`
              : backendOnly
                ? `${leaked.length} row(s) belonging to ${victim} came back because policy "${openPolicy!.name}" is \`${openPolicy!.using}\` for ${openPolicy!.roles.join(", ")}. It is named for the service role but has no TO service_role, so it applies to every caller. The service role skips RLS anyway: restrict the policy to service_role or drop it.`
                : `${leaked.length} row(s) belonging to ${victim} came back.${relKind === "view" ? " Views run as their owner unless security_invoker is set." : ""}${profile ? PROFILE_NOTE : ""}`,
      };
    }
    case "read-state": {
      const { leaked, precondition, sensitive } = o.facts;
      const anon = isAnon(actor);
      return {
        rule: sensitive.length ? "read-state/sensitive" : "read-state",
        kind: readKind(actor, "table"),
        severity: sensitive.length ? (anon ? "high" : "medium") : anon ? "medium" : "low",
        target,
        title: `${who(actor)} can read ${victim}'s rows in ${target} once ${precondition}`,
        detail: `${leaked.length} row(s) belonging to ${victim} came back after ${precondition}, a state ${victim} reaches by normal use.${sensitive.length ? ` The rows include ${sensitive.join(", ")}.` : " The visible columns do not look identifying, so a public listing may be intended; confirm."} A policy opens the rows in that state without limiting which columns, or to whom, they are shown.`,
        fix: `Restrict the "${precondition.split(" = ")[0]}" branch: return only the columns meant to be public (through a view with the public columns, or a narrower policy), not whole rows with person, order or contact fields.`,
      };
    }
    case "graphql-read": {
      const { relKind, leakedCount } = o.facts;
      const { open } = readPolicyVerdict(schema, target, relKind, actor);
      const tenant = !isAnon(actor);
      return {
        rule: open ? "graphql-read/open-policy" : "graphql-read",
        kind: readKind(actor, relKind),
        severity: open ? (tenant ? "medium" : "high") : tenant ? "high" : "critical",
        target,
        title: `${who(actor)} can read ${victim}'s rows in ${target} through GraphQL`,
        detail: `${leakedCount} row(s) belonging to ${victim} came back from /graphql/v1.${open ? ` Policy "${open.name}" is \`${open.using}\`.` : ""}`,
      };
    }
    case "update":
      return {
        rule: "update",
        kind: "cross-tenant-update",
        severity: isAnon(actor) ? "critical" : "high",
        target,
        title: `${who(actor)} can modify ${victim}'s rows in ${target}`,
        detail: `PATCH changed ${target}.${o.facts.column} on a row owned by ${victim}. Verified in the database, then restored.`,
      };
    case "reparent": {
      const { refTable, columns, victimCanSee } = o.facts;
      const open = openReadPolicy(schema, refTable, "authenticated");
      const seen = open ? true : victimCanSee;
      return {
        rule: open ? "reparent/shared-parent" : !seen ? "reparent/unseen-parent" : "reparent",
        kind: "cross-tenant-reparent",
        severity: open || !seen ? "low" : "high",
        target,
        title: `${actor} can move its own rows into ${victim}'s ${refTable} by editing ${columns.join(", ")}`,
        detail: open
          ? `Allowed, but ${refTable} is readable by every signed-in user (policy "${open.name}"), so it looks like a shared space. Confirm that moving rows between them is intended.`
          : !seen
            ? DANGLING(actor, victim, refTable)
            : `The UPDATE policy on ${target} has no WITH CHECK that re-validates the new ${columns.join(", ")}, so a row can be re-pointed at another tenant (data injection, and the row becomes visible to them).`,
        fix: open ? undefined : `Add a WITH CHECK to the update policy on ${target} that repeats the tenant condition.`,
      };
    }
    case "insert": {
      const { parentTable, columns, victimCanSee } = o.facts;
      const open = openReadPolicy(schema, parentTable, roleOf(actor));
      const seen = open ? true : victimCanSee;
      return {
        rule: open ? "insert/shared-parent" : !seen ? "insert/unseen-parent" : "insert",
        kind: "cross-tenant-insert",
        severity: open || !seen ? "low" : isAnon(actor) ? "critical" : "high",
        target,
        title: seen ? `${who(actor)} can create rows inside ${victim}'s data in ${target}` : `${who(actor)} can create ${target} rows that reference ${victim}'s ${parentTable}`,
        detail: open
          ? `Accepted, but the parent ${parentTable} is readable by every signed-in user (policy "${open.name}"), so it looks like a shared space (e.g. posting in a public channel).`
          : !seen
            ? DANGLING(actor, victim, parentTable)
            : `Insert accepted with ${columns.join(", ")} pointing at ${victim}'s ${parentTable}. Plants data in another tenant.`,
      };
    }
    case "impersonate": {
      const { columns, personAndTenantInKey } = o.facts;
      // Membership tables (workspace_members, account_user...): putting another user's id in them
      // is how a team admin adds people. Worth knowing (no consent step), not impersonation.
      const table = target.split(".").slice(1).join(".");
      const membership = /member|participant|collaborator|account_user|team_user|user_role|seat/i.test(table) || personAndTenantInKey;
      return membership
        ? {
            rule: "impersonate/membership",
            kind: "impersonation-insert",
            severity: "low",
            target,
            title: `${actor} can add ${victim} to its own ${target} without their consent`,
            detail: `${target} looks like a membership table: inserting another user's id is how members are added. It is accepted without any invite or acceptance step, so anyone can be enrolled in a stranger's team. Fine if the app adds members directly; otherwise require an accepted invitation.`,
          }
        : {
            rule: "impersonate",
            kind: "impersonation-insert",
            severity: "medium",
            target,
            title: `${actor} can create ${target} rows that name ${victim} in ${columns.join(", ")}`,
            detail: `The INSERT policy on ${target} does not check that ${columns.join(", ")} is the caller, so a user can create records attributed to, or owned by, someone else.`,
            fix: `Add \`${columns[0]} = auth.uid()\` to the WITH CHECK of the insert policy on ${target}.`,
          };
    }
    case "rpc-leak": {
      const f = fn(schema, target);
      const how = f?.volatile ? HOW_ROLLED_BACK : "";
      const profile = profileOnly(world, o.facts.hits, o.facts.output, victim);
      const tenant = !isAnon(actor);
      // A number or a word computed from the victim's records (a member count, a plan): not their
      // rows, but something about them the caller should not know.
      if (o.facts.derived)
        return {
          rule: "rpc-leak/derived-value",
          kind: "rpc-leak",
          severity: "low",
          target,
          title: `${who(actor)} learns something about ${victim}'s records from ${target}()`,
          detail: `${DEFINER(f)}${
            o.facts.derived.by === "removal"
              ? `It takes nothing that points at ${victim}, yet ${actor === "anon" ? "a visitor" : actor} got ${short(o.facts.output, 80)}, and ${short(o.facts.derived.blank, 80)} once ${victim}'s rows were left out (checked in a transaction that was rolled back). So its answer includes ${victim}'s records for any caller (a total across every account).`
              : `Called with ${victim}'s id it answered ${short(o.facts.output, 80)}; called with an id that does not exist it answered ${short(o.facts.derived.blank, 80)}. So it reads ${victim}'s records for any caller.`
          } It returns a value about them (a count, a status), not their rows, so this is reported as low; check the caller inside the function before answering.${how}`,
          fix: "Check inside the function that auth.uid() belongs to the record or organization before answering.",
        };
      // Only record ids came back (a membership check that answers with a member id): it tells the
      // caller a record exists, not what it holds.
      if (o.facts.hits.length && o.facts.hits.every((h) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(h)))
        return {
          rule: "rpc-leak/ids-only",
          kind: "rpc-leak",
          severity: "low",
          target,
          title: `${who(actor)} learns ${victim}'s record ids from ${target}()`,
          detail: `${DEFINER(f)}Called with ${victim}'s values, it returned ${o.facts.hits.length} of their record id(s) but none of their data. Ids alone do not expose content, but they confirm a record exists and can be used in other calls; check the caller inside the function.${how}`,
          fix: "Check inside the function that auth.uid() owns or belongs to the record before answering.",
        };
      return {
        rule: profile ? "rpc-leak/profile-only" : "rpc-leak",
        kind: "rpc-leak",
        severity: profile ? (tenant ? "low" : "medium") : tenant ? "high" : "critical",
        target,
        title: `${who(actor)} gets ${victim}'s data from ${target}()`,
        detail: `${DEFINER(f)}Called with ${victim}'s values, it returned their data.${how}${profile ? PROFILE_NOTE : ""}`,
      };
    }
    case "rpc-write": {
      const f = fn(schema, target);
      const how =
        (f?.volatile ? HOW_ROLLED_BACK : "") +
        (o.facts.primed ? ` Before the call, ${victim}'s row was set to ${o.facts.primed} in that same transaction: the function only acts on rows in that state, which the app reaches in normal use.` : "");
      const { changed } = o.facts;
      if (o.facts.shared) {
        // Existing rows of a table that belongs to no tenant (an audit log, global counters) were
        // deleted or edited by a caller with no check: nobody's data in particular, everyone's integrity.
        const tables = [...new Set(changed.map((c) => c.split(" ")[0]))];
        const timeGated = scheduledJob(f);
        // Only counters and timestamps moved (a stats refresh, a cache recompute): a side effect.
        const countersOnly = changed.every((c) => {
          const parts = c.split(": ").slice(1).join(": ");
          return !/row (deleted|changed)$/.test(parts) && parts.split("; ").every((p) => COUNTER.test(p.split(" ")[0]));
        });
        // A recompute (compute_, refresh_, rebuild_, backfill_): it rewrites derived numbers from
        // the data that is already there, so a caller can only make it run early, not choose values.
        const recompute = !!f && /^(re)?(compute|calc|calculate|refresh|rebuild|backfill|sync|reindex|aggregate|recount)/i.test(f.name) && f.args.every((a) => !VALUE_ARG.test(a.type));
        if (countersOnly || recompute)
          return {
            rule: recompute && !countersOnly ? "rpc-write/shared-recompute" : "rpc-write/shared-counters",
            kind: "rpc-write",
            severity: "low",
            target,
            title: recompute && !countersOnly ? `${who(actor)} can run the recompute ${target}() early` : `${who(actor)} can move counters or timestamps in ${tables.join(", ")} through ${target}()`,
            detail: `${DEFINER(f)}Called by ${isAnon(actor) ? "a visitor without an account" : actor}, it ${recompute && !countersOnly ? "recomputed derived values on" : "only changed counters or timestamps on"} ${changed.length} shared row(s) (a refresh or a recount); the caller cannot choose the values. Usually harmless; worth a look if it is expensive to run or those numbers drive money, limits or what others see.${how}`,
            fix: "Revoke EXECUTE from anon and authenticated if only a backend or scheduled job should run it.",
          };
        return {
          rule: timeGated ? "rpc-write/shared-scheduled-job" : "rpc-write/shared-change",
          kind: "rpc-write",
          severity: timeGated ? "low" : isAnon(actor) ? "high" : "medium",
          target,
          title: `${who(actor)} can delete or change shared data in ${tables.join(", ")} through ${target}()`,
          detail: `${DEFINER(f)}Called by ${isAnon(actor) ? "a visitor without an account" : actor}, it deleted or changed ${changed.length} existing row(s) of ${tables.join(", ")}, which belong to no single user (for example an audit log or global counters).${how}`,
          fix: "Check the caller inside the function (auth.uid(), or the service role for jobs), or revoke EXECUTE from anon and authenticated and call it from a backend or scheduled job.",
        };
      }
      // Only new rows, none of the victim's existing rows touched: the caller created records in the
      // victim's name or space (an org that names them admin, usage charged to their project).
      const createdOnly = changed.every((c) => / row appeared$/.test(c));
      // Idempotent seeding of an org's defaults (seed_, ensure_, get_or_create_): the caller can only
      // add the rows the app would add anyway, never choose their content.
      if (createdOnly && f && /^(seed|ensure|get_or_create|init|initialize|provision|bootstrap)_/i.test(f.name))
        return {
          rule: "rpc-write/seed-defaults",
          kind: "rpc-write",
          severity: "low",
          target,
          title: `${who(actor)} can make ${target}() create ${victim}'s default records`,
          detail: `${DEFINER(f)}Called with ${victim}'s values, it created ${changed.length} default row(s) for them (${[...new Set(changed.map((c) => c.split(" ")[0]))].join(", ")}). The caller cannot choose their content; worth a look if creating them has a cost or sends anything.${how}`,
          fix: "Check the caller inside the function, or revoke EXECUTE from anon and authenticated and call it from the backend.",
        };
      if (createdOnly && scheduledJob(f))
        return {
          rule: "rpc-write/scheduled-job-creates",
          kind: "rpc-write",
          severity: "low",
          target,
          title: `${who(actor)} can run the scheduled job ${target}() early`,
          detail: `${DEFINER(f)}It takes no arguments it could aim with (at most a batch size or a day window) and writes only what its schedule would write; it created ${changed.length} row(s) for ${victim} (${[...new Set(changed.map((c) => c.split(" ")[0]))].join(", ")}). The caller cannot choose who gets them or what they say. Worth a look if running it early sends emails or costs money.${how}`,
          fix: "Revoke EXECUTE on the function from anon and authenticated and call it from pg_cron or a backend job.",
        };
      if (createdOnly)
        return {
          rule: "rpc-write/creates-in-victim",
          kind: "rpc-write",
          severity: isAnon(actor) ? "high" : "medium",
          target,
          title: `${who(actor)} can create records in ${victim}'s data through ${target}()`,
          detail: `${DEFINER(f)}Called with ${victim}'s values, it created ${changed.length} new row(s) that point at ${victim} or their records (${[...new Set(changed.map((c) => c.split(" ")[0]))].join(", ")}). None of their existing rows changed.${how}`,
          fix: "Check inside the function that auth.uid() owns or belongs to the record it writes under, or make it SECURITY INVOKER so RLS applies.",
        };
      // Only counters and timestamps moved: the side effect of a normal cross-user action such as
      // buying someone's course, not control over their data.
      const sideEffect = changed.every((c) => {
        const parts = c.split(": ").slice(1).join(": ");
        if (/row appeared/.test(parts)) return true;
        if (/row deleted/.test(parts)) return false;
        return parts.split("; ").every((p) => COUNTER.test(p.split(" ")[0]));
      });
      // No arguments and every write gated on the clock (expired codes, stale sessions): the caller
      // cannot pick whose rows change, only make a scheduled cleanup run early.
      // Only caches changed (recomputed or dropped), and the function takes nothing it could write:
      // the caller makes the victim's cached numbers refresh early, never chooses them.
      const tablesChanged = [...new Set(changed.map((c) => c.split(" ")[0].split(".").pop() ?? ""))];
      if (!sideEffect && f && f.args.every((a) => !VALUE_ARG.test(a.type)) && tablesChanged.every((t) => DERIVED_STORE.test(t)))
        return {
          rule: "rpc-write/cache-refresh",
          kind: "rpc-write",
          severity: "low",
          target,
          title: `${who(actor)} can make ${target}() refresh ${victim}'s cached values`,
          detail: `${DEFINER(f)}Called with ${victim}'s values, it recomputed or dropped ${changed.length} of their cached row(s) (${tablesChanged.join(", ")}). It takes no value it could write, so the caller cannot choose what ends up there; the cache is rebuilt from ${victim}'s own data. Worth a look if refreshing is expensive or the cached numbers gate limits or billing.${how}`,
          fix: "Check inside the function that auth.uid() belongs to the record, or revoke EXECUTE from anon and authenticated if only the backend refreshes it.",
        };
      const housekeeping =
        !sideEffect && scheduledJob(f);
      if (housekeeping)
        return {
          rule: "rpc-write/time-based-cleanup",
          kind: "rpc-write",
          severity: "low",
          target,
          title: `${who(actor)} can run the time-based cleanup ${target}() early`,
          detail: `${DEFINER(f)}It takes no arguments it could aim with (at most a batch size or a day window) and only changes rows past a time limit, so a caller cannot choose whose data changes; it changed ${changed.length} of ${victim}'s row(s) that were already due. Usually harmless; make sure running it at any moment is safe, or revoke EXECUTE from anon and authenticated and call it from a scheduled job.${how}`,
          fix: "Revoke EXECUTE on the function from anon and authenticated and call it from pg_cron or a backend job.",
        };
      return {
        rule: sideEffect ? "rpc-write/counters" : "rpc-write/change",
        kind: "rpc-write",
        severity: sideEffect ? "low" : isAnon(actor) ? "critical" : "high",
        target,
        title: sideEffect ? `${who(actor)} moves counters on ${victim}'s data through ${target}()` : `${who(actor)} changes ${victim}'s data through ${target}()`,
        detail: sideEffect
          ? `Called with ${victim}'s values, it only changed counters or timestamps on their row(s), which is typical of a normal action between users (a purchase, a view, a like). Worth a look if those counters drive money or limits.${how}`
          : `${DEFINER(f)}Called with ${victim}'s values, it changed ${changed.length} of their row(s).${how}`,
        fix: "Check inside the function that auth.uid() owns or belongs to the record before changing it, or make it SECURITY INVOKER so RLS applies.",
      };
    }
    case "self-escalation": {
      const { column, value, unlocked, steppedDown } = o.facts;
      // steppedDown: the test user already held the value, so the scan set the plainest one first and
      // climbed back as that plain member.
      return {
        rule: unlocked.length ? "self-escalation" : "self-escalation/stored",
        kind: "self-escalation",
        severity: unlocked.length ? "critical" : "medium",
        target,
        title: steppedDown
          ? `a plain member (${column} = ${steppedDown}) can make themselves ${value} on their own ${target} row`
          : `${actor} can make themselves privileged by setting ${column} = ${value} on their own ${target} row`,
        detail: unlocked.length
          ? `The update policy lets a user edit every column of their own row, and the app trusts ${column}: after setting it, ${actor} could read ${victim}'s rows in ${unlocked.join(", ")}.`
          : `The update policy lets a user edit every column of their own row, and a policy or function trusts ${column}. The new value was stored; no other user's rows opened to a plain read in this test, so check what else ${column} unlocks.`,
        fix: `Revoke UPDATE on ${target}.${column} from authenticated (grant UPDATE only on the columns users may edit), or refuse changes to it in a trigger unless the caller is already privileged.`,
      };
    }
    case "self-enrollment": {
      const { column, value, parentTable, policy, unlocked } = o.facts;
      return {
        rule: "self-enrollment",
        kind: "self-enrollment",
        severity: unlocked.length ? "critical" : "high",
        target,
        title: `${actor} can add themselves to ${victim}'s ${parentTable} with ${column} = ${value}`,
        detail: `Policy "${policy}" lets a user insert their own row in ${target} (${column} = ${value}) without tying it to a parent they own, so ${actor} added a privileged row in ${victim}'s ${parentTable}.${unlocked.length ? ` Every check that reads ${column} then passed: ${actor} could read ${victim}'s rows in ${unlocked.join(", ")}.` : ""}`,
        fix: `Limit the self-insert branch to the parent's own members or creator (for example \`exists (select 1 from <parent> p where p.id = ${target.split(".").pop()}.<parent key> and p.created_by = auth.uid())\`), or create the first privileged row from a SECURITY DEFINER trigger on the parent, not from a client insert.`,
      };
    }
    case "metadata":
      return {
        rule: "metadata",
        kind: "metadata-escalation",
        severity: "critical",
        target,
        title: `${actor} can read ${victim}'s ${target} by editing their own user_metadata`,
        detail: `Policy "${o.facts.policy}" trusts user_metadata.${o.facts.keys.join(", ")}. Any user can set it with supabase.auth.updateUser({ data: { ${o.facts.keys[0]}: "<victim id>" } }).`,
        fix: "Use app_metadata (only the service role can write it) or a membership table lookup.",
      };
    case "delete":
      return {
        rule: "delete",
        kind: "cross-tenant-delete",
        severity: isAnon(actor) ? "critical" : "high",
        target,
        title: `${who(actor)} can delete ${victim}'s rows in ${target}`,
        detail: `DELETE removed a row owned by ${victim}. Verified in the database, then restored.`,
      };
    case "file-download":
      return {
        rule: "file-download",
        kind: isAnon(actor) ? "anon-read" : "cross-tenant-read",
        severity: isAnon(actor) ? "critical" : "high",
        target,
        title: `${who(actor)} can download ${victim}'s files from the private bucket "${o.facts.bucket}"`,
        detail: `Downloaded ${victim}'s file ${o.facts.path}.${seeded(o.facts.seededByService)}`,
        fix: `Limit the SELECT policy on storage.objects for bucket "${o.facts.bucket}" to the owner's folder, e.g. (storage.foldername(name))[1] = auth.uid()::text.`,
      };
    case "file-list": {
      const { bucket, path, folder } = o.facts;
      const pub = o.facts.public;
      return {
        rule: pub ? "file-list/public-bucket" : "file-list",
        kind: isAnon(actor) ? "anon-read" : "cross-tenant-read",
        severity: pub ? "low" : isAnon(actor) ? "critical" : "high",
        target,
        title: `${who(actor)} can list ${victim}'s files in the ${pub ? "public" : "private"} bucket "${bucket}"`,
        detail: `Listing ${folder ? `folder ${folder}` : "the bucket"} returned ${victim}'s file ${path}.${pub ? " Public buckets serve files by URL, but listing them should still be limited to the owner." : ""}${seeded(o.facts.seededByService)}`,
        fix: `Limit the SELECT policy on storage.objects for bucket "${bucket}" to the owner's folder.`,
      };
    }
    case "file-overwrite":
      return {
        rule: "file-overwrite",
        kind: "cross-tenant-update",
        severity: isAnon(actor) ? "critical" : "high",
        target,
        title: `${who(actor)} can replace ${victim}'s files in bucket "${o.facts.bucket}"`,
        detail: `Uploading over ${o.facts.path} with x-upsert replaced ${victim}'s file.${seeded(o.facts.seededByService)}`,
        fix: `Limit the UPDATE policy on storage.objects for bucket "${o.facts.bucket}" to the owner's folder.`,
      };
    case "file-upload": {
      const { bucket, path, folder, victimCanSee } = o.facts;
      return {
        rule: !victimCanSee ? "file-upload/unseen" : "file-upload",
        kind: "cross-tenant-insert",
        severity: !victimCanSee ? "low" : isAnon(actor) ? "high" : "medium",
        target,
        title: `${who(actor)} can upload files into ${victim}'s folder in bucket "${bucket}"`,
        detail: `Uploaded ${path}. The folder ${folder} is where the app keeps ${victim}'s files.${
          victimCanSee
            ? ` ${victim} sees the planted file among their own.`
            : ` ${victim} cannot see it (reads are limited to the uploader), so the impact is clutter and possible name collisions in their folder.`
        }${seeded(o.facts.seededByService)}`,
        fix: `Limit the INSERT policy on storage.objects for bucket "${bucket}" to the uploader's own folder.`,
      };
    }
    case "file-delete":
      return {
        rule: "file-delete",
        kind: "cross-tenant-delete",
        severity: isAnon(actor) ? "critical" : "high",
        target,
        title: `${who(actor)} can delete ${victim}'s files in bucket "${o.facts.bucket}"`,
        detail: `Deleted ${o.facts.path}; confirmed gone with the service role, then restored.${seeded(o.facts.seededByService)}`,
        fix: `Limit the DELETE policy on storage.objects for bucket "${o.facts.bucket}" to the owner's folder.`,
      };
  }
}

const seeded = (byService: boolean) =>
  byService ? " The app's own upload path was not accepted for the test files, so the service role placed them under each user's id with the owner set; the convention may differ from the app's." : "";

const fn = (schema: Schema, target: string) => schema.functions.find((f) => `${f.schema}.${f.name}` === target);

// ---------------------------------------------------------------------------------------------

/**
 * Observations in probe order become findings in the same order. One finding per (kind, target,
 * anon-or-tenant): the other direction is noted, not repeated; a GraphQL read REST already proved
 * is noted on the REST finding.
 */
export function judgeObservations(schema: Schema, summary: WorldSummary, observations: Observation[]): Finding[] {
  const world: JudgeWorld = {
    emails: new Map(summary.tenants.filter((t) => t.email).map((t) => [t.label, t.email!])),
    profileTokens: new Map(summary.profileTokens),
  };
  const findings: Finding[] = [];
  const side = (a?: string) => (a === ANON ? "anon" : "tenant");
  for (const o of observations) {
    const d = draft(o, schema, world);
    const dup = findings.find((x) => x.kind === d.kind && x.target === d.target && side(x.evidence?.actor) === side(o.actor));
    if (o.probe === "graphql-read" && dup) {
      if (d.rule) dup.alsoRules = [...new Set([...(dup.alsoRules ?? []), `${d.rule}|${d.severity}|${side(o.actor)}`])];
      if (!dup.detail.includes("GraphQL") && !dup.title.includes("GraphQL")) dup.detail += " Also reachable through GraphQL (POST /graphql/v1).";
      continue;
    }
    if (dup) {
      // Merged into an earlier finding (a file list after a download of the same bucket): keep its rule.
      if (d.rule && d.rule !== dup.rule) dup.alsoRules = [...new Set([...(dup.alsoRules ?? []), `${d.rule}|${d.severity}|${side(o.actor)}`])];
      if (dup.evidence?.actor !== o.actor && !dup.detail.includes("both directions")) dup.detail += " Reproduced in both directions.";
      continue;
    }
    findings.push({ ...d, id: `P${String(findings.length + 1).padStart(3, "0")}`, confidence: "proven", evidence: o.evidence });
  }
  return findings;
}

