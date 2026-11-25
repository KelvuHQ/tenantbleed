import type { Finding } from "../core/findings.js";
import { qualified, type RpcFunction, type Schema } from "../supabase/introspect.js";

const TRIVIAL = /^\s*\(?\s*true\s*\)?\s*$/i;

/** A function body (comments stripped) that does nothing but return true. */
const stripComments = (b: string) => b.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
const RETURNS_TRUE = /^\s*(?:begin\s+)?return\s+\(?\s*true\s*\)?\s*;?\s*(?:end\s*;?)?\s*$/i;
const SELECTS_TRUE = /^\s*select\s+\(?\s*true\s*\)?\s*;?\s*$/i;

/** schema.name and bare name of every function that only ever returns true (through up to 3 calls). */
function constantTrueFns(s: Schema): Set<string> {
  const bodies = new Map<string, string>();
  for (const f of s.functions) bodies.set(`${f.schema}.${f.name}`, f.body);
  for (const [k, b] of Object.entries(s.helpers ?? {})) bodies.set(k, b);
  const set = new Set<string>();
  const direct = (b: string) => {
    const t = stripComments(b).trim();
    return RETURNS_TRUE.test(t) || SELECTS_TRUE.test(t);
  };
  for (const [k, b] of bodies) if (direct(b)) set.add(k);
  // A function that only returns/selects another constant-true function is constant-true too.
  for (let pass = 0; pass < 3; pass++) {
    for (const [k, b] of bodies) {
      if (set.has(k)) continue;
      const t = stripComments(b).trim();
      const m = /^\s*(?:begin\s+)?(?:return|select)\s+(?:\(\s*select\s+)?"?(\w+)"?\s*\(/i.exec(t);
      if (m && (set.has(m[1]) || [...set].some((x) => x.split(".").pop() === m[1]))) set.add(k);
    }
  }
  const out = new Set<string>();
  for (const k of set) {
    out.add(k);
    out.add(k.split(".").pop()!);
  }
  return out;
}

/** Schema-only checks. They explain WHY a proven finding happens; they are never the headline. */
/** Statements that remove isolation: RLS off, policies dropped or changed, rights granted to the API roles. */
const WEAKENS_ACCESS = /\b(disable\s+row\s+level\s+security|no\s+force\s+row\s+level\s+security|drop\s+policy|alter\s+policy|grant\s+[a-z ,]+\s+on\s+[^;']*?\s+to\s+(?:anon|authenticated|public))\b/i;

/**
 * The text argument an EXECUTE runs as SQL: the argument itself (EXECUTE sql_query), glued in with ||,
 * or placed by format() with %s. Quoted names and values (quote_ident, quote_literal, format with only
 * %I and %L) and values bound with USING are not the caller's SQL.
 */
export function callerSql(f: { body: string; args: { name: string; type: string }[] }): string | undefined {
  const body = f.body.replace(/--[^\n]*/g, "");
  const textArgs = f.args.filter((a) => a.name && /^(text|character varying|varchar|citext)/.test(a.type));
  if (!textArgs.length) return undefined;
  for (const m of body.matchAll(/\bexecute\s+([\s\S]*?)(?:;|$)/gi)) {
    // Only the statement text: INTO and USING come after it.
    let e = m[1].replace(/\b(into|using)\b[\s\S]*$/i, "");
    e = e.replace(/quote_(literal|ident|nullable)\s*\(\s*[\w.]+\s*\)/gi, "''");
    // format('...%I...%L...', ...) with no %s quotes everything it places.
    e = e.replace(/format\s*\(\s*'((?:[^']|'')*)'((?:[^()]|\([^()]*\))*)\)/gi, (all, tpl: string) => (/%s/.test(tpl) ? all : "''"));
    for (const a of textArgs) if (new RegExp(`(^|[^\\w.])${a.name.replace(/[^\w]/g, "")}\\b`, "i").test(e)) return a.name;
  }
  return undefined;
}

export function staticChecks(s: Schema, exposed: Set<string>): Finding[] {
  const out: Finding[] = [];
  let n = 0;
  const constTrue = constantTrueFns(s);
  // A policy expression that is exactly one call to a constant-true helper (is_org_member() that
  // just returns true), optionally wrapped in parens or (select ...).
  const helperAlwaysTrue = (expr: string): string | undefined => {
    const m = /^\s*\(*\s*(?:select\s+)?"?(\w+)"?\s*\([^;]*\)\s*\)*\s*$/i.exec(expr.trim());
    return m && constTrue.has(m[1]) ? m[1] : undefined;
  };
  const id = () => `S${String(++n).padStart(3, "0")}`;

  for (const r of s.relations) {
    if (!exposed.has(r.schema)) continue;
    const q = qualified(r);
    const granted = r.grants.anon.select || r.grants.authenticated.select;

    if (r.kind === "table" && !r.rlsEnabled && granted) {
      out.push({
        id: id(),
        rule: "static/rls-disabled",
        kind: "static",
        severity: "high",
        target: q,
        title: "Row level security is disabled on an API-exposed table",
        detail: `${q} is reachable through the Data API (anon select=${r.grants.anon.select}, authenticated select=${r.grants.authenticated.select}) and has RLS off, so no policy filters rows.`,
        confidence: "static",
        fix: `alter table ${q} enable row level security; then add policies scoped to the tenant.`,
      });
    }

    if (r.kind === "view" && !r.securityInvoker && granted) {
      out.push({
        id: id(),
        rule: "static/definer-view",
        kind: "static",
        severity: "medium",
        target: q,
        title: "View runs with its owner's privileges and bypasses RLS",
        detail: `${q} has no security_invoker option, so it reads underlying tables as its owner (usually postgres) and ignores their policies.`,
        confidence: "static",
        fix: `alter view ${q} set (security_invoker = true);`,
      });
    }
  }

  for (const p of s.policies) {
    if (!exposed.has(p.schema)) continue;
    const q = `${p.schema}.${p.table}`;
    const writes = p.cmd !== "SELECT";
    const appliesToUsers = p.roles.some((role) => ["public", "anon", "authenticated"].includes(role));

    for (const [label, expr] of [["using", p.using], ["with check", p.withCheck]] as const) {
      if (!expr || !appliesToUsers) continue;

      if (TRIVIAL.test(expr) && !(p.cmd === "INSERT" && label === "with check" && p.roles.includes("authenticated") && !p.roles.includes("anon"))) {
        out.push({
          id: id(),
          rule: "static/policy-always-true",
          kind: "static",
          severity: writes ? "high" : "low",
          target: q,
          title: `Policy "${p.name}" is unconditional (${p.cmd}, ${label} true)`,
          detail: writes
            ? `Any ${p.roles.join("/")} user passes ${p.cmd} on every row of ${q}.`
            : `Every ${p.roles.join("/")} user can read every row of ${q}. Fine for public catalogs, a leak for tenant data.`,
          confidence: "static",
        });
      } else {
        const helper = helperAlwaysTrue(expr);
        if (helper) {
          out.push({
            id: id(),
            rule: "static/policy-helper-always-true",
            kind: "static",
            // Higher than an explicit `true`: the policy claims an isolation it does not give.
            severity: writes || p.roles.includes("anon") ? "high" : "medium",
            target: q,
            title: `Policy "${p.name}" calls ${helper}(), which always returns true (${p.cmd}, ${label})`,
            detail: `${q} looks tenant-isolated, but its ${label} is \`${helper}(...)\` and that function only ever returns true (a placeholder or stub), so every ${p.roles.join("/")} user ${writes ? `passes ${p.cmd} on` : "reads"} every row.`,
            confidence: "static",
          });
        }
      }

      if (/user_metadata/i.test(expr)) {
        out.push({
          id: id(),
          rule: "static/policy-user-metadata",
          kind: "static",
          severity: "high",
          target: q,
          title: `Policy "${p.name}" trusts user_metadata`,
          detail: `user_metadata is writable by the user themselves (auth.updateUser), so a ${label} expression based on it can be satisfied by anyone: ${expr}`,
          confidence: "static",
          fix: "Use app_metadata (only the service role can write it) or a membership table lookup.",
        });
      }
    }
  }

  const checks = callerChecker(s);
  const writer = reaches(s, (b) => WRITES.test(b) || /\bexecute\b/i.test(b) || /\bnet\.http_|\bhttp_(post|get)\b|extensions\.http\s*\(/i.test(b));
  const tableNames = new Set(s.relations.map((r) => r.name.toLowerCase()));
  // Conservative on purpose: any FROM/JOIN/INTO/UPDATE, dynamic SQL, or a known table name counts.
  const touches = reaches(
    s,
    (b) =>
      /\b(from|join|into|update|table)\s+(only\s+)?[\w".]+/i.test(b) || /\bexecute\b/i.test(b) || /\b(auth|storage|vault)\.\w+/i.test(b) || [...b.toLowerCase().matchAll(/[a-z_][a-z0-9_]*/g)].some((m) => tableNames.has(m[0])),
  );
  for (const f of s.functions) {
    if (!f.securityDefiner || !(f.execAnon || f.execAuthenticated) || !exposed.has(f.schema)) continue;
    const callers = [f.execAnon && "anon", f.execAuthenticated && "authenticated"].filter(Boolean).join(" and ");
    const writesAuth = /\b(insert\s+into|update|delete\s+from)\s+auth\.\w+/i.test(f.body);
    const checksCaller = checks(f);
    const safe = safeByConstruction(f, s, writer, touches);
    // Reads with no arguments cannot be aimed at one user, and a number behind a login cannot carry
    // another user's records; the RPC probe still checks what they return.
    const cannotTarget = !f.volatile && (f.args.length === 0 || (!f.execAnon && !f.returnsSet && /^(integer|bigint|smallint|numeric|real|double precision)$/.test(f.returnType)));
    const sig = `${f.schema}.${f.name}(${f.args.map((a) => a.type).join(", ")})`;
    // SQL text from the caller, run as the owner: any statement, every policy skipped. The schema
    // shows it; a test call would have to run an attacker's statement to.
    const sqlArg = callerSql(f);
    if (sqlArg) {
      out.push({
        id: id(),
        rule: "static/definer-exec-arg",
        kind: "static",
        severity: "critical",
        target: `${f.schema}.${f.name}`,
        title: `SECURITY DEFINER function runs SQL text the caller sends, callable by ${callers}`,
        detail: `${sig} runs EXECUTE on its argument ${sqlArg}${checksCaller ? " (after a caller check, which still lets those callers run any statement)" : ""}, with owner privileges. Whoever can call it runs any SQL as the function's owner: read or change every tenant's rows, skip every policy.`,
        confidence: "static",
        fix: `revoke execute on function ${f.schema}.${f.name} from anon, authenticated; never run caller text as SQL (pass values with USING and names with format('%I')).`,
      });
    }
    // Isolation switched off for any caller: RLS disabled, a policy dropped or changed, table rights
    // handed to the API roles. A quoted table name does not help; the statement is the attack.
    const weakens = !checksCaller && WEAKENS_ACCESS.exec(f.body.replace(/--[^\n]*/g, ""));
    if (weakens) {
      out.push({
        id: id(),
        rule: "static/definer-security-ddl",
        kind: "static",
        severity: "critical",
        target: `${f.schema}.${f.name}`,
        title: `SECURITY DEFINER function weakens access control for any caller (${callers})`,
        detail: `${sig} runs "${weakens[0].replace(/\s+/g, " ")}" with owner privileges and no caller check. Anyone who can call it removes the isolation between tenants for that table, through the API.`,
        confidence: "static",
        fix: `drop the function, or revoke execute on function ${f.schema}.${f.name} from anon, authenticated and run such changes in migrations only.`,
      });
    }
    // Risks outside the database, stated by the schema because no call can show them.
    if (!checksCaller && SENDS_HTTP.test(f.body)) {
      const key = serviceRoleKeyIn(f.body);
      out.push({
        id: id(),
        rule: "static/definer-http",
        kind: "static",
        severity: key ? "critical" : f.execAnon ? "high" : "medium",
        target: `${f.schema}.${f.name}`,
        title: key ? `SECURITY DEFINER function sends HTTP requests with a service role key, callable by ${callers}` : `SECURITY DEFINER function sends HTTP requests for any caller (${callers})`,
        detail: `${sig} makes the database send an HTTP request, with no caller check, and the caller's arguments go into it.${
          key ? " The request carries a service role key written in the function, so any caller acts as the service role (for example deleting any stored file). The key is also in the migration, readable by anyone with the repository." : " The scan does not follow requests that leave the database, so check what the request can do."
        }`,
        confidence: "static",
        fix: `revoke execute on function ${f.schema}.${f.name} from anon, authenticated;${key ? " move the key to vault or an Edge Function secret, and rotate it;" : ""} or check auth.uid() inside.`,
      });
    }
    if (!checksCaller && f.returnType !== "void" && /\bvault\.decrypted_secrets\b/i.test(f.body)) {
      out.push({
        id: id(),
        rule: "static/definer-vault",
        kind: "static",
        severity: f.execAnon ? "high" : "medium",
        target: `${f.schema}.${f.name}`,
        title: `SECURITY DEFINER function hands a vault secret to any caller (${callers})`,
        detail: `${sig} reads vault.decrypted_secrets with owner privileges and returns a value, with no caller check. Whatever is stored under that name is readable through the API.`,
        confidence: "static",
        fix: `revoke execute on function ${f.schema}.${f.name} from anon, authenticated; secrets belong in server-side code.`,
      });
    }
    if (writesAuth && checksCaller) {
      // Deleting one's own account or session, or an admin action behind a role check.
      out.push({
        id: id(),
        rule: "static/auth-writer-checked",
        kind: "static",
        severity: "info",
        target: `${f.schema}.${f.name}`,
        title: "SECURITY DEFINER function writes to the auth schema (checks the caller)",
        detail: `${sig} modifies auth.* tables with owner privileges, and checks the caller first (auth.uid() or a helper that does): typically the caller's own account or session, or an admin-only action. Executable by ${callers}.`,
        confidence: "static",
      });
      continue;
    }
    if (writesAuth) {
      out.push({
        id: id(),
        rule: "static/auth-writer",
        kind: "static",
        severity: f.execAnon ? "high" : "medium",
        target: `${f.schema}.${f.name}`,
        title: `SECURITY DEFINER function writes to the auth schema and is callable by ${callers}`,
        detail: `${sig} modifies auth.* tables with owner privileges. Callers can create or change users outside the Auth API (no signup settings, captcha or rate limits).`,
        confidence: "static",
        fix: `revoke execute on function ${f.schema}.${f.name} from anon, authenticated; or move it to a non-exposed schema.`,
      });
      continue;
    }
    out.push({
      id: id(),
      rule: f.returnType === "boolean" ? "static/definer-yes-no" : checksCaller ? "static/definer-checks-caller" : cannotTarget ? "static/definer-cannot-target" : safe ? "static/definer-safe-by-construction" : "static/definer-unchecked",
      kind: "static",
      // Boolean helpers (is_member style) and functions that check the caller are the normal pattern.
      severity: f.returnType === "boolean" || checksCaller || cannotTarget || safe ? "info" : f.execAnon ? "medium" : "low",
      target: `${f.schema}.${f.name}`,
      title: checksCaller ? "SECURITY DEFINER function callable through the API (checks the caller)" : "SECURITY DEFINER function callable through the API without a visible caller check",
      detail: `${sig} runs as its owner and bypasses RLS. Executable by ${callers}.${
        checksCaller
          ? " It checks the caller (auth.uid(), the JWT, the request role, or a helper that does); the RPC probe tests it with another tenant's values."
          : cannotTarget
            ? " It only reads and cannot be aimed at one user (no arguments, or a single number behind a login); the RPC probe checked its output for other users' data."
            : safe
              ? ` ${safe}`
            : " Neither its body nor the functions it calls reference auth.uid() or auth.jwt(); make sure it cannot return or change other tenants' data."
      }`,
      confidence: "static",
      fix: checksCaller ? undefined : `revoke execute on function ${f.schema}.${f.name} from anon, authenticated; or check auth.uid() inside.`,
    });
  }

  return out;
}

const SHARED_SENSITIVE = /(^|_)(e?mail|phone|mobile|address|street|zip|postal|gstin|tax|vat|iban|card|ssn|dob|birth|balance|salary|secret|token|notes?)($|_)/i;

/**
 * A shared table (no path from its rows to a user) whose policies let everyone, or every signed-in
 * user, read or write it. Today these are only counted ("N shared by design"); this adds a report
 * line so the access is not silent. Shared is read from coverage (the `shared` flag the scan set).
 */
export function sharedOpenChecks(s: Schema, coverage: { relation: string; kind: string; shared?: boolean }[]): Finding[] {
  const out: Finding[] = [];
  let n = 0;
  const id = () => `H${String(++n).padStart(3, "0")}`;
  const constTrue = constantTrueFns(s);
  const sharedTables = new Set(coverage.filter((c) => c.shared && c.kind !== "function" && c.kind !== "bucket").map((c) => c.relation));
  const everyone = (expr: string) => TRIVIAL.test(expr) || !!/^\s*\(*\s*(?:select\s+)?"?(\w+)"?\s*\([^;]*\)\s*\)*\s*$/i.exec(expr.trim())?.[1] && constTrue.has(/^\s*\(*\s*(?:select\s+)?"?(\w+)"?\s*\(/i.exec(expr.trim())?.[1] ?? "");
  const signedIn = (expr: string) => /auth\.uid\(\)\s*is\s+not\s+null|auth\.role\(\)\s*=\s*'authenticated'/i.test(expr);
  for (const r of s.relations) {
    const q = `${r.schema}.${r.name}`;
    if (r.kind !== "table" || !sharedTables.has(q)) continue;
    const pols = s.policies.filter((p) => p.schema === r.schema && p.table === r.name && p.roles.some((role) => ["public", "anon", "authenticated"].includes(role)));
    const openWrite = pols.find((p) => p.cmd !== "SELECT" && (everyone(p.withCheck ?? p.using ?? "") || signedIn(p.withCheck ?? p.using ?? "")));
    const openRead = pols.find((p) => (p.cmd === "SELECT" || p.cmd === "ALL") && p.using && (everyone(p.using) || signedIn(p.using)));
    const anonRead = openRead && pols.some((p) => (p.cmd === "SELECT" || p.cmd === "ALL") && p.roles.includes("anon") && p.using && (everyone(p.using) || signedIn(p.using)) && everyone(p.using));
    const sensitive = r.columns.filter((c) => SHARED_SENSITIVE.test(c.name)).map((c) => c.name);
    if (openWrite) {
      const anon = openWrite.roles.includes("anon") && everyone(openWrite.withCheck ?? openWrite.using ?? "");
      out.push({
        id: id(),
        rule: "static/shared-open-write",
        kind: "static",
        severity: anon ? "high" : "medium",
        target: q,
        title: `${q} is shared and ${anon ? "anyone" : "every signed-in user"} can ${openWrite.cmd} it (policy "${openWrite.name}")`,
        detail: `${q} has no link from its rows to a user, and policy "${openWrite.name}" lets ${anon ? "any visitor" : "every signed-in user"} ${openWrite.cmd} every row.${sensitive.length ? ` It holds ${sensitive.join(", ")}.` : ""} Fine for a public catalog that staff may edit; a leak if this is one tenant's data. In an invite-only app (signups off) every account is staff, so confirm that every staff member may change this.`,
        confidence: "static",
      });
    }
    if (anonRead && sensitive.length) {
      out.push({
        id: id(),
        rule: "static/shared-anon-read",
        kind: "static",
        severity: "high",
        target: q,
        title: `${q} is shared and a visitor can read it, including ${sensitive.join(", ")}`,
        detail: `${q} has no link to a user and an open SELECT policy lets a signed-out visitor read every row, including ${sensitive.join(", ")}. If this is personal or financial data, it is a leak even in an invite-only app.`,
        confidence: "static",
      });
    }
  }
  return out;
}

/** pg_net, the http extension, or the older http_post/http_get helpers. */
const SENDS_HTTP = /\bnet\.http_\w+\s*\(|\bhttp_(post|get|put|delete|patch)\s*\(|\bextensions\.http\s*\(|\bhttp\s*\(\s*\(/i;

/** A JWT written in the code whose claims say role service_role. */
function serviceRoleKeyIn(body: string): boolean {
  for (const m of body.matchAll(/eyJ[\w-]+\.(eyJ[\w-]+)\.[\w-]+/g)) {
    try {
      if (JSON.parse(Buffer.from(m[1], "base64url").toString("utf8")).role === "service_role") return true;
    } catch {
      // Not a JWT after all.
    }
  }
  return false;
}

/** References to the caller: auth helpers, JWT claims, the request role or headers, the session user. */
const CALLER_REF =
  /auth\.(uid|jwt|role|email)\s*\(|current_setting\s*\(\s*'(role|request\.jwt\.claims?[\w.]*|request\.headers?[\w.]*)'|\b(current_user|session_user)\b|current_user_account_role|is_member|has_role|authorize\s*\(/i;
/** Calls to other functions, schema-qualified or not. */
const CALL = /\b(?:("?)(\w+)\1\.)?"?(\w+)"?\s*\(/g;
const MAX_DEPTH = 3;

/**
 * Whether a function checks its caller, directly or through the functions it calls (is_org_member(),
 * private.require_admin()), up to three calls deep.
 */
function callerChecker(s: Schema) {
  const bodies = new Map<string, string[]>();
  const add = (key: string, body: string) => bodies.set(key, [...(bodies.get(key) ?? []), body]);
  for (const f of s.functions) add(`${f.schema}.${f.name}`, f.body);
  for (const [k, b] of Object.entries(s.helpers ?? {})) add(k, b);
  const byName = new Map<string, string[]>();
  for (const k of bodies.keys()) byName.set(k.split(".").pop()!, [...(byName.get(k.split(".").pop()!) ?? []), k]);
  const memo = new Map<string, boolean>();
  const visit = (key: string, depth: number, seen: Set<string>): boolean => {
    if (memo.has(key)) return memo.get(key)!;
    const own = bodies.get(key) ?? [];
    if (own.some((b) => CALLER_REF.test(b))) return memo.set(key, true), true;
    if (depth >= MAX_DEPTH) return false;
    seen.add(key);
    for (const b of own)
      for (const m of b.matchAll(CALL)) {
        const callee = m[2] ? [`${m[2]}.${m[3]}`] : (byName.get(m[3]) ?? []);
        for (const c of callee) if (!seen.has(c) && bodies.has(c) && visit(c, depth + 1, seen)) return memo.set(key, true), true;
      }
    return false;
  };
  return (f: RpcFunction) => visit(`${f.schema}.${f.name}`, 0, new Set());
}

/** Statements that change data. UPDATE may carry an alias (update public.todos t set); "for update" is a lock, not a write. */
const WRITES = /\b(insert\s+into|(?<!\bfor\s)(?<!\bno\s)(?<!\bkey\s)update\s+(only\s+)?[\w".]+\s+((as\s+)?\w+\s+)?set|delete\s+from|truncate|merge\s+into)\b/i;
/** Argument names that carry a secret the caller must already hold (an invite token, its hash). */
const SECRET_ARG = /(^|_)(token|secret|nonce|otp)(_hash)?$|(^|_)token_hash$/i;

/**
 * Whether some property holds for a function's body or the app functions it calls, up to three calls
 * deep (the same walk as the caller check).
 */
function reaches(s: Schema, test: (body: string) => boolean) {
  const bodies = new Map<string, string[]>();
  const add = (key: string, body: string) => bodies.set(key, [...(bodies.get(key) ?? []), body]);
  for (const f of s.functions) add(`${f.schema}.${f.name}`, f.body);
  for (const [k, b] of Object.entries(s.helpers ?? {})) add(k, b);
  const byName = new Map<string, string[]>();
  for (const k of bodies.keys()) byName.set(k.split(".").pop()!, [...(byName.get(k.split(".").pop()!) ?? []), k]);
  const visit = (key: string, depth: number, seen: Set<string>): boolean => {
    const own = bodies.get(key) ?? [];
    if (own.some(test)) return true;
    if (depth >= MAX_DEPTH) return false;
    seen.add(key);
    for (const b of own)
      for (const m of b.matchAll(CALL)) {
        const callee = m[2] ? [`${m[2]}.${m[3]}`] : (byName.get(m[3]) ?? []);
        for (const c of callee) if (!seen.has(c) && bodies.has(c) && visit(c, depth + 1, seen)) return true;
      }
    return false;
  };
  return (f: RpcFunction) => visit(`${f.schema}.${f.name}`, 0, new Set());
}

/**
 * Reasons a definer function cannot hand one user another user's data, read from its body: it
 * touches no table at all (a code generator, an advisory lock); it returns nothing and writes
 * nothing; or it acts only when the caller passes a secret that matches a stored value (an invite
 * token). Returns the reason in plain words, or undefined.
 */
function safeByConstruction(f: RpcFunction, s: Schema, writer: (f: RpcFunction) => boolean, touches: (f: RpcFunction) => boolean): string | undefined {
  if (!touches(f)) return "It reads and writes no table (it only computes a value or takes a lock), so it holds no one's data.";
  if (["void", "trigger"].includes(f.returnType) && !writer(f)) return "It returns nothing and changes nothing (it only checks and raises errors), so a caller gets no data out of it.";
  const secret = f.args.filter((a) => SECRET_ARG.test(a.name.replace(/^p_/, "")) && /^(text|character varying|uuid|bytea)$/.test(a.type));
  // The secret must be compared in a condition (where, and, if, when) or passed to a check function,
  // not stored (update ... set value = secret is the opposite: the caller supplies the secret).
  const guarded = (n: string) =>
    new RegExp(`\\b(where|and|or|if|when|not)\\b[^;]{0,200}?(=\\s*${n}\\b|\\b${n}\\s*(=|!=|<>))`, "i").test(f.body) || new RegExp(`\\b(if|not)\\b[^;]{0,80}?\\w+\\s*\\(\\s*${n}\\s*\\)`, "i").test(f.body);
  if (secret.length && secret.every((a) => guarded(a.name)) && !secret.some((a) => new RegExp(`\\bset\\b[^;]{0,200}?=\\s*${a.name}\\b`, "i").test(f.body)))
    return `It acts only when the caller passes a secret that matches a stored value (${secret.map((a) => a.name).join(", ")}), so it is safe as long as that value is long, random and only sent to the right person.`;
  return undefined;
}
