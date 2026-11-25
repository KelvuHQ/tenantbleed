import type { Finding } from "../core/findings.js";
import { GRANT_OR_REVOKE } from "../supabase/repo-hints.js";

/** Seed-only objects are low; a restriction defeated by default grants is explained. Inputs come from src/supabase/repo-hints.ts. */

export function downgradeSeedOnly(findings: Finding[], seedOnly: Set<string>): Finding[] {
  if (!seedOnly.size) return findings;
  return findings.map((f) =>
    f.target && seedOnly.has(f.target.toLowerCase()) && f.severity !== "info" && f.severity !== "low"
      ? {
          ...f,
          alsoRules: [...(f.alsoRules ?? []), "modifier/seed-only"],
          severity: "low",
          detail: `${f.detail} ${f.target} is created only by the seed file, not by a migration: it exists on local and branch databases but usually not in production. Reported as low; it is real anywhere the seed runs on a shared database.`,
        }
      : f,
  );
}

/**
 * A function the migrations try to restrict (GRANT EXECUTE ... TO service_role, or REVOKE ... FROM
 * PUBLIC) but never revoke from anon and authenticated stays callable from the browser: Supabase's
 * default privileges grant every new function in public to both roles directly. When a probe proves
 * such a function callable, say why the restriction did not hold.
 */
export function restrictedOnlyInIntent(statements: string[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  if (!statements.length) return out;
  const sql = statements.join("\n");
  const name = (raw: string) => {
    const parts = raw.replace(/"/g, "").split(".").map((p) => p.trim().toLowerCase());
    return parts.length > 1 ? `${parts[0]}.${parts[1]}` : `public.${parts[0]}`;
  };
  const FN = /((?:"?\w+"?\s*\.\s*)?"?\w+"?)\s*\(/;
  // Roles the author meant to have it, and roles explicitly revoked, in migration order.
  const granted = new Map<string, Set<string>>();
  const restricted = new Set<string>();
  const revoked = new Map<string, Set<string>>();
  const roles = (s: string) => new Set([...s.toLowerCase().matchAll(/\b(anon|authenticated|service_role|public)\b/g)].map((m) => m[1]));
  for (const m of sql.matchAll(GRANT_OR_REVOKE)) {
    const fn = FN.exec(m[2]);
    if (!fn) continue;
    const n = name(fn[1]);
    const r = roles(m[4]);
    if (m[1].toLowerCase() === "grant") {
      const g = granted.get(n) ?? new Set();
      for (const x of r) g.add(x);
      granted.set(n, g);
      if (!r.has("anon") && !r.has("public")) restricted.add(n);
    } else {
      const v = revoked.get(n) ?? new Set();
      for (const x of r) v.add(x);
      revoked.set(n, v);
      if (r.has("public")) restricted.add(n);
    }
  }
  for (const n of restricted) {
    const g = granted.get(n) ?? new Set();
    const v = revoked.get(n) ?? new Set();
    // Roles left out on purpose that were never revoked by name still hold the default grant.
    const leftOut = new Set(["anon", "authenticated"].filter((x) => !g.has(x) && !g.has("public") && !v.has(x)));
    if (leftOut.size) out.set(n, leftOut);
  }
  return out;
}

export function explainDefaultGrants(findings: Finding[], intended: Map<string, Set<string>>): Finding[] {
  if (!intended.size) return findings;
  return findings.map((f) => {
    const left = f.target ? intended.get(f.target.toLowerCase()) : undefined;
    const role = f.evidence?.actor === "anon" ? "anon" : "authenticated";
    if (!left || !left.has(role) || (f.kind !== "rpc-leak" && f.kind !== "rpc-write")) return f;
    return {
      ...f,
      detail: `${f.detail} The migrations grant this function only to ${[...["anon", "authenticated", "service_role"]].filter((r) => !left.has(r)).join(" and ") || "other roles"}, but Supabase grants EXECUTE on new functions to anon and authenticated directly, so leaving ${role} out does not take it away. Revoke it from ${role} by name.`,
      fix: `revoke execute on function ${f.target} from ${[...left].join(", ")};${role === "authenticated" ? " (or check auth.uid() inside the function)" : ""}`,
    };
  });
}
