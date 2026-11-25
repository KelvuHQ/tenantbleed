import type { RpcFunction } from "../supabase/introspect.js";

/**
 * "Check it yourself" prompts: for a warning the scan could neither prove nor clear, a plain-English
 * request the user pastes into their AI builder (Lovable, Bolt, Cursor, Claude). It names the exact
 * object, says what the scan already tried, and asks for a yes or no with a fix. The verdict stays
 * deterministic; the prompt only hands the open question to the person who knows the app.
 */

const callers = (f?: RpcFunction) =>
  !f ? "can be called from the browser" : f.execAnon ? "anyone can call it from the browser, even without an account" : "any signed-in user can call it from the browser";

const ASK =
  "Answer yes or no first, then explain in plain words. If the answer is yes, write a new SQL migration that fixes it without breaking access for the rightful owner.";

export interface PromptSubject {
  lint: string;
  target: string;
  verdict: "flagged" | "not-tested";
  /** Why the scan did not settle it, already in plain words. */
  reason: string;
  fn?: RpcFunction;
}

export function checkPrompt(s: PromptSubject): string {
  const { target: t, fn } = s;
  const tried = s.verdict === "flagged" ? `A security scan called it as one test user with another user's ids and data and saw no leak, but it cannot prove it is safe.` : `A security scan could not test it: ${s.reason}`;
  if (/security_definer_function_executable|dynamic_sql/.test(s.lint) || fn) {
    const dyn = /dynamic_sql/.test(s.lint) ? " It also builds SQL from text, so check that no argument can change the query (SQL injection)." : "";
    return [
      `In my Supabase project, the database function ${t} runs with full database rights (SECURITY DEFINER), so it skips the row level security rules, and ${callers(fn)}.`,
      tried,
      `Please check: can a caller use ${t} to read, change or delete data that belongs to another user or another organization, for example by passing someone else's id, email or slug?${dyn}`,
      `If it should only run for its owner, add a check inside it that the signed-in user (auth.uid()) owns or belongs to that record. If it is only meant for the backend or scheduled jobs, revoke EXECUTE on it from anon and authenticated instead.`,
      ASK,
    ].join("\n");
  }
  if (s.lint === "security_definer_view") {
    return [
      `In my Supabase project, the view ${t} runs with its owner's rights, so it ignores the row level security rules of the tables it reads.`,
      tried,
      `Please check: can one user see another user's or another organization's rows through ${t}? If yes, recreate it with (security_invoker = true) so the table rules apply.`,
      ASK,
    ].join("\n");
  }
  if (s.lint === "rls_references_user_metadata") {
    return [
      `In my Supabase project, a row level security rule on ${t} reads user_metadata, which every user can edit for themselves.`,
      tried,
      `Please check: can a user give themselves access to other users' rows of ${t} by editing their own user_metadata? If yes, move that value to app_metadata or a memberships table.`,
      ASK,
    ].join("\n");
  }
  if (s.lint === "rls_policy_always_true") {
    return [
      `In my Supabase project, a row level security rule on ${t} allows every row (true), so it does not limit who can use it.`,
      tried,
      `Please check: is ${t} meant to be fully public for that action? If it holds data that belongs to a user or an organization, limit the rule to the owner or members.`,
      ASK,
    ].join("\n");
  }
  return [
    `In my Supabase project, Supabase's security checker warns about ${t} (${s.lint.replace(/_/g, " ")}).`,
    tried,
    `Please check: can one user read, change or delete another user's or another organization's data in ${t}? If yes, add row level security rules that limit each row to its owner or the owner's organization.`,
    ASK,
  ].join("\n");
}
