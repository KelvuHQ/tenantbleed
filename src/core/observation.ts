import type { Evidence } from "./findings.js";

/**
 * What a probe saw, as plain JSON: no verdict, no severity, no wording. The engine (public, in the
 * Action) produces observations; the judge (private, behind the API) turns them into findings.
 * Every field is a primitive, an array or a plain object so it crosses the API unchanged.
 */
type Base<P extends string, F> = { probe: P; target: string; actor: string; victim: string; evidence: Evidence; facts: F };

export type Row = Record<string, unknown>;

export type Observation =
  /** Rows of the victim came back from a REST read. `hits` are the victim's markers found, row by row. */
  | Base<"read", { relKind: "table" | "view"; leaked: Row[]; hits: string[] }>
  /** Rows came back only after a parent (or the row itself) was put in a normal state (state='live'). */
  | Base<"read-state", { leaked: Row[]; precondition: string; sensitive: string[] }>
  /** Rows of the victim came back from /graphql/v1. */
  | Base<"graphql-read", { relKind: "table" | "view"; leakedCount: number }>
  /** A PATCH changed a column of the victim's row (verified in the database). */
  | Base<"update", { column: string }>
  /** The attacker re-pointed its own row at the victim's parent row. */
  | Base<"reparent", { refTable: string; columns: string[]; victimCanSee: boolean }>
  /** The attacker inserted a row whose tenant key points at the victim's parent row. */
  | Base<"insert", { parentTable: string; columns: string[]; victimCanSee: boolean }>
  /** The attacker inserted a row naming the victim in its person columns. */
  | Base<"impersonate", { columns: string[]; personAndTenantInKey: boolean }>
  /** A function returned the victim's data. */
  | Base<"rpc-leak", { output: string; hits: string[]; derived?: { blank: string; by?: "removal" } }>
  /** A function changed the victim's rows (rolled back). `changed` lists "table key: col a -> b; ...". */
  | Base<"rpc-write", { changed: string[]; shared?: boolean; primed?: string }>
  /** Editing user_metadata let the attacker read the victim's rows. */
  | Base<"metadata", { policy: string; keys: string[] }>
  /** A user rewrote a privilege column the app trusts on their own row; unlocked lists what it opened. */
  | Base<"self-escalation", { column: string; value: string; unlocked: string[]; steppedDown?: string }>
  /** A user inserted a privileged row for themselves in another tenant (a self-add-as-admin policy). */
  | Base<"self-enrollment", { column: string; value: string; parentTable: string; policy: string; unlocked: string[] }>
  /** A DELETE removed the victim's row (verified, then restored). */
  | Base<"delete", Record<string, never>>
  /** Storage: the attacker downloaded, listed, replaced, uploaded into, or deleted the victim's file. */
  | Base<"file-download", { bucket: string; path: string; seededByService: boolean }>
  | Base<"file-list", { bucket: string; path: string; folder?: string; public: boolean; seededByService: boolean }>
  | Base<"file-overwrite", { bucket: string; path: string; seededByService: boolean }>
  | Base<"file-upload", { bucket: string; path: string; folder: string; victimCanSee: boolean; seededByService: boolean }>
  | Base<"file-delete", { bucket: string; path: string; seededByService: boolean }>;

/** What the judge needs to know about the test world, beyond the schema catalog. */
export interface WorldSummary {
  tenants: { label: string; email?: string }[];
  /** Marker value written into a profile table, and the column it went into. */
  profileTokens: [string, string][];
}
