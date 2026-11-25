import type { Actor, ApiResponse, SupabaseApi } from "../supabase/api.js";

/**
 * The `http` and `storage` primitives: requests to the app's API as a named test user. Operations
 * name users by label ("anon", "tenant A"); tokens and passwords stay on the runner. Both delegate
 * to SupabaseApi, the one implementation of every request the scan sends.
 */
export interface HttpOp {
  /** Test user label; "anon" for no account. */
  as: string;
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
}

export interface StorageOp extends Omit<HttpOp, "as" | "body"> {
  /** Test user label, or "service" for setup and verification. */
  as: string;
  /** A string is sent as a text file, an object as JSON. */
  body?: string | object;
}

export interface HttpResult extends ApiResponse {
  /** Set when the body was cut at the size limit; the planner then treats the content as unknown. */
  truncated?: true;
}

export interface HttpLimits {
  /** Largest response text returned, in characters. Default: no limit (the in-process engine). */
  maxBody?: number;
}

export type Actors = ReadonlyMap<string, Actor>;

const ANON: Actor = { label: "anon" };
const actorFor = (actors: Actors, label: string) => (label === "anon" ? ANON : actors.get(label));
const unknownUser = (label: string): HttpResult => ({ status: 0, body: null, text: `unknown test user ${label}` });

function capped(r: ApiResponse, limits: HttpLimits): HttpResult {
  if (limits.maxBody === undefined || r.text.length <= limits.maxBody) return r;
  const text = r.text.slice(0, limits.maxBody);
  return { status: r.status, body: text, text, truncated: true };
}

/** REST, RPC and GraphQL requests, in order. */
export async function http(api: SupabaseApi, actors: Actors, ops: HttpOp[], limits: HttpLimits = {}): Promise<HttpResult[]> {
  const out: HttpResult[] = [];
  for (const op of ops) {
    const actor = actorFor(actors, op.as);
    out.push(actor ? capped(await api.request(actor, op.method, op.path, op.body, op.headers), limits) : unknownUser(op.as));
  }
  return out;
}

/** Storage API requests, in order. */
export async function storage(api: SupabaseApi, actors: Actors, ops: StorageOp[], limits: HttpLimits = {}): Promise<HttpResult[]> {
  const out: HttpResult[] = [];
  for (const op of ops) {
    const as = op.as === "service" ? "service" : actorFor(actors, op.as);
    out.push(as ? capped(await api.storage(as, op.method, op.path, op.body, op.headers), limits) : unknownUser(op.as));
  }
  return out;
}
