import type pg from "pg";
import type { Actor, SupabaseApi } from "../supabase/api.js";
import { sqlOne } from "./sql.js";

/**
 * The `user` primitive: create, sign in, update and delete test users by label. Sessions and
 * passwords stay in `actors` on the runner; results carry only the label and the user id.
 * Delegates to SupabaseApi and, when the auth API refuses, to a direct insert.
 */
export type UserOp =
  | { op: "create"; label: string; direct?: "fallback" | "only" }
  | { op: "sign-in"; label: string }
  | { op: "set-metadata"; label: string; data: Record<string, unknown> }
  | { op: "delete"; label: string };

export interface UserResult {
  label: string;
  userId?: string;
  /** True when the session was minted with the local JWT secret (email login off). */
  minted?: boolean;
  error?: string;
}

/**
 * When the app's signup trigger refuses new users (invite-only, terms of service), create the
 * test user directly with triggers skipped for that one insert. The scan creates whatever profile
 * rows the trigger would have made while it builds test data.
 */
export async function createUserDirect(db: pg.Client, api: SupabaseApi, label: string): Promise<Actor> {
  const { email, password } = api.newCredentials(label);
  const id = crypto.randomUUID();
  await sqlOne(db, {
    replica: true,
    statements: [
      {
        text: `insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
                               created_at, updated_at, confirmation_token, recovery_token, email_change_token_new, email_change)
       values ('00000000-0000-0000-0000-000000000000', $1, 'authenticated', 'authenticated', $2, extensions.crypt($3, extensions.gen_salt('bf')), now(),
               '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')`,
        params: [id, email, password],
      },
      {
        text: `insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
       values (gen_random_uuid(), $1::uuid, $3::text, jsonb_build_object('sub', $3::text, 'email', $2::text, 'email_verified', true), 'email', now(), now(), now())`,
        params: [id, email, id],
      },
    ],
  });
  const actor: Actor = { label, userId: id, email, password };
  await api.signInOrMint(actor);
  return actor;
}

/** Run user operations in order; `actors` is updated in place. */
export async function users(api: SupabaseApi, db: pg.Client, actors: Map<string, Actor>, ops: UserOp[]): Promise<UserResult[]> {
  const out: UserResult[] = [];
  for (const op of ops) {
    try {
      if (op.op === "create") {
        const a =
          op.direct === "only"
            ? await createUserDirect(db, api, op.label)
            : await api.createUser(op.label).catch((e) => (op.direct === "fallback" ? createUserDirect(db, api, op.label) : Promise.reject(e)));
        actors.set(op.label, a);
      } else {
        const a = actors.get(op.label);
        if (!a) throw new Error(`unknown test user ${op.label}`);
        if (op.op === "sign-in") await api.signInOrMint(a);
        else if (op.op === "set-metadata") await api.setOwnMetadata(a, op.data);
        else {
          await api.deleteUser(a);
          actors.delete(op.label);
        }
      }
      const a = actors.get(op.label);
      out.push({ label: op.label, userId: a?.userId, minted: a?.minted });
    } catch (e) {
      out.push({ label: op.label, error: (e as Error).message });
    }
  }
  return out;
}
