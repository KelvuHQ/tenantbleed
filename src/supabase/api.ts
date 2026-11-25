import { createHmac } from "node:crypto";

export interface Stack {
  apiUrl: string;
  anonKey: string;
  serviceKey: string;
  dbUrl: string;
  /** Local stack JWT secret. Lets the scan mint sessions when the app turns email login off. */
  jwtSecret?: string;
}

export interface Actor {
  label: string; // "anon", "tenant A", "tenant B"
  userId?: string;
  email?: string;
  password?: string;
  token?: string; // user access token; undefined for anon
  /** True when the token was minted with the JWT secret instead of a password sign-in. */
  minted?: boolean;
  userMetadata?: Record<string, unknown>;
  /** Extra app_metadata claims (set by the backend, e.g. role: "admin"); only for minted tokens. */
  appMetadata?: Record<string, unknown>;
}

const b64url = (v: string | Buffer) => Buffer.from(v).toString("base64url");

export interface ApiResponse {
  status: number;
  body: unknown;
  text: string;
}

export class SupabaseApi {
  constructor(private stack: Stack) {}

  private headers(actor: Actor, extra: Record<string, string> = {}): Record<string, string> {
    return {
      apikey: this.stack.anonKey,
      Authorization: `Bearer ${actor.token ?? this.stack.anonKey}`,
      "Content-Type": "application/json",
      ...extra,
    };
  }

  async request(actor: Actor, method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<ApiResponse> {
    const res = await fetch(this.stack.apiUrl + path, {
      method,
      headers: this.headers(actor, extra),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: unknown = text;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      /* keep text */
    }
    return { status: res.status, body: parsed, text };
  }

  /**
   * Storage API call. `as` is an actor or "service" (setup and verification only). A string body is
   * sent as a text file, an object as JSON.
   */
  async storage(as: Actor | "service", method: string, path: string, body?: string | object, extra: Record<string, string> = {}): Promise<ApiResponse> {
    const service = as === "service";
    const headers: Record<string, string> = {
      apikey: service ? this.stack.serviceKey : this.stack.anonKey,
      Authorization: `Bearer ${service ? this.stack.serviceKey : (as.token ?? this.stack.anonKey)}`,
      ...(body === undefined ? {} : { "Content-Type": typeof body === "string" ? "text/plain" : "application/json" }),
      ...extra,
    };
    const res = await fetch(this.stack.apiUrl + path, { method, headers, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
    const text = await res.text();
    let parsed: unknown = text;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      /* keep text */
    }
    return { status: res.status, body: parsed, text };
  }

  /** Reproduction command. Tokens are shown as variables so reports are safe to paste into PRs. */
  curl(actor: Actor, method: string, path: string, body?: unknown, extra: Record<string, string> = {}): string {
    const tokenVar = actor.token ? `$TOKEN_${actor.label.replace(/\W+/g, "_").toUpperCase()}` : "$ANON_KEY";
    const parts = [
      `curl -X ${method} '${this.stack.apiUrl}${path}'`,
      `-H "apikey: $ANON_KEY"`,
      `-H "Authorization: Bearer ${tokenVar}"`,
      ...Object.entries(extra).map(([k, v]) => `-H '${k}: ${v}'`),
    ];
    if (typeof body === "string") parts.push(`-H 'Content-Type: text/plain' --data-binary '${body}'`);
    else if (body !== undefined) parts.push(`-H 'Content-Type: application/json' -d '${JSON.stringify(body)}'`);
    return parts.join(" ");
  }

  async createUser(label: string): Promise<Actor> {
    const email = `tp-${label.replace(/\W+/g, "").toLowerCase()}-${Date.now()}@tenantbleed.test`;
    const password = `Tp!${crypto.randomUUID()}`;
    const res = await fetch(`${this.stack.apiUrl}/auth/v1/admin/users`, {
      method: "POST",
      headers: { apikey: this.stack.serviceKey, Authorization: `Bearer ${this.stack.serviceKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, email_confirm: true }),
    });
    if (!res.ok) throw new Error(`cannot create test user: ${res.status} ${await res.text()}`);
    const user = (await res.json()) as { id: string };
    const actor: Actor = { label, userId: user.id, email, password };
    await this.signInOrMint(actor);
    return actor;
  }

  /** Credentials for a user created without the auth API (see createUserDirect in cli). */
  newCredentials(label: string) {
    return { email: `tp-${label.replace(/\W+/g, "").toLowerCase()}-${Date.now()}@tenantbleed.test`, password: `Tp!${crypto.randomUUID()}` };
  }

  /**
   * Password sign-in, or, when the app turned email login off, a session token signed with the
   * local JWT secret carrying the same claims the auth server would issue.
   */
  async signInOrMint(actor: Actor): Promise<void> {
    try {
      await this.signIn(actor);
    } catch (e) {
      if (!this.stack.jwtSecret) throw e;
      this.mint(actor);
    }
  }

  mint(actor: Actor) {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      aud: "authenticated",
      exp: now + 3600,
      iat: now,
      iss: `${this.stack.apiUrl}/auth/v1`,
      sub: actor.userId,
      email: actor.email,
      phone: "",
      app_metadata: { provider: "email", providers: ["email"], ...(actor.appMetadata ?? {}) },
      user_metadata: actor.userMetadata ?? {},
      role: "authenticated",
      aal: "aal1",
      amr: [{ method: "password", timestamp: now }],
      session_id: crypto.randomUUID(),
      is_anonymous: false,
    };
    const head = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body = b64url(JSON.stringify(claims));
    const sig = createHmac("sha256", this.stack.jwtSecret!).update(`${head}.${body}`).digest("base64url");
    actor.token = `${head}.${body}.${sig}`;
    actor.minted = true;
  }

  async signIn(actor: Actor): Promise<void> {
    const res = await fetch(`${this.stack.apiUrl}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: this.stack.anonKey, "Content-Type": "application/json" },
      body: JSON.stringify({ email: actor.email, password: actor.password }),
    });
    if (!res.ok) throw new Error(`cannot sign in ${actor.label}: ${res.status} ${await res.text()}`);
    actor.token = ((await res.json()) as { access_token: string }).access_token;
  }

  async deleteUser(actor: Actor): Promise<void> {
    if (!actor.userId) return;
    await fetch(`${this.stack.apiUrl}/auth/v1/admin/users/${actor.userId}`, {
      method: "DELETE",
      headers: { apikey: this.stack.serviceKey, Authorization: `Bearer ${this.stack.serviceKey}` },
    }).catch(() => {});
  }

  /** What any user can do from the browser: edit their own user_metadata. */
  async setOwnMetadata(actor: Actor, data: Record<string, unknown>): Promise<void> {
    if (actor.minted) {
      // No real session to call /auth/v1/user with. The admin API writes the same field the user
      // could write themselves, then the token is re-minted with it.
      const res = await fetch(`${this.stack.apiUrl}/auth/v1/admin/users/${actor.userId}`, {
        method: "PUT",
        headers: { apikey: this.stack.serviceKey, Authorization: `Bearer ${this.stack.serviceKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ user_metadata: data }),
      });
      if (!res.ok) throw new Error(`cannot update metadata: ${res.status} ${await res.text()}`);
      actor.userMetadata = data;
      this.mint(actor);
      return;
    }
    const res = await fetch(`${this.stack.apiUrl}/auth/v1/user`, {
      method: "PUT",
      headers: this.headers(actor),
      body: JSON.stringify({ data }),
    });
    if (!res.ok) throw new Error(`cannot update metadata: ${res.status} ${await res.text()}`);
    await this.signIn(actor); // fresh JWT carries the new metadata
  }
}
