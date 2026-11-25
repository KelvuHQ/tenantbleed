import { createHash } from "node:crypto";
import type { Finding, FindingKind } from "./findings.js";

/**
 * What a report for one customer needs around each finding, engine-neutral: which app and version
 * was scanned, a finding id that stays the same from run to run, where the responsible rule lives
 * in the app's code, what kind of data is exposed, and the standard references auditors expect.
 * Engines supply the facts (ScanTarget, SourceRef); the helpers here turn them into finding fields.
 */

/** The app and version a scan ran against. */
export interface ScanTarget {
  /** tenantbleed.json "name", else the project folder's name. */
  name: string;
  /** Code version: the git commit of the scanned project, and whether it had uncommitted changes. */
  commit?: string;
  branch?: string;
  dirty?: boolean;
  /** Database schema version: the migrations that built the scanned database. */
  schemaVersion?: { migrations: number; latest?: string; hash: string };
  /** tenantbleed version that ran the scan. */
  tool: string;
}

/** Where an object was defined in the app's code (the last definition wins, as it does in the database). */
export interface SourceRef {
  /** "policy", "function", "table", "view": the engine's own kinds. */
  kind: string;
  /** "schema.name" of the object, or of the table a policy is on. */
  object: string;
  /** Policy name, for policies. */
  name?: string;
  /** Path relative to the project folder, and 1-based line. */
  file: string;
  line: number;
}

export interface Standards {
  owasp: string[];
  cwe: string[];
}

/** One stable id per finding: what broke, where, by which rule, from which side. Never positions or row ids. */
export function fingerprint(f: Pick<Finding, "kind" | "target" | "rule" | "evidence" | "confidence">): string {
  const side = f.confidence === "static" ? "static" : f.evidence?.actor === "anon" ? "anon" : "user";
  return `TP-${createHash("sha256").update(`${f.kind}|${f.target}|${f.rule}|${side}`).digest("hex").slice(0, 10)}`;
}

/** Fingerprints for a list, kept unique: a repeat gets a suffix in list order. */
export function fingerprints(findings: Finding[]): string[] {
  const seen = new Map<string, number>();
  return findings.map((f) => {
    const id = fingerprint(f);
    const n = (seen.get(id) ?? 0) + 1;
    seen.set(id, n);
    return n === 1 ? id : `${id}-${n}`;
  });
}

const A01 = "A01:2021 Broken Access Control";
const API1 = "API1:2023 Broken Object Level Authorization";
const CWE_INCORRECT = "CWE-863 Incorrect Authorization";
const CWE_MISSING = "CWE-862 Missing Authorization";
const CWE_USER_KEY = "CWE-639 Authorization Bypass Through User-Controlled Key";
const CWE_UNTRUSTED = "CWE-807 Reliance on Untrusted Inputs in a Security Decision";
const CWE_ACCESS = "CWE-284 Improper Access Control";
const CWE_PRIVILEGE = "CWE-269 Improper Privilege Management";

const STANDARDS: Record<FindingKind, Standards> = {
  "cross-tenant-read": { owasp: [A01, API1], cwe: [CWE_INCORRECT] },
  "cross-tenant-update": { owasp: [A01, API1], cwe: [CWE_INCORRECT] },
  "cross-tenant-delete": { owasp: [A01, API1], cwe: [CWE_INCORRECT] },
  "cross-tenant-insert": { owasp: [A01, API1], cwe: [CWE_INCORRECT] },
  "cross-tenant-reparent": { owasp: [A01, API1], cwe: [CWE_USER_KEY] },
  "impersonation-insert": { owasp: [A01, API1], cwe: [CWE_USER_KEY] },
  "anon-read": { owasp: [A01, API1], cwe: [CWE_MISSING] },
  "view-leak": { owasp: [A01, API1], cwe: [CWE_INCORRECT] },
  "rpc-leak": { owasp: [A01, API1], cwe: [CWE_USER_KEY] },
  "rpc-write": { owasp: [A01, API1], cwe: [CWE_USER_KEY] },
  "metadata-escalation": { owasp: [A01], cwe: [CWE_UNTRUSTED] },
  "self-escalation": { owasp: [A01], cwe: [CWE_PRIVILEGE] },
  "self-enrollment": { owasp: [A01], cwe: [CWE_PRIVILEGE] },
  static: { owasp: [A01], cwe: [CWE_ACCESS] },
};

export const standardsOf = (kind: FindingKind): Standards => STANDARDS[kind];

/**
 * Data classes by column name, whole words of snake_case or camelCase names. The first match wins,
 * so the specific classes come first ("email_verified_at" is an email-related column, not a date).
 */
const CLASSES: [string, RegExp][] = [
  ["credentials", /^(password|passwd|secret|token|api_key|apikey|private_key|key_hash|access_token|refresh_token|otp|totp|mfa|recovery_code|session)$/],
  ["email", /^(e?mail|email_address)$/],
  ["phone", /^(phone|mobile|cell|telephone|tel|whatsapp)$/],
  ["government-id", /^(ssn|cpf|cnpj|nif|passport|national_id|tax_id|tax|vat)$/],
  ["financial", /^(iban|card|card_number|pan|cvv|bank|account_number|routing|salary|income|balance|amount|price|invoice|payment|stripe|billing)$/],
  ["health", /^(diagnosis|medical|medication|allergy|allergies|condition|health|symptom|symptoms|prescription)$/],
  ["birth-date", /^(birth|birthday|dob|date_of_birth|birthdate)$/],
  ["address", /^(address|street|zip|zipcode|postal|postcode|city)$/],
  ["location", /^(location|lat|lng|latitude|longitude|geo|coordinates)$/],
  ["ip-address", /^(ip|ip_address|user_agent)$/],
  ["person-name", /^(first_name|last_name|full_name|display_name|surname|username|given_name|family_name)$/],
  ["free-text", /^(note|notes|body|message|messages|content|comment|comments|description|text|bio|memo|transcript|prompt)$/],
];

const words = (column: string) => {
  const snake = column.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  const parts = snake.split(/[^a-z0-9]+/).filter(Boolean);
  // The whole name, then pairs and single words: "date_of_birth" and "birth" both count.
  const out = new Set([snake, ...parts]);
  for (let i = 0; i + 1 < parts.length; i++) out.add(`${parts[i]}_${parts[i + 1]}`);
  return [...out];
};

/** The data class of one column, or undefined. */
export function dataClassOf(column: string): string | undefined {
  const w = words(column);
  return CLASSES.find(([, re]) => w.some((x) => re.test(x)))?.[0];
}

/** Data classes of a set of columns, in the order of CLASSES (most sensitive first). */
export function dataClasses(columns: string[]): string[] {
  const found = new Set(columns.map(dataClassOf).filter((c): c is string => !!c));
  return CLASSES.map(([c]) => c).filter((c) => found.has(c));
}

/** Column names in a proof: the keys of a JSON row or list of rows, also when the proof was cut short. */
export function columnsInProof(proof: string): string[] {
  try {
    const v = JSON.parse(proof);
    const row = Array.isArray(v) ? v[0] : v;
    if (row && typeof row === "object") return Object.keys(row);
  } catch {
    // A shortened proof is not valid JSON: read the keys it still shows.
  }
  return [...new Set([...proof.matchAll(/"([A-Za-z_][\w]*)"\s*:/g)].map((m) => m[1]))];
}
