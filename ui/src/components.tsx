import { useState } from "react";
import type { Finding } from "./types";

const RANK: Record<string, string> = { critical: "C", high: "H", medium: "M", low: "L", info: "I" };

/** The verb a finding exercised, derived from the HTTP method and the finding kind. */
export function verbOf(f: Finding): string {
  const target = f.target ?? "";
  const kind = (f.kind ?? "").toLowerCase();
  if (target.endsWith("()") || kind.includes("rpc") || kind.includes("function")) return "RPC";
  const method = (f.evidence?.request.method ?? "").toUpperCase();
  if (method === "GET") return "READ";
  if (method === "POST") return "CREATE";
  if (method === "PATCH" || method === "PUT") return "WRITE";
  if (method === "DELETE") return "DELETE";
  if (kind.includes("read")) return "READ";
  if (kind.includes("insert") || kind.includes("create") || kind.includes("enroll")) return "CREATE";
  if (kind.includes("update") || kind.includes("reparent") || kind.includes("escalat")) return "WRITE";
  if (kind.includes("delete")) return "DELETE";
  return "ACCESS";
}

/**
 * The code the database SHOULD have returned, shown struck-through before the actual code,
 * ONLY where that claim is literally true at the HTTP layer. A blocked INSERT is that case: row
 * level security denies it through WITH CHECK with 403, so a 200/201 is a genuine status-level
 * breach. For a read, update or delete a correctly isolated database returns the SAME status
 * (200 with no rows, 204 affecting no rows), so the crime is the data touched, not the code; we
 * do not strike a fabricated expected code there. The red actual code and the dossier carry it.
 */
export function expectedCode(f: Finding): number | null {
  if (!f.evidence) return null;
  if (verbOf(f) === "CREATE") return 403;
  return null;
}

/** One honest sentence for the dossier: what a properly isolated database would have done. */
export function shouldLine(f: Finding): string {
  if (!f.evidence) return "";
  const s = f.evidence.status;
  const victim = f.evidence.victim ?? "another tenant";
  switch (verbOf(f)) {
    case "CREATE":
      return `A database with row level security would have refused this insert with 403. It returned ${s} and wrote into ${victim}'s data.`;
    case "WRITE":
      return `A properly isolated database would have changed no rows. It returned ${s} after altering ${victim}'s data.`;
    case "DELETE":
      return `A properly isolated database would have removed no rows. It returned ${s} after deleting ${victim}'s data.`;
    case "RPC":
      return `The function answered ${s} and handed ${victim}'s data to a caller from another tenant.`;
    default:
      return `A properly isolated database would have returned no cross-tenant rows. It returned ${s} with ${victim}'s data.`;
  }
}

/**
 * One plain word for what the server actually did, so a red "200" reads as a breach
 * instead of the usual "OK". Verb-aware: a read exfiltrated rows, a write changed them, and so on.
 */
export function outcomeWord(f: Finding): string {
  switch (verbOf(f)) {
    case "READ":
      return "leaked";
    case "CREATE":
      return "created";
    case "WRITE":
      return "wrote";
    case "DELETE":
      return "deleted";
    case "RPC":
      return "answered";
    default:
      return "allowed";
  }
}

export function RankLetter({ severity, flagged }: { severity: string; flagged?: boolean }) {
  if (flagged) return <span className="rank flagged" title="flagged, not proven">?</span>;
  return <span className={`rank ${severity}`} title={severity}>{RANK[severity] ?? "?"}</span>;
}

/** The signature: expected (struck) then the actual code in red, or just the actual code. */
export function StatusStamp({ f, big }: { f: Finding; big?: boolean }) {
  if (!f.evidence) return <span className={`stamp muted${big ? " big" : ""}`}>static</span>;
  const exp = expectedCode(f);
  return (
    <span className={`stamp${big ? " big" : ""}`}>
      {exp !== null && (
        <>
          <span className="exp">{exp}</span>
          <span className="arrow">&rarr;</span>
        </>
      )}
      <span className="act">{f.evidence.status}</span>
      {!big && <span className="outcome">{outcomeWord(f)}</span>}
    </span>
  );
}

/** actor -> victim as one bound phrase, the arrow tinted like the breach. */
export function ActorVictim({ actor, victim }: { actor: string; victim?: string }) {
  // The anon (public) role means the request carried no login at all: the worst reach.
  const noLogin = /^anon(ymous)?$/i.test(actor.trim());
  return (
    <span className="pair">
      {noLogin ? (
        <span className="actor nologin" title="anon (public) role: no login">no login</span>
      ) : (
        <span className="actor">{actor}</span>
      )}
      <span className="arrow">&rarr;</span>
      {victim ? <span className="victim">{victim}</span> : <span className="shared">shared</span>}
    </span>
  );
}

/** A warning triangle for the write-to-database caution. */
export function WarnGlyph() {
  return (
    <svg className="warn-glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
  );
}

/** A small offline lock glyph for the masthead trust signal. */
export function LockGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

/** Masthead button that flips between light and dark; shows the theme it switches to. */
export function ThemeToggle({ theme, onToggle }: { theme: "light" | "dark"; onToggle: () => void }) {
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button className="theme-toggle" onClick={onToggle} type="button" aria-label={`Switch to ${next} mode`} title={`Switch to ${next} mode`}>
      {theme === "dark" ? (
        // Sun: tapping goes back to light.
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      ) : (
        // Moon: tapping goes to dark.
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />
        </svg>
      )}
    </button>
  );
}

/** A block of code with a copy button. */
export function CodeCopy({ text, label }: { text: string; label?: string }) {
  return (
    <div className="copy-wrap">
      {label && <div className="dossier-sec">{label}</div>}
      <pre>{text}</pre>
      <CopyButton text={text} />
    </div>
  );
}

/** Write to the clipboard, falling back to a hidden textarea where the API is blocked. */
export async function writeClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
    } catch {
      /* nothing more to do */
    }
    ta.remove();
  }
}

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    await writeClipboard(text);
    setDone(true);
    setTimeout(() => setDone(false), 1400);
  };
  return (
    <button className={`copy-btn ${done ? "done" : ""}`} onClick={copy} type="button">
      {done ? "copied" : "copy"}
    </button>
  );
}

/** A labeled copy button for toolbar actions (copy-all, etc.). */
export function CopyInline({ text, label, disabled }: { text: string; label: string; disabled?: boolean }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    await writeClipboard(text);
    setDone(true);
    setTimeout(() => setDone(false), 1400);
  };
  return (
    <button className={`btn secondary small ${done ? "flash" : ""}`} onClick={copy} type="button" disabled={disabled}>
      {done ? "copied" : label}
    </button>
  );
}
