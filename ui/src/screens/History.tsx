import { useEffect, useState } from "react";
import { listHistory, type HistoryEntry } from "../api";

export function History({ workdir, viewingId, reloadKey, onOpen }: { workdir?: string; viewingId: string | null; reloadKey: number; onOpen: (id: string) => void }) {
  const [scans, setScans] = useState<HistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setScans(null);
    listHistory(workdir)
      .then((r) => setScans(r.scans))
      .catch((e) => setError(String(e.message ?? e)));
  }, [workdir, reloadKey]);

  return (
    <div>
      <h1>History</h1>
      <p className="sub">Every scan of this project is saved on this machine, under your home folder. Open a past scan to read its findings, or watch the number move as you fix things.</p>

      {error && (
        <div className="error-box">
          <strong>Could not load history.</strong> {error}
        </div>
      )}
      {scans && scans.length === 0 && <div className="empty">No saved scans yet. Run a scan and it will appear here.</div>}

      {scans && scans.length > 0 && (
        <div className="history-list">
          {scans.map((s, i) => {
            const prev = scans[i + 1];
            const delta = prev ? s.proven - prev.proven : null;
            return (
              <button key={s.id} className={`history-row ${viewingId === s.id ? "active" : ""}`} onClick={() => onOpen(s.id)} type="button">
                <span className="hist-when">{fmtWhen(s.savedAt)}</span>
                <span className={`hist-proven ${s.proven === 0 ? "clean" : "has"}`}>{s.proven}</span>
                <span className="hist-plabel">proven</span>
                <span className="hist-counts">{sevStr(s.counts)}</span>
                {delta === null ? (
                  <span className="hist-delta first">first scan</span>
                ) : delta === 0 ? (
                  <span className="hist-delta flat">no change</span>
                ) : (
                  <span className={`hist-delta ${delta < 0 ? "down" : "up"}`}>
                    {delta < 0 ? `${-delta} fewer` : `${delta} more`}
                  </span>
                )}
                <span className="hist-scope">
                  {s.relations} rel &middot; {s.functions} fn &middot; {(s.durationMs / 1000).toFixed(1)}s
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function fmtWhen(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return iso;
  }
}

function sevStr(c: Partial<Record<string, number>>): string {
  const order = ["critical", "high", "medium", "low"];
  const parts: string[] = [];
  for (const s of order) if (c[s]) parts.push(`${c[s]} ${s}`);
  return parts.join("  ");
}
