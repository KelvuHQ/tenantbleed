import { useState } from "react";
import { WarnGlyph } from "../components";
import type { ProgressEvent, ProjectCandidate, Severity, TargetInfo } from "../types";

const STEP_ORDER = [
  "inspect schema",
  "create test users",
  "build world",
  "read",
  "policy_state_read",
  "graphql",
  "user_metadata",
  "self_escalation",
  "self_enrollment",
  "update",
  "reparent",
  "insert",
  "impersonation",
  "rpc",
  "storage",
  "delete",
  "triage linter warnings",
];
const STEP_LABEL: Record<string, string> = {
  policy_state_read: "read (state-gated)",
  user_metadata: "user metadata",
  self_escalation: "self escalation",
  self_enrollment: "self enrollment",
  "triage linter warnings": "triage linter warnings",
};

interface Props {
  target: TargetInfo | null;
  projects: ProjectCandidate[];
  phase: "idle" | "scanning" | "done" | "error";
  progress: ProgressEvent | null;
  notes: string[];
  error: string | null;
  counts: { severity: Severity; n: number }[];
  provenTotal: number;
  onStart: (opts: { schemas?: string; triage: boolean }) => void;
  onChooseFolder: (dir: string) => void;
  onSeeFindings: () => void;
}

export function Scan({ target, projects, phase, progress, notes, error, counts, provenTotal, onStart, onChooseFolder, onSeeFindings }: Props) {
  const [triage, setTriage] = useState(true);
  const [editingFolder, setEditingFolder] = useState(false);
  const [pathInput, setPathInput] = useState("");
  const scanning = phase === "scanning";

  function openEditor() {
    setPathInput(target?.workdir ?? "");
    setEditingFolder(true);
  }
  function useTyped() {
    const dir = pathInput.trim();
    if (!dir) return;
    onChooseFolder(dir);
    setEditingFolder(false);
  }
  function pick(dir: string) {
    onChooseFolder(dir);
    setEditingFolder(false);
  }

  const current = progress ? STEP_ORDER.indexOf(progress.step) : -1;
  const pct = progress ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <div>
      <h1>Scan</h1>
      <p className="sub">Create two tenants on your local Supabase and try to cross between them. tenantbleed runs the attacks and records what the server did.</p>

      <div className="banner">
        <WarnGlyph />
        <div>
          <strong>This writes to your database.</strong> The scan creates test users and inserts, updates and deletes rows. Point it at a local dev or staging database, never production.
        </div>
      </div>

      {target === null && !error && <div className="empty">Detecting your local project...</div>}

      {target && !target.hasLocalProject && (
        <div className="panel">
          <div className="kv">
            No <code className="inline">supabase/config.toml</code> found in <code className="inline">{target.workdir}</code>.
          </div>
          <p className="meta" style={{ marginTop: "var(--s2)" }}>
            Point tenantbleed at the root of a Supabase project (the folder that holds the <code className="inline">supabase/</code> directory), with the local stack running.
          </p>
          <div className="arm-actions" style={{ marginTop: "var(--s3)" }}>
            <button className="btn secondary small" onClick={() => (editingFolder ? setEditingFolder(false) : openEditor())} type="button">
              {editingFolder ? "Cancel" : "Change folder"}
            </button>
          </div>
        </div>
      )}

      {target?.hasLocalProject && (
        <div className="arm">
          <div className="arm-main">
            <span className="arm-label">Target</span>
            <span className="arm-name">{target.name ?? "local project"}</span>
            <span className="arm-path">
              {target.workdir}
              {target.exposedSchemas?.length ? ` · schemas: ${target.exposedSchemas.join(", ")}` : ""}
            </span>
          </div>
          <div className="arm-actions">
            <button className="btn secondary small" disabled={scanning} onClick={() => (editingFolder ? setEditingFolder(false) : openEditor())} type="button">
              {editingFolder ? "Cancel" : "Change folder"}
            </button>
            <button className="btn" disabled={scanning} onClick={() => onStart({ triage })} type="button">
              {scanning ? "Scanning..." : "Start scan"}
            </button>
          </div>
        </div>
      )}

      {editingFolder && (
        <div className="panel">
          <div className="row">
            <input className="input" value={pathInput} onChange={(e) => setPathInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && useTyped()} placeholder="/path/to/your/supabase/project" spellCheck={false} autoFocus />
            <button className="btn" disabled={!pathInput.trim()} onClick={useTyped} type="button">
              Use folder
            </button>
          </div>
          <p className="meta" style={{ marginTop: "var(--s2)" }}>
            The folder that holds your <code className="inline">supabase/</code> directory.
          </p>
          {projects.length > 0 && (
            <div style={{ marginTop: "var(--s2)" }}>
              <div className="meta">Detected projects</div>
              <div className="chips">
                {projects.map((p) => (
                  <button key={p.workdir} type="button" className="chip" onClick={() => pick(p.workdir)} title={p.workdir}>
                    {p.name ?? p.workdir}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {target?.hasLocalProject && !scanning && phase !== "done" && (
        <label className="check" style={{ marginTop: "var(--s3)" }}>
          <input type="checkbox" checked={triage} onChange={(e) => setTriage(e.target.checked)} />
          Also triage Supabase linter warnings
        </label>
      )}

      {(scanning || phase === "done") && progress && (
        <div className="console">
          <div className="console-head">
            <span>{phase === "done" ? "scan complete" : "running probes"}</span>
            <span className="pct">{pct}%</span>
          </div>
          <div className="bar">
            <div style={{ width: `${pct}%` }} />
          </div>
          {STEP_ORDER.map((step, i) => {
            const isDone = phase === "done" || i < current;
            const isActive = i === current && phase !== "done";
            return (
              <div className={`c-line ${isDone ? "done" : isActive ? "active" : ""}`} key={step}>
                <span className="c-step">{STEP_LABEL[step] ?? step}</span>
                <span className="c-leader" />
                <span className={`c-res ${isActive ? "run" : "ok"}`}>{isDone ? "ok" : isActive ? "running" : ""}</span>
              </div>
            );
          })}
          {notes.length > 0 && (
            <div className="c-notes">
              {notes.map((n, i) => (
                <div key={i}>{n}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {phase === "done" && (
        <div className="verdict">
          <span className={`fig ${provenTotal === 0 ? "clean" : ""}`}>{provenTotal}</span>
          <span className="vlabel">
            {provenTotal === 0 ? "no cross-tenant breaches proven" : `proven cross-tenant breach${provenTotal === 1 ? "" : "es"}`}
          </span>
          {provenTotal > 0 && (
            <button className="btn secondary small" onClick={onSeeFindings} type="button" style={{ marginLeft: "auto" }}>
              See findings
            </button>
          )}
        </div>
      )}

      {phase === "done" && counts.length > 0 && (
        <div className="verdict-counts">
          {counts.map((c) => (
            <span key={c.severity} className={`c ${c.severity}`}>
              <b>{c.n}</b> {c.severity}
            </span>
          ))}
        </div>
      )}

      {error && (
        <div className="error-box">
          <strong>Scan failed.</strong> {error}
        </div>
      )}
    </div>
  );
}
