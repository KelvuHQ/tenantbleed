import { useMemo } from "react";
import { RankLetter } from "../components";
import { SEVERITY_ORDER, type ScanResult, type Severity } from "../types";
import { statusOf } from "./Coverage";

export function Status({ result, onInspect, onGoFindings, onGoCheck, onGoCoverage }: { result: ScanResult; onInspect: (target: string) => void; onGoFindings: () => void; onGoCheck: () => void; onGoCoverage: () => void }) {
  const proven = useMemo(() => result.findings.filter((f) => f.confidence === "proven"), [result]);
  const flaggedCount = result.findings.length - proven.length;
  const checkCount = result.triage?.rows.filter((r) => r.checkPrompt).length ?? 0;

  // Objects that need fixing: grouped by target, worst severity first.
  const needsFix = useMemo(() => {
    const byTarget = new Map<string, { target: string; worst: Severity; count: number; title: string }>();
    for (const f of proven) {
      const cur = byTarget.get(f.target);
      if (!cur) byTarget.set(f.target, { target: f.target, worst: f.severity, count: 1, title: f.title });
      else {
        cur.count++;
        // Describe the object by its worst finding, so the line reads as the most serious way in.
        if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(cur.worst)) {
          cur.worst = f.severity;
          cur.title = f.title;
        }
      }
    }
    return [...byTarget.values()].sort((a, b) => SEVERITY_ORDER.indexOf(a.worst) - SEVERITY_ORDER.indexOf(b.worst) || b.count - a.count);
  }, [proven]);

  // Good news only: objects tenantbleed tested and could NOT cross into.
  const breached = useMemo(() => new Set(proven.map((f) => f.target)), [proven]);
  const held = useMemo(
    () =>
      result.coverage
        .filter((r) => statusOf(r).label === "tested" && !breached.has(r.relation))
        .map((r) => r.relation)
        .sort((a, b) => a.localeCompare(b)),
    [result, breached],
  );

  const clean = needsFix.length === 0;

  return (
    <div>
      <h1>Status</h1>
      <p className="sub">Where {result.target?.name ?? result.stack} stands right now: what is holding, and what needs fixing.</p>

      <div className="posture">
        <section className="posture-col good">
          <div className="posture-head">
            <span className="posture-fig ok">{held.length}</span>
            <span className="posture-label">holding</span>
          </div>
          <p className="posture-sub">Tested and could not be crossed into. No tenant reached another tenant here.</p>
          {held.length === 0 ? (
            <div className="posture-empty">Nothing cleared yet.</div>
          ) : (
            <ul className="posture-list">
              {held.map((rel) => (
                <li key={rel} className="held-item">
                  <span className="held-check" aria-hidden="true">
                    &#10003;
                  </span>
                  <span className="mono">{rel}</span>
                </li>
              ))}
            </ul>
          )}
          <button className="btn secondary small" onClick={onGoCoverage} type="button">
            See full coverage
          </button>
        </section>

        <section className="posture-col fix">
          <div className="posture-head">
            <span className={`posture-fig ${clean ? "ok" : "bad"}`}>{needsFix.length}</span>
            <span className="posture-label">{needsFix.length === 1 ? "object needs fixing" : "objects need fixing"}</span>
          </div>
          {clean ? (
            <p className="posture-sub">No proven cross-tenant breaches. Nothing to fix from this scan.</p>
          ) : (
            <>
              <p className="posture-sub">Each one let a tenant reach another tenant. Open it for the proof and the fix.</p>
              <ul className="posture-list">
                {needsFix.map((n) => (
                  <li key={n.target}>
                    <button className="fix-item" onClick={() => onInspect(n.target)} type="button">
                      <RankLetter severity={n.worst} />
                      <span className="fix-body">
                        <span className="fix-head">
                          <span className="mono fix-target">{n.target}</span>
                          <span className="fix-count">
                            {n.count} finding{n.count === 1 ? "" : "s"}
                          </span>
                        </span>
                        <span className="fix-desc">{n.title}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
              <button className="btn small" onClick={onGoFindings} type="button">
                Open all findings
              </button>
            </>
          )}
          {checkCount > 0 && (
            <p className="posture-foot">
              <button className="linklike" onClick={onGoCheck} type="button">
                {checkCount} warning{checkCount === 1 ? "" : "s"} to check yourself
              </button>{" "}
              that the scan could not prove or clear.
            </p>
          )}
        </section>
      </div>

      <div className="posture-meta">
        Scanned {result.relationsScanned} relations and {result.functionsScanned} functions in {(result.durationMs / 1000).toFixed(1)}s.
        {flaggedCount > 0 ? ` ${flaggedCount} item(s) flagged from the schema, not proven.` : ""}
      </div>
    </div>
  );
}
