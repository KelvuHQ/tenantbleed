import { useEffect, useMemo, useRef, useState } from "react";
import { getFixes } from "../api";
import { ActorVictim, CodeCopy, CopyButton, CopyInline, RankLetter, StatusStamp, shouldLine, verbOf } from "../components";
import { SEVERITY_ORDER, type Finding, type FixesResponse, type ScanResult, type Severity } from "../types";

const VERBS = ["READ", "WRITE", "CREATE", "DELETE", "RPC"];

export function Findings({ result, scanId, filter, initialQuery, onClearFilter }: { result: ScanResult; scanId: string; filter: Severity | null; initialQuery: string; onClearFilter: () => void }) {
  const [fixes, setFixes] = useState<FixesResponse | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [q, setQ] = useState(initialQuery);
  const [sevSel, setSevSel] = useState<Set<Severity>>(new Set());
  const [verbSel, setVerbSel] = useState<Set<string>>(new Set());
  const [cursor, setCursor] = useState(-1);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getFixes(scanId)
      .then(setFixes)
      .catch(() => setFixes({ fixes: [], skipped: [], prompts: {} }));
  }, [scanId]);

  // Seed the severity filter from the masthead scoreboard click.
  useEffect(() => {
    setSevSel(filter ? new Set([filter]) : new Set());
  }, [filter]);

  // Seed the search from the Status page "inspect this object" action.
  useEffect(() => {
    setQ(initialQuery);
  }, [initialQuery]);

  const proven = useMemo(() => result.findings.filter((f) => f.confidence === "proven"), [result]);
  const flagged = useMemo(() => result.findings.filter((f) => f.confidence !== "proven"), [result]);

  const match = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (f: Finding, isProven: boolean) => {
      if (sevSel.size && !sevSel.has(f.severity)) return false;
      if (verbSel.size && (!isProven || !verbSel.has(verbOf(f)))) return false;
      if (!needle) return true;
      const hay = [f.title, f.target, f.evidence?.actor, f.evidence?.victim, isProven ? verbOf(f) : ""].join(" ").toLowerCase();
      return hay.includes(needle);
    };
  }, [q, sevSel, verbSel]);

  const bands = useMemo(
    () =>
      SEVERITY_ORDER.map((severity) => ({
        severity,
        rows: proven.filter((f) => f.severity === severity && match(f, true)),
      })).filter((b) => b.rows.length > 0),
    [proven, match],
  );
  const flaggedShown = useMemo(() => (verbSel.size ? [] : flagged.filter((f) => match(f, false))), [flagged, match, verbSel]);

  // The flat, in-display-order list that keyboard navigation walks.
  const flat = useMemo(() => [...bands.flatMap((b) => b.rows), ...flaggedShown], [bands, flaggedShown]);
  const flatIds = flat.map((f) => f.id);

  const filtering = q.trim() !== "" || sevSel.size > 0 || verbSel.size > 0;
  const shownCount = flat.length;

  function clearAll() {
    setQ("");
    setSevSel(new Set());
    setVerbSel(new Set());
    onClearFilter();
  }
  function toggleSev(s: Severity) {
    setSevSel((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  }
  function toggleVerb(v: string) {
    setVerbSel((prev) => {
      const next = new Set(prev);
      next.has(v) ? next.delete(v) : next.add(v);
      return next;
    });
  }

  // Open a finding and record it in the URL hash so the view is shareable.
  function openFinding(id: string) {
    setOpenId(id);
    setCursor(flatIds.indexOf(id));
    history.replaceState(null, "", `${location.pathname}${location.search}#${encodeURIComponent(id)}`);
  }
  function closeFinding() {
    setOpenId(null);
    history.replaceState(null, "", `${location.pathname}${location.search}`);
  }

  // On load (and when the result or hash changes), open the finding named in the URL hash.
  useEffect(() => {
    const id = decodeURIComponent(location.hash.replace(/^#/, ""));
    if (id && result.findings.some((f) => f.id === id)) {
      setOpenId(id);
      setCursor(result.findings.findIndex((f) => f.id === id));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result]);

  function moveCursor(delta: number) {
    if (!flat.length) return;
    const base = cursor < 0 ? (delta > 0 ? -1 : 0) : cursor;
    const next = Math.max(0, Math.min(flat.length - 1, base + delta));
    setCursor(next);
    document.getElementById(`row-${flat[next].id}`)?.scrollIntoView({ block: "nearest" });
  }
  function stepOpen(delta: number) {
    if (!openId) return;
    const i = flatIds.indexOf(openId);
    if (i < 0) return;
    const next = Math.max(0, Math.min(flat.length - 1, i + delta));
    openFinding(flat[next].id);
  }

  // Esc closes the drawer.
  useEffect(() => {
    if (!openId) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && closeFinding();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openId]);

  // Keyboard navigation over the ledger.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement;
      const typing = el instanceof HTMLElement && (el.tagName === "INPUT" || el.tagName === "TEXTAREA");
      if (e.key === "/" && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (typing) return;
      if (openId) {
        if (e.key === "ArrowDown" || e.key === "j" || e.key === "]") {
          e.preventDefault();
          stepOpen(1);
        } else if (e.key === "ArrowUp" || e.key === "k" || e.key === "[") {
          e.preventDefault();
          stepOpen(-1);
        }
        return;
      }
      if (e.key === "ArrowDown" || e.key === "j") {
        e.preventDefault();
        moveCursor(1);
      } else if (e.key === "ArrowUp" || e.key === "k") {
        e.preventDefault();
        moveCursor(-1);
      } else if (e.key === "Enter" && cursor >= 0 && flat[cursor]) {
        e.preventDefault();
        openFinding(flat[cursor].id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openId, cursor, flat]);

  const open = openId ? result.findings.find((f) => f.id === openId) ?? null : null;

  // Copy-all remediation: every unique suggested fix as one ordered migration.
  const allFixesText = useMemo(() => {
    const seen = new Set<string>();
    const blocks: string[] = [];
    for (const f of proven) {
      const fx = fixes?.fixes.find((x) => x.target === f.target);
      if (fx?.sql && !seen.has(fx.id)) {
        seen.add(fx.id);
        blocks.push(`-- ${fx.title || fx.target}\n${fx.sql.trim()}`);
      }
    }
    if (!blocks.length) return "";
    return `-- tenantbleed remediation for ${result.target?.name ?? result.stack}\n-- ${blocks.length} fix(es), generated locally. Review before applying.\n\n${blocks.join("\n\n")}\n`;
  }, [proven, fixes, result]);

  return (
    <div>
      <h1>Findings</h1>
      <p className="sub">
        {result.findings.length === 0
          ? "Nothing proven. tenantbleed could not cross between tenants on what it tested."
          : "Each row is a real request that crossed a tenant boundary. The red code is the answer the database should have refused. Open a row for the exchange that proves it."}
      </p>

      {proven.length > 0 && (
        <div className="finding-legend">
          <span>
            <span className="lg-code">200</span> <span className="lg-word">leaked</span> is the server's real reply to the attack, not a success: the code the database should have refused, with the word for what it did.
          </span>
          <span>
            <b>no login &rarr; tenant</b> means a request with no account reached that tenant's data.
          </span>
          <span>
            <b>tenant A &rarr; tenant B</b> means one signed-in tenant reached another's: a cross-account leak.
          </span>
        </div>
      )}

      {result.findings.length > 0 && (
        <div className="toolbar">
          <input ref={searchRef} className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search target, actor or verb    ( / )" spellCheck={false} aria-label="Search findings" />
          <div className="filter-chips">
            {SEVERITY_ORDER.filter((s) => proven.some((f) => f.severity === s)).map((s) => (
              <button key={s} className={`fchip ${s} ${sevSel.has(s) ? "on" : ""}`} onClick={() => toggleSev(s)} type="button">
                {s[0].toUpperCase()}
              </button>
            ))}
            <span className="chip-sep" />
            {VERBS.filter((v) => proven.some((f) => verbOf(f) === v)).map((v) => (
              <button key={v} className={`fchip verb ${verbSel.has(v) ? "on" : ""}`} onClick={() => toggleVerb(v)} type="button">
                {v}
              </button>
            ))}
          </div>
          {allFixesText && <CopyInline text={allFixesText} label="Copy all fixes" />}
          {filtering && (
            <button className="btn secondary small" onClick={clearAll} type="button">
              Clear
            </button>
          )}
        </div>
      )}

      {filtering && (
        <p className="meta" style={{ marginBottom: "var(--s3)" }}>
          {shownCount} of {result.findings.length} shown.
        </p>
      )}

      {result.findings.length > 0 && shownCount === 0 && <div className="empty">No findings match. Clear the filters to see all {result.findings.length}.</div>}
      {result.findings.length === 0 && <div className="empty">No findings. See Coverage for what was and was not tested.</div>}

      <div className="ledger">
        {bands.map((band) => (
          <div className="band" key={band.severity}>
            <div className="band-label">
              {band.severity} <span className="n">{band.rows.length}</span>
            </div>
            {band.rows.map((f) => (
              <Row key={f.id} f={f} active={openId === f.id} cursored={cursor >= 0 && flat[cursor]?.id === f.id} onOpen={() => openFinding(f.id)} />
            ))}
          </div>
        ))}

        {flaggedShown.length > 0 && (
          <div className="band">
            <div className="band-label">
              flagged, not proven <span className="n">{flaggedShown.length}</span>
            </div>
            {flaggedShown.map((f) => (
              <button key={f.id} id={`row-${f.id}`} className={`ledger-row ${openId === f.id ? "active" : ""} ${cursor >= 0 && flat[cursor]?.id === f.id ? "cursor" : ""}`} onClick={() => openFinding(f.id)} type="button">
                <RankLetter severity={f.severity} flagged />
                <span className="row-body">
                  <span className="row-title">{f.title}</span>
                  <span className="row-facts">
                    <span className="flag-note">flagged, not proven</span>
                    <span className="dot">&middot;</span>
                    <span className="f-target">{f.target}</span>
                  </span>
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {open && (
        <>
          <div className="drawer-scrim" onClick={closeFinding} />
          <Dossier f={open} fix={fixes?.fixes.find((x) => x.target === open.target)} prompt={fixes?.prompts[open.id]} pos={flatIds.indexOf(open.id)} total={flat.length} onPrev={() => stepOpen(-1)} onNext={() => stepOpen(1)} onClose={closeFinding} />
        </>
      )}
    </div>
  );
}

function Row({ f, active, cursored, onOpen }: { f: Finding; active: boolean; cursored: boolean; onOpen: () => void }) {
  return (
    <button id={`row-${f.id}`} className={`ledger-row ${active ? "active" : ""} ${cursored ? "cursor" : ""}`} onClick={onOpen} type="button">
      <RankLetter severity={f.severity} />
      <span className="row-body">
        <span className="row-title">{f.title}</span>
        <span className="row-facts">
          <StatusStamp f={f} />
          <span className="dot">&middot;</span>
          <span className="verb">{verbOf(f)}</span>
          <span className="dot">&middot;</span>
          {f.evidence ? <ActorVictim actor={f.evidence.actor} victim={f.evidence.victim} /> : <span className="pair shared">read from schema</span>}
          <span className="dot">&middot;</span>
          <span className="f-target">{f.target}</span>
        </span>
      </span>
    </button>
  );
}

function Dossier({ f, fix, prompt, pos, total, onPrev, onNext, onClose }: { f: Finding; fix?: { sql: string; title: string }; prompt?: string; pos: number; total: number; onPrev: () => void; onNext: () => void; onClose: () => void }) {
  const e = f.evidence;
  const ref = (el: HTMLDivElement | null) => el?.focus();
  return (
    <aside className="drawer" role="dialog" aria-modal="true" aria-label={f.title} tabIndex={-1} ref={ref}>
      <div className="drawer-top">
        <span className="drawer-pos">
          {pos + 1} of {total}
        </span>
        <div className="drawer-nav">
          <button className="btn secondary small" onClick={onPrev} disabled={pos <= 0} type="button" aria-label="Previous finding" title="Previous ( [ )">
            &uarr;
          </button>
          <button className="btn secondary small" onClick={onNext} disabled={pos >= total - 1} type="button" aria-label="Next finding" title="Next ( ] )">
            &darr;
          </button>
          <button className="drawer-close" onClick={onClose} type="button" aria-label="Close">
            &times;
          </button>
        </div>
      </div>
      <div className="drawer-head">
        <RankLetter severity={f.severity} flagged={f.confidence !== "proven"} />
        <StatusStamp f={f} big />
      </div>
      <h2 className="drawer-title">{f.title}</h2>
      <div className="drawer-meta">
        {f.target} &middot; {verbOf(f)}
        {e ? (
          <>
            {" "}
            &middot; {e.actor} &rarr; {e.victim ?? "shared"}
          </>
        ) : null}
      </div>
      {f.detail && <p className="drawer-detail">{f.detail}</p>}

      {e && (
        <>
          <div className="dossier-sec">The exchange</div>
          <div className="exchange">
            <div className="col req">
              <div className="col-h">Request</div>
              <div className="line">
                {e.request.method} {e.request.path}
              </div>
              <div className="line">apikey: $ANON_KEY</div>
              <div className="line">as: {e.actor}</div>
              {e.request.body ? <div className="line">body: {JSON.stringify(e.request.body)}</div> : null}
              {e.via?.length ? <div className="line">also via: {e.via.join(", ")}</div> : null}
            </div>
            <div className="col res">
              <div className="col-h">Response</div>
              <div className="status-big">{e.status}</div>
              <div className="should">{shouldLine(f)}</div>
              {e.proof && <div className="proof">{e.proof}</div>}
            </div>
          </div>
          {e.curl && <CodeCopy text={e.curl} label="Reproduce" />}
        </>
      )}

      {f.location?.length ? (
        <>
          <div className="dossier-sec">Where to fix</div>
          <div className="meta">
            {f.location.map((l, i) => (
              <div key={i}>
                <code className="inline">
                  {l.file}:{l.line}
                </code>{" "}
                {l.what}
              </div>
            ))}
          </div>
        </>
      ) : null}

      {(f.standards || f.data?.classes.length) && (
        <div className="standards">
          {f.standards?.owasp.concat(f.standards.cwe).map((s) => (
            <span key={s} className="pill">
              {s}
            </span>
          ))}
          {f.data?.classes.length ? <span className="pill">data: {f.data.classes.join(", ")}</span> : null}
        </div>
      )}

      {fix?.sql && <CodeCopy text={fix.sql} label={fix.title ? `The fix: ${fix.title}` : "The fix"} />}

      {prompt && (
        <details className="fold">
          <summary>AI fix prompt (paste into Cursor, Claude, Lovable or Bolt)</summary>
          <div className="copy-wrap">
            <pre>{prompt}</pre>
            <CopyButton text={prompt} />
          </div>
        </details>
      )}
    </aside>
  );
}
