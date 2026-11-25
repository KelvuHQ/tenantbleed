import { useEffect, useMemo, useState } from "react";
import { ApiError, followScan, getTarget, hasToken, listProjects, openHistory, startScan } from "./api";
import { LockGlyph, ThemeToggle } from "./components";
import { Coverage } from "./screens/Coverage";
import { CheckYourself } from "./screens/CheckYourself";
import { Export } from "./screens/Export";
import { Findings } from "./screens/Findings";
import { History } from "./screens/History";
import { Scan } from "./screens/Scan";
import { Status } from "./screens/Status";
import { SEVERITY_ORDER, type ProgressEvent, type ProjectCandidate, type ScanResult, type Severity, type TargetInfo } from "./types";

type Screen = "scan" | "status" | "findings" | "coverage" | "check" | "export" | "history";
type Phase = "idle" | "scanning" | "done" | "error";

const STEPS: { key: Screen; label: string }[] = [
  { key: "scan", label: "Scan" },
  { key: "status", label: "Status" },
  { key: "findings", label: "Findings" },
  { key: "coverage", label: "Coverage" },
  { key: "check", label: "Check" },
  { key: "export", label: "Export" },
];

export function App() {
  if (!hasToken) return <TokenNotice />;
  return <AppInner />;
}

/** Light/dark theme, remembered per browser; falls back to the system setting. */
function useTheme(): ["light" | "dark", () => void] {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try {
      const saved = localStorage.getItem("tp-theme");
      if (saved === "light" || saved === "dark") return saved;
    } catch {
      /* storage blocked: fall through to the system setting */
    }
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("tp-theme", theme);
    } catch {
      /* storage blocked: the data-theme attribute still applies for this session */
    }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

/** Shown when the page has no session token, or carries a stale one the server no longer accepts. */
function TokenNotice({ stale }: { stale?: boolean }) {
  const [theme, toggleTheme] = useTheme();
  return (
    <div className="app">
      <header className="masthead">
        <div className="brand">
          tenant<span>bleed</span>
        </div>
        <span className="mast-local">
          <LockGlyph /> local
        </span>
        <div style={{ marginLeft: "auto" }}>
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
        </div>
      </header>
      <main className="main">
        <h1>{stale ? "This link is from an earlier session" : "Open the session link"}</h1>
        <p className="sub">
          {stale
            ? "The link you opened carries a session token from an earlier run of tenantbleed. Each start prints a fresh link and only the newest one works, so this one is now refused. That is what keeps the scanner reachable only from this machine."
            : "This page needs the one time session token that tenantbleed prints when it starts. Without it, every request is refused, which is what keeps the scanner reachable only from this machine."}
        </p>
        <div className="panel">
          <div className="kv">
            Go back to the terminal where you ran <code className="inline">tenantbleed ui</code> and open the {stale ? "newest" : "printed"} link. It looks like this:
          </div>
          <pre style={{ marginTop: "var(--s3)" }}>http://127.0.0.1:7171/?token=...</pre>
          <p className="meta" style={{ marginTop: "var(--s2)" }}>{stale ? "Reload this tab only after copying the newest link; an old token will always land here." : "The bare address without the token will always land here."}</p>
        </div>
      </main>
    </div>
  );
}

function AppInner() {
  const [target, setTarget] = useState<TargetInfo | null>(null);
  const [workdir, setWorkdir] = useState<string | undefined>(undefined);
  const [projects, setProjects] = useState<ProjectCandidate[]>([]);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>("scan");
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [findingsQuery, setFindingsQuery] = useState<string>("");
  const [viewingSavedAt, setViewingSavedAt] = useState<string | null>(null);
  const [viewingHistoryId, setViewingHistoryId] = useState<string | null>(null);
  const [historyReload, setHistoryReload] = useState(0);
  const [tokenRejected, setTokenRejected] = useState(false);
  const [theme, toggleTheme] = useTheme();

  useEffect(() => {
    getTarget()
      .then((t) => {
        setTarget(t);
        setWorkdir(t.workdir);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.authError) setTokenRejected(true);
        else setError(String(e.message ?? e));
      });
    listProjects()
      .then((r) => setProjects(r.projects))
      .catch(() => setProjects([]));
  }, []);

  // Point the scanner at a different Supabase project folder and re-detect it.
  function chooseFolder(dir: string) {
    setError(null);
    getTarget(dir)
      .then((t) => {
        setTarget(t);
        setWorkdir(t.workdir);
      })
      .catch((e) => setError(String(e.message ?? e)));
  }

  // Load a saved scan from history and show it read-only.
  function openSaved(id: string) {
    setError(null);
    openHistory(id, workdir)
      .then(({ scanId, result, savedAt }) => {
        setResult(result);
        setScanId(scanId);
        setPhase("done");
        setViewingSavedAt(savedAt);
        setViewingHistoryId(id);
        setSeverityFilter(null);
        setFindingsQuery("");
        setScreen("status");
      })
      .catch((e) => setError(String(e.message ?? e)));
  }

  async function run(opts: { schemas?: string; triage: boolean }) {
    setPhase("scanning");
    setError(null);
    setNotes([]);
    setProgress(null);
    setResult(null);
    setViewingSavedAt(null);
    setViewingHistoryId(null);
    try {
      const id = await startScan({ ...opts, workdir });
      setScanId(id);
      followScan(id, {
        onProgress: setProgress,
        onNote: (n) => setNotes((prev) => [...prev, n]),
        onDone: (r) => {
          setResult(r);
          setPhase("done");
          setScreen("status");
          setHistoryReload((n) => n + 1);
        },
        onError: (m) => {
          setError(m);
          setPhase("error");
        },
      });
    } catch (e) {
      if (e instanceof ApiError && e.authError) {
        setTokenRejected(true);
        return;
      }
      setError(String((e as Error).message ?? e));
      setPhase("error");
    }
  }

  const counts = useMemo(() => severityCounts(result), [result]);
  const provenTotal = useMemo(() => result?.findings.filter((f) => f.confidence === "proven").length ?? 0, [result]);
  const checkCount = result?.triage?.rows.filter((r) => r.checkPrompt).length ?? 0;
  const ready = phase === "done" && !!result;

  function goFindings(sev: Severity | null) {
    setSeverityFilter(sev);
    setFindingsQuery("");
    setScreen("findings");
  }

  // From the Status page: jump to Findings pre-filtered to one object.
  function inspect(target: string) {
    setSeverityFilter(null);
    setFindingsQuery(target);
    setScreen("findings");
  }

  const stepCount: Record<Screen, number | undefined> = {
    scan: undefined,
    status: undefined,
    findings: result?.findings.length,
    coverage: result?.coverage.length,
    check: checkCount || undefined,
    export: undefined,
    history: undefined,
  };

  const targetName = result?.target?.name ?? target?.name ?? result?.stack;

  if (tokenRejected) return <TokenNotice stale />;

  return (
    <div className="app">
      <header className="masthead">
        <div className="brand">
          tenant<span>bleed</span>
        </div>
        <span className="mast-local">
          <LockGlyph /> local
        </span>
        {targetName && (
          <span className="mast-target">{targetName}</span>
        )}
        <button className={`mast-history ${screen === "history" ? "active" : ""}`} onClick={() => setScreen("history")} type="button">
          History
        </button>
        <ThemeToggle theme={theme} onToggle={toggleTheme} />
        <div className="scoreboard">
          <button className="score-main" onClick={() => goFindings(null)} disabled={!ready} type="button">
            {ready ? (
              <>
                <span className={`score-fig ${provenTotal > 0 ? "has" : "clean"}`}>{provenTotal}</span>
                <span className="score-label">proven</span>
              </>
            ) : (
              <span className="score-label">not yet scanned</span>
            )}
          </button>
          {ready && counts.length > 0 && (
            <div className="score-sev">
              {counts.map((c) => (
                <button key={c.severity} className={`s ${c.severity}`} onClick={() => goFindings(c.severity)} type="button" title={`${c.n} ${c.severity}`}>
                  {c.severity[0].toUpperCase()}
                  {c.n}
                </button>
              ))}
            </div>
          )}
        </div>
      </header>

      <nav className="runorder">
        {STEPS.map((s, i) => (
          <button
            key={s.key}
            className={`step-link ${screen === s.key ? "active" : ""}`}
            disabled={s.key !== "scan" && !ready}
            onClick={() => {
              setSeverityFilter(null);
              setFindingsQuery("");
              setScreen(s.key);
            }}
            type="button"
          >
            <span className="idx">{String(i + 1).padStart(2, "0")}</span>
            <span>{s.label}</span>
            {stepCount[s.key] !== undefined && <span className="step-count">{stepCount[s.key]}</span>}
          </button>
        ))}
      </nav>

      <main className="main">
        {viewingSavedAt && screen !== "history" && (
          <div className="viewing-strip">
            <span>
              Viewing a saved scan from <b>{fmtSavedAt(viewingSavedAt)}</b>.
            </span>
            <button className="btn secondary small" onClick={() => setScreen("scan")} type="button">
              Run a new scan
            </button>
          </div>
        )}
        {screen === "scan" && <Scan target={target} projects={projects} phase={phase} progress={progress} notes={notes} error={error} counts={counts} provenTotal={provenTotal} onStart={run} onChooseFolder={chooseFolder} onSeeFindings={() => goFindings(null)} />}
        {screen === "status" && result && <Status result={result} onInspect={inspect} onGoFindings={() => goFindings(null)} onGoCheck={() => setScreen("check")} onGoCoverage={() => setScreen("coverage")} />}
        {screen === "findings" && result && scanId && <Findings result={result} scanId={scanId} filter={severityFilter} initialQuery={findingsQuery} onClearFilter={() => { setSeverityFilter(null); setFindingsQuery(""); }} />}
        {screen === "coverage" && result && <Coverage result={result} />}
        {screen === "check" && result && <CheckYourself result={result} />}
        {screen === "export" && result && scanId && <Export result={result} scanId={scanId} />}
        {screen === "history" && <History workdir={workdir} viewingId={viewingHistoryId} reloadKey={historyReload} onOpen={openSaved} />}
      </main>
    </div>
  );
}

function fmtSavedAt(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return iso;
  }
}

export function severityCounts(result: ScanResult | null): { severity: Severity; n: number }[] {
  if (!result) return [];
  const proven = result.findings.filter((f) => f.confidence === "proven");
  return SEVERITY_ORDER.map((severity) => ({ severity, n: proven.filter((f) => f.severity === severity).length })).filter((c) => c.n > 0);
}
