import { CopyButton } from "../components";
import type { ScanResult } from "../types";

export function CheckYourself({ result }: { result: ScanResult }) {
  const rows = (result.triage?.rows ?? []).filter((r) => r.checkPrompt);

  return (
    <div>
      <h1>Check yourself</h1>
      <p className="sub">
        {result.triage && !result.triage.ran
          ? "The linter did not run, so there is nothing to check here."
          : rows.length === 0
            ? "Nothing left to check by hand. Every linter warning was either proven or cleared."
            : `${rows.length} warning(s) the scan could neither prove nor clear. Each has a plain prompt you can run yourself.`}
      </p>

      {rows.map((r, i) => (
        <div className="check-block" key={i}>
          <div className="check-head">
            <b>{r.title}</b>
            <span className="mono">{r.target}</span>
            <span className="meta" style={{ marginLeft: "auto" }}>
              {r.lint} &middot; verdict: {r.verdict}
            </span>
          </div>
          <details className="fold">
            <summary>Prompt to check this yourself</summary>
            <div className="copy-wrap">
              <pre>{r.checkPrompt}</pre>
              <CopyButton text={r.checkPrompt!} />
            </div>
          </details>
        </div>
      ))}
    </div>
  );
}
