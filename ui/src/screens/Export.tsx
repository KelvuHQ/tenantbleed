import { reportUrl } from "../api";
import type { ScanResult } from "../types";

export function Export({ result, scanId }: { result: ScanResult; scanId: string }) {
  const items = [
    { href: reportUrl(scanId, "report.html"), name: "report.html", desc: "A self-contained page to open or share." },
    { href: reportUrl(scanId, "report.md"), name: "report.md", desc: "Markdown, for a pull request or a doc." },
    { href: reportUrl(scanId, ""), name: "result.json", desc: "The raw scan result, for tooling." },
  ];
  return (
    <div>
      <h1>Export</h1>
      <p className="sub">Download the report. Everything is generated locally; nothing is uploaded.</p>
      <div className="dl-list">
        {items.map((it) => (
          <div className="dl-row" key={it.name}>
            <div>
              <div className="dl-name">{it.name}</div>
              <div className="dl-desc">{it.desc}</div>
            </div>
            <a className="btn secondary small" href={it.href} download={it.name} target="_blank" rel="noreferrer">
              Download
            </a>
          </div>
        ))}
      </div>
      <p className="meta" style={{ marginTop: "var(--s4)" }}>
        Scanned {result.target?.name ?? result.stack} &middot; {result.relationsScanned} relations, {result.functionsScanned} functions &middot; {(result.durationMs / 1000).toFixed(1)}s
      </p>
    </div>
  );
}
