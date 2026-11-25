import type { ScanResult } from "../core/scan-result.js";
import { toMarkdown } from "./report.js";

/**
 * A self-contained HTML report: the Markdown report rendered to a single styled page with no
 * external resources, for sharing or archiving. The Markdown stays the single source of truth;
 * this converts the subset the report uses (headings, tables, fenced and inline code, bold, links,
 * blockquotes, ordered and unordered lists, and raw <details>/<summary> passthrough).
 */
export function toHtml(r: ScanResult): string {
  const title = r.target?.name ? `tenantbleed report: ${r.target.name}` : "tenantbleed report";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<main class="report">
${mdToHtml(toMarkdown(r))}
</main>
</body>
</html>
`;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Inline markdown on already-escaped text: code spans, bold, links. */
function inline(s: string): string {
  return esc(s)
    .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, (_, b) => `<strong>${b}</strong>`)
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, t, u) => `<a href="${u}">${t}</a>`);
}

function mdToHtml(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block.
    const fence = /^```(\w*)\s*$/.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) body.push(lines[i++]);
      i++; // closing fence
      out.push(`<pre><code>${esc(body.join("\n"))}</code></pre>`);
      continue;
    }

    // Table: a run of lines starting with "|".
    if (/^\s*\|/.test(line)) {
      const rows: string[] = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(lines[i++]);
      out.push(renderTable(rows));
      continue;
    }

    // Raw HTML passthrough (e.g. <details>, </details>, <summary>).
    if (/^\s*<\/?[a-z]/i.test(line)) {
      out.push(line);
      i++;
      continue;
    }

    // Headings.
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      const n = h[1].length;
      out.push(`<h${n}>${inline(h[2])}</h${n}>`);
      i++;
      continue;
    }

    // Blockquote (one line at a time is enough for this report).
    if (/^\s*>\s?/.test(line)) {
      out.push(`<blockquote>${inline(line.replace(/^\s*>\s?/, ""))}</blockquote>`);
      i++;
      continue;
    }

    // Ordered list.
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*\d+\.\s+/, ""));
      out.push(`<ol>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</ol>`);
      continue;
    }

    // Unordered list.
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*[-*]\s+/, ""));
      out.push(`<ul>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</ul>`);
      continue;
    }

    // Blank line.
    if (/^\s*$/.test(line)) {
      i++;
      continue;
    }

    // Paragraph (gather consecutive plain lines).
    const para: string[] = [];
    while (
      i < lines.length &&
      !/^\s*$/.test(lines[i]) &&
      !/^```/.test(lines[i]) &&
      !/^\s*\|/.test(lines[i]) &&
      !/^\s*<\/?[a-z]/i.test(lines[i]) &&
      !/^#{1,6}\s/.test(lines[i]) &&
      !/^\s*>\s?/.test(lines[i]) &&
      !/^\s*\d+\.\s+/.test(lines[i]) &&
      !/^\s*[-*]\s+/.test(lines[i])
    )
      para.push(lines[i++]);
    out.push(`<p>${para.map(inline).join("<br>")}</p>`);
  }
  return out.join("\n");
}

function renderTable(rows: string[]): string {
  const cells = (row: string) =>
    row
      .trim()
      .replace(/^\|/, "")
      .replace(/\|$/, "")
      .split("|")
      .map((c) => c.trim());
  const isSep = (row: string) => /^\s*\|?[\s:|-]+\|?\s*$/.test(row) && row.includes("-");
  const header = rows[0];
  const bodyStart = rows[1] && isSep(rows[1]) ? 2 : 1;
  const thead = `<thead><tr>${cells(header).map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>`;
  const body = rows
    .slice(bodyStart)
    .map((r) => `<tr>${cells(r).map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`)
    .join("");
  return `<table>${thead}<tbody>${body}</tbody></table>`;
}

const CSS = `
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #5a5f66; --border: #e3e5e8;
  --code-bg: #f4f5f7; --accent: #2457d6; --th-bg: #f7f8fa;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115; --fg: #e6e8eb; --muted: #9aa1a9; --border: #262a31;
    --code-bg: #171a20; --accent: #7aa2ff; --th-bg: #151820;
  }
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); margin: 0; padding: 2rem 1rem;
  font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
.report { max-width: 860px; margin: 0 auto; }
h1, h2, h3, h4 { line-height: 1.25; margin: 1.6em 0 0.5em; }
h1 { font-size: 1.7rem; } h2 { font-size: 1.35rem; } h3 { font-size: 1.1rem; }
h4 { font-size: 1rem; color: var(--muted); }
p { margin: 0.6em 0; }
a { color: var(--accent); }
code { background: var(--code-bg); padding: 0.1em 0.35em; border-radius: 4px;
  font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
pre { background: var(--code-bg); padding: 0.9rem 1rem; border-radius: 8px; overflow: auto;
  border: 1px solid var(--border); }
pre code { background: none; padding: 0; }
blockquote { margin: 0.8em 0; padding: 0.4em 1rem; border-left: 3px solid var(--accent);
  color: var(--muted); background: var(--code-bg); border-radius: 0 6px 6px 0; }
table { border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 14px; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--border); padding: 0.45rem 0.6rem; text-align: left; vertical-align: top; }
th { background: var(--th-bg); font-weight: 600; }
details { margin: 0.8em 0; }
summary { cursor: pointer; color: var(--accent); }
ul, ol { margin: 0.6em 0; padding-left: 1.5rem; }
li { margin: 0.2em 0; }
`;
