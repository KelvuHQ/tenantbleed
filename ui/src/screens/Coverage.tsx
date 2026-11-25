import type { CoverageRow, ScanResult } from "../types";

export function statusOf(r: CoverageRow): { label: string; cls: string; detail?: string } {
  if (r.jwtScoped) return { label: "scoped by JWT claim", cls: "status-warn", detail: `tenant key is the '${r.jwtScoped}' claim, which the scan does not mint, so it was not attacked` };
  if (r.shared) return { label: "shared by design", cls: "status-muted", detail: "no path to a single tenant; treated as shared" };
  if (r.staffList) return { label: "staff list", cls: "status-muted", detail: "app-wide list left empty on purpose" };
  if (r.notExposed) return { label: "schema not exposed", cls: "status-muted", detail: "filled only to call functions; not served by the API" };
  if (!r.populated) return { label: "no test data", cls: "status-muted", detail: r.reason };
  if (r.kind === "function") {
    if (r.broken) return { label: "broken", cls: "status-muted", detail: r.broken };
    if (r.refused) return { label: "not callable", cls: "status-muted", detail: r.refusedMessage ?? "permission denied for the API roles" };
    if (r.ownerControl === "guarded") return { label: "tested", cls: "status-ok", detail: "checks the caller" };
    if (r.ownerControl === "secret-gated") return { label: "tested", cls: "status-ok", detail: "answers only to a secret the caller knows" };
    if (r.ownerControl === "no-effect") return { label: "check yourself", cls: "status-warn", detail: "the test call did nothing; see Check yourself" };
  }
  if (r.reached === 0 && r.unreachable > 0) return { label: "not served", cls: "status-muted", detail: "the API answered 404/406" };
  if (r.reached === 0 && r.unreachable === 0) return { label: "no API access", cls: "status-muted" };
  return { label: "tested", cls: "status-ok", detail: r.reason };
}

/** The clean/breached verdict for a coverage row: red when a tenant crossed into it, teal when it was tested and held, a dash when it was not tested. */
function verdictOf(r: CoverageRow, breached: Set<string>): { label: string; cls: string } {
  if (breached.has(r.relation)) return { label: "breached", cls: "cov-breached" };
  if (statusOf(r).cls === "status-ok") return { label: "clean", cls: "cov-clean" };
  return { label: "not tested", cls: "cov-na" };
}

export function Coverage({ result }: { result: ScanResult }) {
  const rows = [...result.coverage].sort((a, b) => a.relation.localeCompare(b.relation));
  const breached = new Set(result.findings.filter((f) => f.confidence === "proven").map((f) => f.target));
  const tested = rows.filter((r) => statusOf(r).cls === "status-ok" || breached.has(r.relation)).length;
  const breachedCount = rows.filter((r) => breached.has(r.relation)).length;

  return (
    <div>
      <h1>Coverage</h1>
      <p className="sub">
        What was tested, what was not, and why. {tested} of {rows.length} reachable objects were tested
        {breachedCount > 0 ? <>: <span className="cov-breached">{breachedCount} breached</span>, the rest held</> : ", and all of them held"}. The untested rest are declared here, not hidden.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Result</th>
              <th>Relation</th>
              <th>Kind</th>
              <th>Status</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const s = statusOf(r);
              const v = verdictOf(r, breached);
              return (
                <tr key={`${r.kind}:${r.relation}`}>
                  <td className={v.cls}>
                    <span className="cov-dot" aria-hidden="true" />
                    {v.label}
                  </td>
                  <td className="mono" style={{ color: "var(--fg)" }}>{r.relation}</td>
                  <td className="status-muted">{r.kind}</td>
                  <td className={s.cls}>{s.label}</td>
                  <td className="meta">{s.detail ?? ""}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
