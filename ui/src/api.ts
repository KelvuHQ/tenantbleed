import type { FixesResponse, ProgressEvent, ProjectCandidate, ScanResult, TargetInfo } from "./types";

// The per-session token is handed to the page in its URL (?token=...). Every API call carries it.
const token = new URLSearchParams(location.search).get("token") ?? "";

/** Whether this page was opened with its session token. Without it, every API call is rejected. */
export const hasToken = token.length > 0;

function withToken(path: string): string {
  const u = new URL(path, location.origin);
  u.searchParams.set("token", token);
  return u.toString();
}

/** An Error from a rejected request, tagged so the UI can tell a bad token apart from a real failure. */
export class ApiError extends Error {
  authError: boolean;
  constructor(message: string, authError: boolean) {
    super(message);
    this.authError = authError;
  }
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { "x-tp-token": token } });
  if (!res.ok) {
    const msg = (await res.json().catch(() => ({}))).error ?? `${res.status} ${res.statusText}`;
    throw new ApiError(msg, res.status === 401);
  }
  return res.json() as Promise<T>;
}

export function getTarget(workdir?: string): Promise<TargetInfo> {
  const q = workdir ? `?workdir=${encodeURIComponent(workdir)}` : "";
  return getJson<TargetInfo>(`/api/target${q}`);
}

export function listProjects(): Promise<{ projects: ProjectCandidate[] }> {
  return getJson<{ projects: ProjectCandidate[] }>("/api/projects");
}

export interface HistoryEntry {
  id: string;
  savedAt: string;
  name?: string;
  proven: number;
  counts: Partial<Record<string, number>>;
  durationMs: number;
  relations: number;
  functions: number;
}

export function listHistory(workdir?: string): Promise<{ scans: HistoryEntry[] }> {
  const q = workdir ? `?workdir=${encodeURIComponent(workdir)}` : "";
  return getJson<{ scans: HistoryEntry[] }>(`/api/history${q}`);
}

export function openHistory(id: string, workdir?: string): Promise<{ scanId: string; result: ScanResult; savedAt: string }> {
  const q = workdir ? `?workdir=${encodeURIComponent(workdir)}` : "";
  return getJson<{ scanId: string; result: ScanResult; savedAt: string }>(`/api/history/${encodeURIComponent(id)}/open${q}`);
}

export async function startScan(body: { schemas?: string; triage?: boolean; workdir?: string }): Promise<string> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "x-tp-token": token, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const msg = (await res.json().catch(() => ({}))).error ?? `${res.status}`;
    throw new ApiError(msg, res.status === 401);
  }
  return (await res.json()).scanId as string;
}

export interface ScanHandlers {
  onProgress?: (e: ProgressEvent) => void;
  onNote?: (note: string) => void;
  onDone?: (result: ScanResult) => void;
  onError?: (message: string) => void;
}

/** Follow a scan over Server-Sent Events. Returns a function to stop listening. */
export function followScan(scanId: string, h: ScanHandlers): () => void {
  // EventSource cannot set headers, so the token rides in the query string.
  const es = new EventSource(withToken(`/api/scan/${scanId}/events`));
  es.addEventListener("progress", (e) => h.onProgress?.(JSON.parse((e as MessageEvent).data)));
  es.addEventListener("note", (e) => h.onNote?.(JSON.parse((e as MessageEvent).data)));
  es.addEventListener("done", (e) => {
    h.onDone?.(JSON.parse((e as MessageEvent).data));
    es.close();
  });
  es.addEventListener("error", (e) => {
    const data = (e as MessageEvent).data;
    if (data) h.onError?.(JSON.parse(data));
    es.close();
  });
  return () => es.close();
}

export function getFixes(scanId: string): Promise<FixesResponse> {
  return getJson<FixesResponse>(`/api/scan/${scanId}/fixes`);
}

/** A tokened URL for a downloadable report artifact. */
export function reportUrl(scanId: string, kind: "report.md" | "report.html" | ""): string {
  return withToken(kind ? `/api/scan/${scanId}/${kind}` : `/api/scan/${scanId}`);
}
