import type { CryptoAsset, Paginated, ScanSummary, TimelineResponse } from "./types";

// Base URL + bearer token. Both overridable at build time (Vite env) or at runtime (localStorage,
// set by the Login page). The default token matches qubit-api's dev default so local runs work
// out of the box; production overrides via QUBIT_API_TOKEN on the server + login on the client.
const API_BASE =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8787/api/v1";
const DEFAULT_TOKEN =
  (import.meta.env.VITE_API_TOKEN as string | undefined) ?? "qubit-dev-token-do-not-use-in-prod";

export function getToken(): string {
  return localStorage.getItem("qubit_token") || DEFAULT_TOKEN;
}

export function setToken(token: string): void {
  localStorage.setItem("qubit_token", token);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function send<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const detail = await res
      .clone()
      .json()
      .then((b) => (b as { detail?: string }).detail)
      .catch(() => null);
    throw new ApiError(res.status, detail ?? `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ── Scans ────────────────────────────────────────────────────────────────────
export async function fetchScans(): Promise<ScanSummary[]> {
  return send<ScanSummary[]>("/scans");
}

export async function fetchScan(scanId: string): Promise<ScanSummary> {
  return send<ScanSummary>(`/scans/${scanId}`);
}

/** Create an ad-hoc project + scan for the given target paths (risk analysis runs inline). */
export async function createScan(name: string, targets: string[]): Promise<ScanSummary> {
  const project = await send<{ id: string }>("/projects", "POST", { name });
  const resp = await send<{ scan: ScanSummary }>(`/projects/${project.id}/scans`, "POST", {
    targets,
    run_risk: true,
  });
  return resp.scan;
}

export async function deleteScan(scanId: string): Promise<void> {
  await send<void>(`/scans/${scanId}`, "DELETE");
}

// ── Assets ───────────────────────────────────────────────────────────────────
export async function fetchScanAssets(
  scanId: string,
  page = 1,
  size = 100,
): Promise<Paginated<CryptoAsset>> {
  try {
    return await send<Paginated<CryptoAsset>>(`/scans/${scanId}/assets?page=${page}&size=${size}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return { items: [], total: 0, page, size };
    throw e;
  }
}

// ── Risk ─────────────────────────────────────────────────────────────────────
/** On-demand CRQC arrival curve for one algorithm (real Monte-Carlo simulator, doc 02 §5.3). */
export async function fetchTimeline(algorithm = "RSA-2048"): Promise<TimelineResponse> {
  return send<TimelineResponse>(`/risk/timeline?algorithm=${encodeURIComponent(algorithm)}`);
}
