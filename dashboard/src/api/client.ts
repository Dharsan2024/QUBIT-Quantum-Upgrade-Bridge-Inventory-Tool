import type { CryptoAsset, Paginated, TimelineResponse } from "./types";

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

async function request<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!res.ok) {
    const detail = await res
      .clone()
      .json()
      .then((b) => (b as { detail?: string }).detail)
      .catch(() => null);
    throw new ApiError(res.status, detail ?? `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchAssets(
  projectId: string,
  scanId?: string,
  page = 1,
  size = 50,
): Promise<Paginated<CryptoAsset>> {
  let path = `/projects/${projectId}/assets?page=${page}&size=${size}`;
  if (scanId) path += `&scan_id=${scanId}`;
  try {
    return await request<Paginated<CryptoAsset>>(path);
  } catch (e) {
    // A project/scan that doesn't exist yet is an empty inventory, not an error.
    if (e instanceof ApiError && e.status === 404) {
      return { items: [], total: 0, page, size };
    }
    throw e;
  }
}

/** On-demand CRQC arrival curve for one algorithm (real Monte-Carlo simulator, doc 02 §5.3). */
export async function fetchTimeline(algorithm = "RSA-2048"): Promise<TimelineResponse> {
  return request<TimelineResponse>(`/risk/timeline?algorithm=${encodeURIComponent(algorithm)}`);
}
