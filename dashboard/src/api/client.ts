import type {
  CryptoAsset,
  HndlExplanation,
  MigrationPatch,
  MigrationPlan,
  MigrationTask,
  Paginated,
  Project,
  RiskSummary,
  ScanSummary,
  TimelineResponse,
} from "./types";

// Base URL + bearer token. Both overridable at build time (Vite env) or at runtime (localStorage,
// set by the Login page). The default token matches qubit-api's dev default so local runs work
// out of the box; production overrides via QUBIT_API_TOKEN on the server + login on the client.
/** Absolute base by default. IMPORTANT: in the Tauri desktop app the dashboard is bundled and loads
 *  from `tauri.localhost`, so a RELATIVE base (e.g. "/api/v1") resolves to tauri.localhost and every
 *  request fails with "Failed to fetch". Always keep this absolute for the desktop build. */
import { API_PREFIX, DEFAULT_API_BASE, normalizeApiBase } from "./apiBase";

// Re-exported so existing importers of the client keep working.
export { API_PREFIX, normalizeApiBase };

/** Set by the API itself on the HTML it serves (native desktop mode) — see `_mount_dashboard`.
 *  Present ONLY when this page came from the API, so it is a reliable signal that the API shares
 *  this origin, whatever port it ended up on. */
declare global {
  interface Window {
    __QUBIT_API_BASE__?: string;
  }
}

export function getApiBase(): string {
  if (typeof window !== "undefined") {
    // 1. An explicit choice by the user (Login page) always wins.
    const override = localStorage.getItem("qubit_api_base");
    if (override) return normalizeApiBase(override);
    // 2. The base the serving API injected. This beats the build-time default because that default
    //    hardcodes a PORT (127.0.0.1:8787) which the desktop launcher cannot always bind — 8787 is
    //    inside the range Windows reserves for Hyper-V/WSL on some machines, so the launcher has to
    //    move and a build-time base would then point at nothing. Same-origin is port-agnostic.
    if (window.__QUBIT_API_BASE__) return normalizeApiBase(window.__QUBIT_API_BASE__);
  }
  return normalizeApiBase((import.meta.env.VITE_API_BASE as string | undefined) ?? DEFAULT_API_BASE);
}

export function setApiBase(base: string) {
  // Stored already-normalized, so anything reading localStorage directly (the desktop shell, a
  // browser test) sees a usable value rather than whatever was typed.
  localStorage.setItem("qubit_api_base", normalizeApiBase(base));
}
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
  const res = await fetch(`${getApiBase()}${path}`, {
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

// ── Auth / projects ───────────────────────────────────────────────────────────
export async function whoami(): Promise<{ name: string; scopes: string }> {
  return send<{ name: string; scopes: string }>("/auth/whoami");
}

/** Engine liveness + version. Anonymous endpoint — no token needed. */
export async function fetchHealth(): Promise<{ status: string; db: string; version: string }> {
  return send<{ status: string; db: string; version: string }>("/health");
}

/** Optional local dependencies (Docker sandbox validation, Ollama LLM patches). */
export async function fetchHealthDeps(): Promise<{
  api: string;
  docker: boolean;
  ollama: boolean;
}> {
  return send<{ api: string; docker: boolean; ollama: boolean }>("/health/deps");
}

export async function fetchProjects(): Promise<Project[]> {
  return send<Project[]>("/projects");
}

// ── Scans ────────────────────────────────────────────────────────────────────
export async function fetchScans(): Promise<ScanSummary[]> {
  return send<ScanSummary[]>("/scans");
}

export async function fetchScan(scanId: string): Promise<ScanSummary> {
  return send<ScanSummary>(`/scans/${scanId}`);
}

const DASHBOARD_PROJECT = "Dashboard scans";

/** Find the single stable dashboard project, creating it once. Previously every scan minted a new
 *  `scan-<timestamp>` project, which piled up dozens of empty junk projects. */
async function ensureDashboardProject(): Promise<string> {
  const projects = await fetchProjects();
  const existing = projects.find((p) => p.name === DASHBOARD_PROJECT);
  if (existing) return existing.id;
  const created = await send<{ id: string }>("/projects", "POST", { name: DASHBOARD_PROJECT });
  return created.id;
}

/** Scan the given target paths into the stable dashboard project (risk analysis runs inline).
 *  Surfaces the API's error (e.g. "scan target does not exist") to the caller instead of hiding it. */
export async function createScan(targets: string[]): Promise<ScanSummary> {
  const projectId = await ensureDashboardProject();
  const resp = await send<{ scan: ScanSummary }>(`/projects/${projectId}/scans`, "POST", {
    targets,
    run_risk: true,
  });
  return resp.scan;
}

/** Live TLS/SSH enumeration + hybrid-PQC group probe against hosts.
 *
 *  `authorized` is the scanner's own authorization assertion, not an API permission: loopback and
 *  RFC1918 targets are always allowed, and this flag is required for a PUBLIC host, which must also
 *  appear in the server-side scan allowlist. Left false unless the operator ticks the box. */
export async function createNetworkScan(
  targets: string[],
  opts: { ports?: number[]; probePqc?: boolean; authorized?: boolean } = {},
): Promise<ScanSummary> {
  const projectId = await ensureDashboardProject();
  const resp = await send<{ scan: ScanSummary }>(
    `/projects/${projectId}/scans/network`,
    "POST",
    {
      targets,
      ports: opts.ports ?? [443],
      probe_pqc: opts.probePqc ?? true,
      authorized: opts.authorized ?? false,
      run_risk: true,
    },
  );
  return resp.scan;
}

/** HashiCorp Vault transit-key + PKI-certificate enumeration.
 *
 *  The token is sent for this one request and is never persisted by the server — not in the job
 *  payload, the scan row, or any response. It is also deliberately NOT written to localStorage here. */
export async function createVaultScan(
  addr: string,
  token: string,
  opts: { mountTransit?: string; mountPki?: string } = {},
): Promise<ScanSummary> {
  const projectId = await ensureDashboardProject();
  const resp = await send<{ scan: ScanSummary }>(`/projects/${projectId}/scans/vault`, "POST", {
    addr,
    token,
    mount_transit: opts.mountTransit ?? "transit",
    mount_pki: opts.mountPki ?? "pki",
    run_risk: true,
  });
  return resp.scan;
}

export async function deleteScan(scanId: string): Promise<void> {
  await send<void>(`/scans/${scanId}`, "DELETE");
}

// ── Assets ───────────────────────────────────────────────────────────────────
/**
 * `offset`/`limit` match the server's actual query params exactly (routers/assets.py:
 * `limit: int = 50, le=200` / `offset: int = 0`) — there is no page/size pagination on the
 * wire. Previously this sent `page`/`size`, which the server silently ignored (unrecognized
 * query params), so every call fell back to the default limit=50 regardless of what the caller
 * asked for — pagination beyond the first 50 assets was unreachable app-wide until this fix.
 */
export async function fetchScanAssets(
  scanId: string,
  offset = 0,
  limit = 100,
  q = '',
): Promise<Paginated<CryptoAsset>> {
  try {
    const params = new URLSearchParams({ offset: String(offset), limit: String(limit) });
    if (q.trim()) params.set('q', q.trim());
    return await send<Paginated<CryptoAsset>>(`/scans/${scanId}/assets?${params.toString()}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return { items: [], total: 0, limit, offset };
    throw e;
  }
}

// ── Risk ─────────────────────────────────────────────────────────────────────
/** On-demand CRQC arrival curve for one algorithm (real Monte-Carlo simulator, doc 02 §5.3). */
export async function fetchTimeline(
  algorithm = "RSA-2048",
  opts: { blend?: boolean; weight?: number } = {},
): Promise<TimelineResponse> {
  const params = new URLSearchParams({ algorithm });
  if (opts.blend) params.set("blend", "true");
  if (opts.weight != null) params.set("weight", String(opts.weight));
  return send<TimelineResponse>(`/risk/timeline?${params.toString()}`);
}

// The scan summary already carries the risk aggregates (scores, top-10, by-algorithm).
// /scans/{id}/risk/summary is the separate normative RiskRun record (needs POST /risk/run first).
export async function fetchAssetHndl(assetId: string): Promise<HndlExplanation> {
  return send<HndlExplanation>(`/assets/${assetId}/hndl`);
}

// E1 per-asset PQC recommendation. The API returns 404 for a non-vulnerable asset (no action
// needed) — callers should treat ApiError(404) as "no recommendation", not an error.
export async function fetchRecommendation(
  assetId: string,
): Promise<import("./types").AssetRecommendation> {
  return send<import("./types").AssetRecommendation>(`/assets/${assetId}/recommendation`);
}

export async function fetchRiskSummary(scanId: string): Promise<RiskSummary> {
  return send<RiskSummary>(`/scans/${scanId}/summary`);
}

// ── Migration workflow ───────────────────────────────────────────────────────
export async function fetchPlans(): Promise<MigrationPlan[]> {
  return send<MigrationPlan[]>("/migrate/plans");
}

export async function createPlan(minRisk = 0): Promise<MigrationPlan> {
  return send<MigrationPlan>("/migrate/plans", "POST", { min_risk: minRisk });
}

export async function fetchPlanQueue(planId: string): Promise<MigrationTask[]> {
  return send<MigrationTask[]>(`/migrate/plans/${planId}/queue`);
}

export async function generatePatch(
  taskId: string,
  generator: "auto" | "llm" | "template" = "auto",
): Promise<MigrationPatch> {
  return send<MigrationPatch>(`/migrate/tasks/${taskId}/generate`, "POST", { generator });
}

export async function fetchTaskPatches(taskId: string): Promise<MigrationPatch[]> {
  return send<MigrationPatch[]>(`/migrate/tasks/${taskId}/patches`);
}

export async function reviewPatch(
  patchId: string,
  approve: boolean,
  note = "",
): Promise<MigrationPatch> {
  return send<MigrationPatch>(`/migrate/patches/${patchId}/review`, "POST", { approve, note });
}

export async function fetchPlanGraph(planId: string): Promise<import("./types").PlanGraphResponse> {
  return send<import("./types").PlanGraphResponse>(`/migrate/plans/${planId}/graph`);
}

export async function fetchTaskGovernance(taskId: string): Promise<import("./types").GovernanceGateResponse> {
  return send<import("./types").GovernanceGateResponse>(`/migrate/tasks/${taskId}/governance`);
}

// ── CBOM ─────────────────────────────────────────────────────────────────────
/** CycloneDX 1.7 CBOM document for a scan. */
export async function fetchCbom(scanId: string): Promise<Record<string, unknown>> {
  return send<Record<string, unknown>>(`/scans/${scanId}/cbom`);
}

// ── Compliance + reports ─────────────────────────────────────────────────────
/** CNSA 2.0 migration-milestone posture for a scan (NSA deadlines 2025 → 2035). */
export async function fetchCnsa2(scanId: string): Promise<import("./types").Cnsa2Report> {
  return send<import("./types").Cnsa2Report>(`/scans/${scanId}/cnsa2`);
}

/** SARIF 2.1.0 log for a scan — uploadable to GitHub code scanning. */
export async function fetchSarif(
  scanId: string,
  includeSafe = false,
): Promise<Record<string, unknown>> {
  const q = includeSafe ? "?include_safe=true" : "";
  return send<Record<string, unknown>>(`/scans/${scanId}/sarif${q}`);
}

/**
 * The real paginated PDF report, as bytes.
 *
 * Deliberately NOT routed through `send()`: that helper ends in `res.json()`, which would throw on
 * a PDF body. It also cannot be a plain `<a href>` link, because every API route requires an
 * `Authorization` header and a link cannot carry one — the download has to be a fetch.
 */
export async function fetchReportPdf(scanId: string): Promise<Uint8Array> {
  const res = await fetch(`${getApiBase()}/scans/${scanId}/report.pdf`, {
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
  return new Uint8Array(await res.arrayBuffer());
}
