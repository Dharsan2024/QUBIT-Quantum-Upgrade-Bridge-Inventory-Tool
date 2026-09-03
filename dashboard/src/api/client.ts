import type {
  CryptoAsset,
  HndlExplanation,
  MigrationPatch,
  MigrationPlan,
  MigrationTask,
  Paginated,
  Project,
  ProjectOverview,
  RiskSummary,
  ScanSummary,
  LearningStats,
  LlmProvider,
  LlmProviderConfig,
  LlmProviderModels,
  LlmProviderVerifyResult,
  ThreatIntelConfig,
  ThreatIntelSnapshot,
  TimelineResponse,
} from "./types";

// Base URL + bearer token. Both overridable at build time (Vite env) or at runtime (localStorage,
// set by the Login page). The default token matches qubit-api's dev default so local runs work
// out of the box; production overrides via QUBIT_API_TOKEN on the server + login on the client.
/** Absolute base by default. IMPORTANT: in the Tauri desktop app the dashboard is bundled and loads
 *  from `tauri.localhost`, so a RELATIVE base (e.g. "/api/v1") resolves to tauri.localhost and every
 *  request fails with "Failed to fetch". Always keep this absolute for the desktop build. */
import { API_PREFIX, DEFAULT_API_BASE, normalizeApiBase } from "./apiBase";
import { projectNameForTargets } from "../lib/projectNames";

// Re-exported so existing importers of the client keep working.
export { API_PREFIX, normalizeApiBase };
export { projectNameForTargets };

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
/** The current token's identity, including the team it speaks for.
 *
 *  `tenant` matters on a shared engine: a token is bound to exactly one team, so this is how a
 *  user confirms whose projects they are about to act on before acting on them. */
export async function whoami(): Promise<{
  name: string;
  scopes: string;
  tenant: string;
  tenant_id: string;
}> {
  return send<{ name: string; scopes: string; tenant: string; tenant_id: string }>("/auth/whoami");
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

/** Source languages the code scanner can read, with the rule count behind each.

    Surfaced in the app because a language with no rules is invisible otherwise: the file parses,
    finds nothing, and reports as scanned — identical to a file with no cryptography in it. */
export async function fetchLanguages(): Promise<
  { language: string; rules: number; libraries: string[]; extensions: string[] }[]
> {
  return send<{ language: string; rules: number; libraries: string[]; extensions: string[] }[]>(
    "/registry/languages",
  );
}

export async function fetchProjects(): Promise<Project[]> {
  return send<Project[]>("/projects");
}

/** Every project with the headline numbers each tab's landing grid needs, aggregated server-side.
 *  One request instead of "fetch all scans, then all assets, then count in the browser". */
export async function fetchProjectsOverview(): Promise<ProjectOverview[]> {
  return send<ProjectOverview[]>("/projects/overview");
}

export async function createProject(name: string, description?: string): Promise<Project> {
  return send<Project>("/projects", "POST", { name, description: description ?? null });
}

// ── Scans ────────────────────────────────────────────────────────────────────
export async function fetchScans(): Promise<ScanSummary[]> {
  return send<ScanSummary[]>("/scans");
}

export async function fetchScan(scanId: string): Promise<ScanSummary> {
  return send<ScanSummary>(`/scans/${scanId}`);
}

/** Find (or create) the project a scan belongs to, by name. */
/** Normalised for comparison: a path is the same path whichever way it was typed.
 *
 *  Windows accepts either separator and is case-insensitive, and the API stores whatever it was
 *  handed — so `X:\qubit-eval-corpus\certbot` and `x:/qubit-eval-corpus/certbot/` are one directory
 *  written three ways, and comparing them literally makes each look like a different codebase. */
function samePath(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  const norm = (p: string) => p.trim().replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  return norm(a) === norm(b);
}

async function ensureProject(
  name: string,
  description: string,
  rootPath?: string,
): Promise<string> {
  const projects = await fetchProjects();
  // A project IS the codebase it points at, so the root path identifies it and the display name
  // does not. Matching on the name alone split a project in two the moment its name was edited or
  // differed from the folder: scanning `X:\...\certbot__certbot` a second time derived the name
  // `certbot__certbot`, did not match the existing `lab: certbot__certbot` over the SAME directory,
  // and created a duplicate. Everything downstream then disagreed with itself — two scans both
  // numbered #1 (the sequence is per project and each was correct), the Migration Hub showing one
  // project's plan beside the other project's scan, and "Build plan" running against the older
  // project's finished plan while the panel underneath read "no vulnerable assets in scope".
  const byPath = rootPath ? projects.find((p) => samePath(p.root_path, rootPath)) : undefined;
  const existing = byPath ?? projects.find((p) => p.name === name);
  if (existing) return existing.id;
  try {
    // Recorded at creation, not only matched on. Without it every project the dashboard makes has
    // a null root path, so the match above can never find one and the SECOND scan of a folder
    // duplicates the project all over again — the fix would work once, for projects that happened
    // to have a root path set by some other route, and never after.
    const created = await send<{ id: string }>("/projects", "POST", {
      name,
      description,
      ...(rootPath ? { root_path: rootPath } : {}),
    });
    return created.id;
  } catch (e) {
    // 409 means another tab (or a double-click) created it between the read and the write.
    if (e instanceof ApiError && e.status === 409) {
      const again = (await fetchProjects()).find((p) => p.name === name);
      if (again) return again.id;
    }
    throw e;
  }
}

/** Scan the given target paths into the stable dashboard project (risk analysis runs inline).
 *  Surfaces the API's error (e.g. "scan target does not exist") to the caller instead of hiding it. */
export async function createScan(targets: string[]): Promise<ScanSummary> {
  const projectId = await ensureProject(
    projectNameForTargets(targets, "files"),
    targets.join(", "),
    // Only for a single-target scan: with several roots there is no one directory the project is,
    // and matching on the first would fold two different multi-root scans together.
    targets.length === 1 ? targets[0] : undefined,
  );
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
  const projectId = await ensureProject(
    projectNameForTargets(targets, "network"),
    targets.join(", "),
  );
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
  const projectId = await ensureProject(projectNameForTargets([addr], "vault"), addr);
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

export async function clearAllScans(): Promise<{ deleted: number }> {
  return send<{ deleted: number }>("/scans", "DELETE");
}

/** The "Reset" button: every project, not just every scan. Deleting a project cascades its scans,
 *  assets, tasks and plans, so this clears everything `clearAllScans` does and the project shells
 *  it deliberately leaves behind. */
export async function resetAllProjects(): Promise<{ deleted: number }> {
  return send<{ deleted: number }>("/projects", "DELETE");
}

/** The gentlest of the three: throw away every migration plan and its tasks and patches, and keep
 *  the scans and assets they were derived from. Rebuilding a plan costs nothing but a click, so
 *  "start the migration over" should not also mean "rescan the corpus". */
export async function clearAllMigrationPlans(): Promise<{ deleted: number }> {
  return send<{ deleted: number }>("/migrate/plans", "DELETE");
}

// ── Bulk migration ───────────────────────────────────────────────────────────
export interface MigrationRunResult {
  plan_id: string;
  /** Which half ran. `generate` prepared patches and wrote nothing; `apply` wrote prepared
   *  patches and ran no model; `full` is the single-shot run that does both. */
  mode?: "generate" | "apply" | "full";
  total: number;
  generated: number;
  applied: number;
  covered: number;
  failed: number;
  from_cache: number;
  needs_guidance: number;
  /** `apply` runs only: findings with no patch prepared, so nothing was written for them. */
  no_patch?: number;
  repo_root: string | null;
  applied_to_disk: boolean;
  failures: { task_id: string; rule_id: string; detail: string }[];
}

export interface JobStatus {
  id: string;
  kind: string;
  status: string;
  progress?: number | null;
  stage?: string | null;
  message?: string | null;
  error?: string | null;
  result?: MigrationRunResult | null;
  /** What the job was asked to do. `plan_id` is how a reopened page finds the run it belongs to,
   *  and `apply` is how it knows whether to say "preparing" or "writing". */
  payload?: { plan_id?: string; apply?: boolean; generate?: boolean } | null;
}

/** A migration already in flight for this plan, or null.
 *
 *  The run lives on the server; the page only watches it. Nothing recorded that, so the job id was
 *  component state — leaving the Migration Hub unmounted the component, the id was lost, and coming
 *  back showed a project with no run in progress and a "Build plan" button inviting a SECOND one.
 *  The first was still going the whole time.
 *
 *  So the page asks. `apply` distinguishes the two halves, because a run that is preparing changes
 *  must never be described as writing them. */
export async function findRunningMigration(
  planId: string,
): Promise<{ id: string; mode: "generate" | "apply" } | null> {
  const jobs = await send<JobStatus[]>("/jobs?limit=25");
  const mine = jobs.find(
    (j) =>
      j.kind === "migrate" &&
      ["queued", "running"].includes(j.status) &&
      j.payload?.plan_id === planId,
  );
  if (!mine) return null;
  return { id: mine.id, mode: mine.payload?.apply ? "apply" : "generate" };
}

/** Run one or both halves of a plan's migration. Returns the job to poll — the work happens off
 *  the request path because a plan of twenty findings takes minutes.
 *
 *  - `{ generate: true, apply: false }` — "Build plan": prepare a patch per finding, touch nothing.
 *  - `{ generate: false, apply: true }` — "Initiate migration": write the prepared patches in.
 *  - neither — the single-shot run, which is what every caller got before the split. */
export async function runPlan(
  planId: string,
  opts: {
    apply?: boolean;
    generate?: boolean;
    generator?: "auto" | "llm" | "template";
  } = {},
): Promise<{ job: { id: string; kind: string }; tasks: number; warning: string }> {
  return send(`/migrate/plans/${planId}/run`, "POST", {
    apply: opts.apply ?? true,
    generate: opts.generate ?? true,
    generator: opts.generator ?? "auto",
  });
}

export async function fetchJob(jobId: string): Promise<JobStatus> {
  return send<JobStatus>(`/jobs/${jobId}`);
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
/** Migration plans, newest first. With `projectId`, only that project's — plans built before
 *  plans carried a scope have a null `project_id` and are excluded by the filter rather than
 *  being silently attributed to a project they were not built from. */
/** What the engine has learned from its own migrations. Local; nothing here leaves the machine. */
export async function fetchLearning(): Promise<LearningStats> {
  return send<LearningStats>("/migrate/learning");
}

export async function fetchPlans(projectId?: string): Promise<MigrationPlan[]> {
  const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return send<MigrationPlan[]>(`/migrate/plans${q}`);
}

/** Build a plan. `scanId` narrows it to one scan's assets — the default for a rebuild, because
 *  nothing dedupes assets across scans, so a project-wide plan over a directory scanned three
 *  times carries three copies of every task. */
export async function createPlan(
  minRisk = 0,
  opts: { projectId?: string; scanId?: string } = {},
): Promise<MigrationPlan> {
  return send<MigrationPlan>("/migrate/plans", "POST", {
    min_risk: minRisk,
    project_id: opts.projectId ?? null,
    scan_id: opts.scanId ?? null,
  });
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

/** Ask the local model how to migrate this finding by hand.
 *
 *  For the tasks QUBIT cannot patch — a structural protocol change, a language with no codemod, a
 *  SQL dialect the token swap cannot express — the queue otherwise says "manual change" and stops.
 *  Needs Ollama; the result is cached on the task, and `force` regenerates it. */
export async function adviseTask(taskId: string, force = false): Promise<MigrationTask> {
  return send<MigrationTask>(`/migrate/tasks/${taskId}/advise`, "POST", { force });
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

// ── Threat intelligence (optional, off by default) ─────────────────────────────
// A fixed, curated allowlist of NIST reference pages — never "the whole web" — checked only when
// the user opts in. A changed source is staged as a snapshot for review, never auto-applied to the
// CRQC/Mosca parameters. See qubit_risk.threat_intel for the full rationale.
export async function fetchThreatIntelConfig(): Promise<ThreatIntelConfig> {
  return send<ThreatIntelConfig>("/threat-intel/config");
}

export async function patchThreatIntelConfig(
  patch: Partial<Pick<ThreatIntelConfig, "enabled" | "check_interval_hours">>,
): Promise<ThreatIntelConfig> {
  return send<ThreatIntelConfig>("/threat-intel/config", "PATCH", patch);
}

/** Fetches every allowlisted source right now, regardless of the configured interval. */
export async function runThreatIntelCheckNow(): Promise<ThreatIntelSnapshot[]> {
  return send<ThreatIntelSnapshot[]>("/threat-intel/check-now", "POST");
}

export async function fetchThreatIntelSnapshots(limit = 20): Promise<ThreatIntelSnapshot[]> {
  return send<ThreatIntelSnapshot[]>(`/threat-intel/snapshots?limit=${limit}`);
}

export async function reviewThreatIntelSnapshot(
  snapshotId: string,
  note?: string,
): Promise<ThreatIntelSnapshot> {
  return send<ThreatIntelSnapshot>(`/threat-intel/snapshots/${snapshotId}/review`, "POST", {
    note: note ?? null,
  });
}

// ── LLM provider (Ollama by default; an external OpenAI-compatible endpoint on opt-in) ────────
// Which engine `qubit_migrate` calls for patch generation. Ollama stays the always-available
// fallback: an external outage degrades generation, it never stops it. See Settings' own copy.
export async function fetchLlmProviderConfig(): Promise<LlmProviderConfig> {
  return send<LlmProviderConfig>("/llm-provider/config");
}

export async function patchLlmProviderConfig(patch: {
  provider?: LlmProvider;
  base_url?: string;
  model?: string;
  /** Omit to keep the existing key; empty string clears it. */
  api_key?: string;
  backup_base_url?: string;
  backup_model?: string;
  /** Same convention as `api_key`: omit to keep, empty string to clear. */
  backup_api_key?: string;
}): Promise<LlmProviderConfig> {
  return send<LlmProviderConfig>("/llm-provider/config", "PATCH", patch);
}

/** Makes one real, cheap call against whatever is currently saved — never accepts a key in the
 *  request, so a partially-typed key can never leak into this call. Save first, then verify. */
export async function verifyLlmProvider(): Promise<LlmProviderVerifyResult> {
  return send<LlmProviderVerifyResult>("/llm-provider/verify", "POST");
}

/** The models the SAVED provider actually offers, read live from it. Requires the config to be
 *  saved first (an external provider needs its key to answer at all). */
export async function fetchLlmProviderModels(): Promise<LlmProviderModels> {
  return send<LlmProviderModels>("/llm-provider/models");
}
