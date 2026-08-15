export type SourceScanner = "code" | "config" | "network" | "cert" | "key";
// "secret" / "sensitive-data" are the HNDL exposure surface — what an attacker gains once
// harvested traffic becomes decryptable (see qubit_core.schemas.AssetType).
export type AssetType =
  | "algorithm-use"
  | "protocol"
  | "certificate"
  | "key"
  | "library"
  | "secret"
  | "sensitive-data";
export type UsageContext = "tls" | "kex" | "signature" | "encryption-at-rest" | "token" | "hash" | "password" | "unknown";
export type Sensitivity =
  | "pii"
  | "phi"
  | "financial"
  | "ip"
  | "credentials"
  | "ephemeral"
  | "public"
  | "unknown";
export type Confidence = "high" | "medium" | "low";

export interface LocationRef {
  host?: string;
  service?: string;
  repo?: string;
  file_path?: string;
  line?: number;
}

export interface QuantumVulnerability {
  vulnerable: boolean;
  attack: "shor" | "grover" | "none";
}

export interface RiskAnnotation {
  score: number;
  ci_low: number;
  ci_high: number;
  mosca_margin_years: number;
  priority_rank: number;
}

/** Proof of a finding, post-redaction. `context.extra.hndl_narrative` carries the
 *  scanner's "how this is exploited under HNDL" explanation for secret/PII findings. */
export interface Evidence {
  snippet: string;
  snippet_sha256?: string | null;
  context: {
    symbols?: Record<string, string[]>;
    imports?: string[];
    extra?: Record<string, unknown>;
  };
}

export interface CryptoAsset {
  id: string;
  source_scanner: SourceScanner;
  location: LocationRef;
  asset_type: AssetType;
  algorithm: string;
  key_size?: number | null;
  library?: { name: string; version?: string | null } | null;
  usage_context: UsageContext;
  quantum_vulnerable: QuantumVulnerability;
  evidence: Evidence;
  discovered_at: string;
  sensitivity?: Sensitivity;
  shelf_life_years?: number | null;
  risk?: RiskAnnotation | null;
  rule_id?: string | null;
  confidence?: Confidence;
}

/** Matches qubit_api.schemas.Page[T] exactly: {items, total, limit, offset}. There is no
 *  page/size on the wire — the server is offset-paginated. */
export interface Paginated<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  root_path: string | null;
  description: string | null;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ScanStats {
  files_scanned?: number;
  files_skipped?: number;
  parse_failures?: number;
  detections?: number;
  assets?: number;
  duration_s?: number;
}

export interface ScanSummary {
  id: string;
  project_id: string;
  seq: number;
  label: string | null;
  status: string;
  targets: string[];
  scanners: string[];
  stats: ScanStats;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

// ── Migration workflow (doc 03 over REST) ────────────────────────────────────
export interface MigrationPlan {
  id: string;
  status: string;
  stats: { tasks?: number; units?: number; message?: string };
  created_at: string;
}

export interface MigrationTask {
  id: string;
  plan_id: string;
  asset_id: string;
  state: string;
  rule_id: string | null;
  priority: number;
  rank: number;
  effort_points: number;
  last_error: string | null;
  algorithm: string | null;
  file_path: string | null;
  line: number | null;
  risk_score: number | null;
}

export interface MigrationPatch {
  id: string;
  task_id: string;
  generator: string;
  model_name: string | null;
  file_path: string;
  diff_text: string;
  validation: {
    passed?: boolean;
    partial?: boolean;
    stages?: Record<string, { status: string; detail: string }>;
  };
  status: string;
  review_note: string | null;
  applied_branch: string | null;
  applied_commit: string | null;
}

/** Top-8 TreeSHAP contribution for the XGBoost regressor (doc 02 §6.4.6). */
export interface ShapContribution {
  feature: string;
  contribution: number;
}

/** XGBoost distillation tier output: calibrated score + conformal CI + SHAP (doc 02 §6.4). */
export interface RegressorExplanation {
  score: number;
  ci_low: number;
  ci_high: number;
  shap_top: ShapContribution[];
}

/** Response of GET /assets/{id}/hndl — per-asset HNDL factor decomposition (doc 02 §6.2). */
export interface HndlExplanation {
  asset_id: string;
  algorithm: string;
  vulnerable: boolean;
  shor?: boolean;
  note?: string;
  exposure?: string;
  sensitivity?: string;
  tier?: string;
  harvest_prob?: number;
  p_decrypt?: number;
  p_hndl_closed_form?: number;
  p_hndl_bayes_net?: number;
  bn_closed_form_agreement?: number;
  crqc_median_year?: number | null;
  persisted_score?: number | null;
  score_source?: "closed-form" | "xgb";
  regressor?: RegressorExplanation | null;
}

/** Response of GET /scans/{id}/risk/summary — aggregate risk posture for one scan. */
export interface RiskSummary {
  total_assets: number;
  by_algorithm: Record<string, { count: number; vulnerable: number }>;
  by_usage_context: Record<string, number>;
  risk_scores: number[];
  top_10_risk: { asset_id: string; algorithm: string; risk_score: number }[];
}

/** Response of GET /risk/timeline?algorithm= — real Monte-Carlo CRQC arrival curve. */
export interface TimelineResponse {
  algorithm: string;
  blended?: boolean;
  survey_weight?: number | null;
  years: number[];
  cdf: number[];
  cdf_stderr: number[];
  median_year: number;
  p05_year: number;
  p95_year: number;
  n_trials: number;
}

export interface GraphNode {
  id: string;
  asset_id: string;
  algorithm?: string;
  usage_context?: string;
  risk_score?: number;
  unit_id?: number | null; // integer index into units[] (API emits a number, not a string)
  order_index?: number | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind?: string;
  confidence?: number;
}

export interface GraphUnit {
  unit_id: number; // integer index (API: enumerate() of units)
  members: string[];
  is_cycle?: boolean;
}

export interface PlanGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  units: GraphUnit[];
}

export interface GovernanceGateResponse {
  gate_status: string;
  required_approvals: number;
  current_approvals: number;
  approvers: string[];
  sensitivity: string;
  reasons: string[];
}

/** Response of GET /assets/{id}/recommendation — per-asset PQC recommendation (E1, doc 08 §2). */
export interface AssetRecommendation {
  asset_id: string;
  current: {
    algorithm: string;
    key_size?: number | null;
    usage_context: string;
    quantum_vulnerable: boolean;
    attack: string;
  };
  target: Record<string, unknown>; // {algorithm, mode: "pure"|"hybrid", parameter_set, ...}
  library: { name?: string; min_version?: string };
  rationale: string;
  source: "rule" | "kb" | "agility-policy";
  confidence: number;
}

