export type SourceScanner = "code" | "config" | "network" | "cert" | "key";
export type AssetType = "algorithm-use" | "protocol" | "certificate" | "key" | "library";
export type UsageContext = "tls" | "kex" | "signature" | "encryption-at-rest" | "token" | "hash" | "password" | "unknown";

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

export interface CryptoAsset {
  id: string;
  source_scanner: SourceScanner;
  location: LocationRef;
  asset_type: AssetType;
  algorithm: string;
  key_size?: number;
  usage_context: UsageContext;
  quantum_vulnerable: QuantumVulnerability;
  evidence: string;
  discovered_at: string;
  risk?: RiskAnnotation;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
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
  years: number[];
  cdf: number[];
  cdf_stderr: number[];
  median_year: number;
  p05_year: number;
  p95_year: number;
  n_trials: number;
}
