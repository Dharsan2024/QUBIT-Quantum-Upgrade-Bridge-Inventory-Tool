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
