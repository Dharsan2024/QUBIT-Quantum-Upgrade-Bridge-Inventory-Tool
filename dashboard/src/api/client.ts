import type { CryptoAsset, Paginated } from "./types";

const API_BASE = "http://127.0.0.1:8787/api/v1";

export async function fetchAssets(projectId: string, scanId?: string, page = 1, size = 50): Promise<Paginated<CryptoAsset>> {
  let url = `${API_BASE}/projects/${projectId}/assets?page=${page}&size=${size}`;
  if (scanId) {
    url += `&scan_id=${scanId}`;
  }
  
  const res = await fetch(url);
  if (!res.ok) {
    // If project not found or no assets, we might return empty for scaffolding
    if (res.status === 404) return { items: [], total: 0, page, size };
    throw new Error(`Failed to fetch assets: ${res.statusText}`);
  }
  
  return res.json();
}
