import { useQuery } from '@tanstack/react-query';
import { fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import type { ScanSummary } from '../api/types';

/**
 * Resolves the scan the page should display.
 *
 * Preference order: the scan explicitly opened from the Scans page, then the newest
 * succeeded scan that actually found assets, then any succeeded scan, then the newest
 * of any status. The "found assets" step matters — an empty scan (e.g. a cloned repo
 * with no crypto) would otherwise win on recency and leave every page blank.
 */
export function pickActiveScan(
  scans: ScanSummary[] | undefined,
  selectedId: string | null | undefined,
): string | undefined {
  if (selectedId) return selectedId;
  if (!scans?.length) return undefined;
  const succeeded = scans.filter((s) => s.status === 'succeeded');
  return (
    succeeded.find((s) => (s.stats?.assets ?? 0) > 0)?.id ?? succeeded[0]?.id ?? scans[0]?.id
  );
}

export function useActiveScan() {
  const scanId = useUiStore((s) => s.scanId);
  const { data: scans, isLoading } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  const activeScanId = pickActiveScan(scans, scanId);
  const activeScan = scans?.find((s) => s.id === activeScanId);
  return { activeScanId, activeScan, scans, scansLoading: isLoading };
}
