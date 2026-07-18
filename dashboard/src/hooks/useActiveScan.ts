import { useQuery } from '@tanstack/react-query';
import { fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';

/**
 * Resolves the scan the page should display: the one selected on the Scans page,
 * otherwise the most recent succeeded scan (falling back to the newest of any status).
 */
export function useActiveScan() {
  const scanId = useUiStore((s) => s.scanId);
  const { data: scans, isLoading } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  const activeScanId =
    scanId ?? scans?.find((s) => s.status === 'succeeded')?.id ?? scans?.[0]?.id;
  const activeScan = scans?.find((s) => s.id === activeScanId);
  return { activeScanId, activeScan, scans, scansLoading: isLoading };
}
