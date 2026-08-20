import { useQuery } from '@tanstack/react-query';
import { fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import type { ScanSummary } from '../api/types';

/**
 * Resolves the scan the page should display, **within the selected project**.
 *
 * The project filter is the part that was missing. `pickActiveScan` used to run over every scan in
 * the installation, so opening a project and then switching tabs quietly moved you to whatever the
 * newest scan anywhere happened to be — on the development machine that meant a project's Risk tab
 * showing a different project's assets from the tab beside it. Scoping the candidate list first is
 * what makes a tab's numbers belong to the project named at the top of it.
 *
 * Within the project, preference order: the scan explicitly opened from Scans & Jobs, then the
 * newest succeeded scan that actually found assets, then any succeeded scan, then the newest of any
 * status. The "found assets" step matters — an empty scan (e.g. a cloned repo with no crypto) would
 * otherwise win on recency and leave every page blank.
 */
export function pickActiveScan(
  scans: ScanSummary[] | undefined,
  selectedId: string | null | undefined,
  projectId?: string | undefined,
): string | undefined {
  const inScope = projectId ? (scans ?? []).filter((s) => s.project_id === projectId) : (scans ?? []);
  // A remembered scan only counts if it is still in this project — and still exists. A deleted
  // scan left every page showing "no data" with no indication why.
  if (selectedId && inScope.some((s) => s.id === selectedId)) return selectedId;
  if (!inScope.length) return undefined;
  const succeeded = inScope.filter((s) => s.status === 'succeeded');
  return succeeded.find((s) => (s.stats?.assets ?? 0) > 0)?.id ?? succeeded[0]?.id ?? inScope[0]?.id;
}

export function useActiveScan() {
  const scanId = useUiStore((s) => s.scanId);
  const projectId = useUiStore((s) => s.projectId);
  const { data: scans, isLoading } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  const activeScanId = pickActiveScan(scans, scanId, projectId);
  const activeScan = scans?.find((s) => s.id === activeScanId);
  /** This project's scans, newest first — for the in-page scan switcher. */
  const projectScans = projectId
    ? (scans ?? []).filter((s) => s.project_id === projectId)
    : (scans ?? []);
  return { activeScanId, activeScan, scans, projectScans, projectId, scansLoading: isLoading };
}
