import type { ReactNode } from 'react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { fetchScanAssets, fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import { pickActiveScan } from '../hooks/useActiveScan';
import { AssetTable } from '../components/AssetTable';
import { AnimatedPage } from '../components/AnimatedPage';
import {
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Boxes,
  KeyRound,
  Download,
  Filter,
} from 'lucide-react';
import type { CryptoAsset } from '../api/types';

/**
 * HUD readout tile: label on top, oversized figure bottom-left, ghosted glyph bottom-right,
 * with the panel's hairline tinted to the tile's semantic colour (DESIGN.md summary stats).
 */
function Kpi({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  color: string;
}) {
  return (
    <div
      className="glass-card flex h-32 flex-col justify-between p-5"
      style={{ borderColor: `color-mix(in srgb, ${color} 32%, transparent)` }}
    >
      <span className="metric-label" style={{ color }}>
        {label}
      </span>
      <div className="flex items-end justify-between gap-3">
        <span className="metric" style={{ color }}>
          {value}
        </span>
        <span className="opacity-25" style={{ color }}>
          {icon}
        </span>
      </div>
    </div>
  );
}

type RiskFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
type TypeFilter = 'all' | 'crypto' | 'hndl';

function isHndl(a: CryptoAsset): boolean {
  return a.asset_type === 'secret' || a.asset_type === 'sensitive-data';
}

function riskBucket(a: CryptoAsset): RiskFilter {
  const s = a.risk?.score;
  if (s == null) return 'low';
  if (s >= 0.66) return 'critical';
  if (s >= 0.33) return 'high';
  if (s >= 0.15) return 'medium';
  return 'low';
}

export function Inventory() {
  const scanId = useUiStore((s) => s.scanId);
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');

  // Resolve which scan to show — same rule every page uses (see pickActiveScan).
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  const activeScanId = pickActiveScan(scans, scanId);
  const activeScan = scans?.find((s) => s.id === activeScanId);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['assets', activeScanId],
    queryFn: () => fetchScanAssets(activeScanId as string),
    enabled: !!activeScanId,
  });

  // Memoised so the filter below has a stable input (`data?.items ?? []` allocates each render).
  const items: CryptoAsset[] = useMemo(() => data?.items ?? [], [data?.items]);
  const vulnerable = items.filter((a) => a.quantum_vulnerable.vulnerable).length;
  const hndl = items.filter(isHndl).length;
  const safe = items.filter((a) => !a.quantum_vulnerable.vulnerable && !isHndl(a)).length;

  const shown = useMemo(
    () =>
      items.filter((a) => {
        if (typeFilter === 'crypto' && isHndl(a)) return false;
        if (typeFilter === 'hndl' && !isHndl(a)) return false;
        if (riskFilter !== 'all' && riskBucket(a) !== riskFilter) return false;
        return true;
      }),
    [items, typeFilter, riskFilter],
  );

  return (
    <AnimatedPage className="flex flex-col gap-6 py-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1>Cryptographic Inventory</h1>
          <h2 className="mt-1 flex items-center gap-2 text-[color:var(--color-accent-2)]/85">
            <ShieldAlert className="h-5 w-5" />
            &amp; HNDL exposure surface
          </h2>
          <p className="metric-label mt-2.5 normal-case tracking-normal">
            {activeScan
              ? `Scan #${activeScan.seq} · ${activeScan.targets.join(', ')}`
              : 'No scan selected'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => refetch()} className="hud-btn hud-btn-ghost" disabled={!activeScanId}>
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/cbom" className="hud-btn">
            <Download className="h-3.5 w-3.5" />
            Export CBOM
          </Link>
        </div>
      </header>

      <div className="stagger grid grid-cols-2 gap-5 lg:grid-cols-4">
        <Kpi
          label="Total assets"
          value={data?.total ?? 0}
          icon={<Boxes className="h-9 w-9" />}
          color="var(--color-accent)"
        />
        <Kpi
          label="Quantum-vulnerable"
          value={vulnerable}
          icon={<ShieldAlert className="h-9 w-9" />}
          color="var(--color-danger)"
        />
        <Kpi
          label="HNDL exposures"
          value={hndl}
          icon={<KeyRound className="h-9 w-9" />}
          color="var(--color-accent-2)"
        />
        <Kpi
          label="Quantum-safe"
          value={safe}
          icon={<ShieldCheck className="h-9 w-9" />}
          color="var(--color-safe)"
        />
      </div>

      {!activeScanId && (
        <div className="glass-card p-10 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link to="/scans" className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]">
            Run a scan
          </Link>{' '}
          to populate the inventory.
        </div>
      )}

      {isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-14 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading assets…
        </div>
      )}

      {isError && (
        <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)]">
          Could not load inventory: {error instanceof Error ? error.message : 'unknown error'}.
          <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
        </div>
      )}

      {data && (
        <div className="flex flex-col gap-4">
          {/* Toolbar: real client-side filters over the loaded scan. */}
          <div className="glass no-ticks flex flex-wrap items-center justify-between gap-4 px-5 py-3">
            <div className="flex flex-wrap items-center gap-4">
              <Filter className="h-3.5 w-3.5 text-[color:var(--color-accent)]/50" />
              <label className="label-caps flex items-center gap-2">
                Risk
                <select
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value as RiskFilter)}
                  className="glass-input py-1 text-xs"
                >
                  <option value="all">All risks</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </label>
              <label className="label-caps flex items-center gap-2">
                Type
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value as TypeFilter)}
                  className="glass-input py-1 text-xs"
                >
                  <option value="all">All types</option>
                  <option value="crypto">Crypto assets</option>
                  <option value="hndl">HNDL exposures</option>
                </select>
              </label>
            </div>
            <div className="label-caps">
              Showing {shown.length} of {data.total} entries
            </div>
          </div>
          <AssetTable data={shown} />
        </div>
      )}
    </AnimatedPage>
  );
}
