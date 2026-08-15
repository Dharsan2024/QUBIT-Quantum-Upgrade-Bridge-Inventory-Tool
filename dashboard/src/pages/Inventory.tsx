import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useQuery, useInfiniteQuery } from '@tanstack/react-query';
import { fetchScanAssets, fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import { pickActiveScan } from '../hooks/useActiveScan';
import { AssetTable } from '../components/AssetTable';
import { AnimatedPage } from '../components/AnimatedPage';
import { Kpi } from '../components/Kpi';
import {
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Boxes,
  KeyRound,
  Download,
  Filter,
  FileText,
  Search,
} from 'lucide-react';
import type { CryptoAsset } from '../api/types';


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
  const [searchInput, setSearchInput] = useState('');
  const [searchQ, setSearchQ] = useState(''); // debounced value sent to API

  // 350 ms debounce — avoids a fetch on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setSearchQ(searchInput), 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Resolve which scan to show — same rule every page uses (see pickActiveScan).
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  const activeScanId = pickActiveScan(scans, scanId);
  const activeScan = scans?.find((s) => s.id === activeScanId);

  // 200 is the server's hard page cap (see routers/assets.py `limit: le=200`), so most real
  // scans load in one page. When a scan exceeds that, the KPI breakdown below is flagged as
  // partial rather than silently under-counting.
  const PAGE_SIZE = 200;
  const { data, isLoading, isError, error, refetch, isFetching, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
    queryKey: ['assets', activeScanId, searchQ],
    queryFn: ({ pageParam }) => fetchScanAssets(activeScanId as string, pageParam, PAGE_SIZE, searchQ),
    initialPageParam: 0, // offset, not a page number — the server is offset-paginated
    getNextPageParam: (lastPage) => {
      const nextOffset = lastPage.offset + lastPage.limit;
      return nextOffset < lastPage.total ? nextOffset : undefined;
    },
    enabled: !!activeScanId,
  });

  // Flatten the paginated pages into a single items array
  const items: CryptoAsset[] = useMemo(() => {
    if (!data) return [];
    return data.pages.flatMap((p) => p.items);
  }, [data]);
  const totalAssets = data?.pages[0]?.total ?? 0;
  // True once every asset for this scan has been fetched — before that, the breakdown tiles
  // below only reflect the loaded pages and must say so rather than imply a full count.
  const allLoaded = items.length >= totalAssets;
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
          {activeScanId && (
            <Link to={`/report/${activeScanId}`} className="hud-btn hud-btn-ghost">
              <FileText className="h-3.5 w-3.5" />
              Detailed Report
            </Link>
          )}
          <Link to="/cbom" className="hud-btn">
            <Download className="h-3.5 w-3.5" />
            Export CBOM
          </Link>
        </div>
      </header>

      <div className="stagger grid grid-cols-2 gap-5 lg:grid-cols-4">
        <Kpi
          label="Total assets"
          value={totalAssets}
          icon={<Boxes className="h-9 w-9" />}
          color="var(--color-accent)"
        />
        <Kpi
          label={allLoaded ? 'Quantum-vulnerable' : 'Quantum-vulnerable*'}
          value={vulnerable}
          icon={<ShieldAlert className="h-9 w-9" />}
          color="var(--color-danger)"
        />
        <Kpi
          label={allLoaded ? 'HNDL exposures' : 'HNDL exposures*'}
          value={hndl}
          icon={<KeyRound className="h-9 w-9" />}
          color="var(--color-accent-2)"
        />
        <Kpi
          label={allLoaded ? 'Quantum-safe' : 'Quantum-safe*'}
          value={safe}
          icon={<ShieldCheck className="h-9 w-9" />}
          color="var(--color-safe)"
        />
      </div>
      {!allLoaded && (
        <p className="metric-label -mt-2 normal-case tracking-normal text-[color:var(--color-warn)]">
          * Based on the {items.length} of {totalAssets} assets loaded so far — load more below
          for the full breakdown.
        </p>
      )}

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
              {/* Server-side full-text search: algorithm, file path, evidence snippet */}
              <label className="label-caps flex items-center gap-2">
                <Search className="h-3.5 w-3.5 text-[color:var(--color-accent)]/60" />
                <input
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Search algorithm, path…"
                  className="glass-input py-1 text-xs w-44"
                  spellCheck={false}
                />
              </label>
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
              Showing {shown.length} of {totalAssets} entries
            </div>
          </div>
          <AssetTable data={shown} />
          {hasNextPage && (
            <div className="flex justify-center p-4 border-t border-[color:var(--edge)]">
              <button
                onClick={() => fetchNextPage()}
                disabled={isFetchingNextPage}
                className="hud-btn"
              >
                {isFetchingNextPage ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  'Load more'
                )}
              </button>
            </div>
          )}
        </div>
      )}
    </AnimatedPage>
  );
}
