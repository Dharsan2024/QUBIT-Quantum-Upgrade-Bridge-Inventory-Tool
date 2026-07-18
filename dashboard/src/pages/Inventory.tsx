import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAssets } from '../api/client';
import { useUiStore } from '../stores/ui';
import { AssetTable } from '../components/AssetTable';
import { RefreshCw, ShieldAlert, ShieldCheck, Boxes, Zap } from 'lucide-react';
import type { CryptoAsset } from '../api/types';

function Kpi({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  accent: string;
}) {
  return (
    <div className="glass-card flex items-center gap-4 p-4">
      <div className={`flex h-11 w-11 items-center justify-center rounded-xl ${accent}`}>{icon}</div>
      <div>
        <div className="text-2xl font-semibold leading-none">{value}</div>
        <div className="mt-1 text-xs uppercase tracking-wide text-[color:var(--color-ink-faint)]">
          {label}
        </div>
      </div>
    </div>
  );
}

export function Inventory() {
  const projectId = useUiStore((s) => s.projectId);
  const scanId = useUiStore((s) => s.scanId);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['assets', projectId, scanId],
    queryFn: () => fetchAssets(projectId, scanId),
  });

  const items: CryptoAsset[] = data?.items ?? [];
  const vulnerable = items.filter((a) => a.quantum_vulnerable.vulnerable).length;
  const shor = items.filter((a) => a.quantum_vulnerable.attack === 'shor').length;
  const safe = items.length - vulnerable;

  return (
    <div className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Cryptographic Inventory</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            {projectId} · scan{' '}
            <span className="text-[color:var(--color-ink)]">{scanId || 'latest'}</span>
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="glass-input flex items-center gap-2 text-sm font-medium hover:border-indigo-400/60"
        >
          <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </header>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Kpi
          label="Total assets"
          value={data?.total ?? 0}
          icon={<Boxes className="h-5 w-5 text-indigo-200" />}
          accent="bg-indigo-500/20 border border-indigo-400/30"
        />
        <Kpi
          label="Quantum-vulnerable"
          value={vulnerable}
          icon={<ShieldAlert className="h-5 w-5 text-rose-200" />}
          accent="bg-rose-500/20 border border-rose-400/30"
        />
        <Kpi
          label="Shor-breakable"
          value={shor}
          icon={<Zap className="h-5 w-5 text-amber-200" />}
          accent="bg-amber-500/20 border border-amber-400/30"
        />
        <Kpi
          label="Quantum-safe"
          value={safe}
          icon={<ShieldCheck className="h-5 w-5 text-emerald-200" />}
          accent="bg-emerald-500/20 border border-emerald-400/30"
        />
      </div>

      {isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading assets…
        </div>
      )}

      {isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load inventory: {error instanceof Error ? error.message : 'unknown error'}.
          <span className="text-[color:var(--color-ink-faint)]"> Is the API running on :8787?</span>
        </div>
      )}

      {data && (
        <div className="flex flex-col gap-3">
          <div className="text-sm text-[color:var(--color-ink-faint)]">
            Showing {items.length} of {data.total} assets
          </div>
          <AssetTable data={items} />
        </div>
      )}
    </div>
  );
}
