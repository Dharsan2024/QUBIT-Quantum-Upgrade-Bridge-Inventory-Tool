import { useState } from 'react';
import { useReactTable, getCoreRowModel, flexRender } from '@tanstack/react-table';
import type { ColumnDef } from '@tanstack/react-table';
import { useQuery } from '@tanstack/react-query';
import { X, Lightbulb } from 'lucide-react';
import type { CryptoAsset } from '../api/types';
import { fetchRecommendation, ApiError } from '../api/client';

function VerdictChip({ asset }: { asset: CryptoAsset }) {
  const qv = asset.quantum_vulnerable;
  if (!qv.vulnerable) return <span className="chip chip-safe">safe</span>;
  if (qv.attack === 'shor') return <span className="chip chip-danger">vuln · shor</span>;
  return <span className="chip chip-warn">vuln · {qv.attack}</span>;
}

function RiskBar({ score }: { score: number | null | undefined }) {
  if (score == null) return <span className="text-[color:var(--color-ink-faint)]">—</span>;
  const pct = Math.round(score * 100);
  const hue = score >= 0.66 ? 'var(--color-danger)' : score >= 0.33 ? 'var(--color-warn)' : 'var(--color-safe)';
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: hue }} />
      </div>
      <span className="tabular-nums text-xs text-[color:var(--color-ink-dim)]">{score.toFixed(2)}</span>
    </div>
  );
}

const columns: ColumnDef<CryptoAsset>[] = [
  {
    accessorKey: 'algorithm',
    header: 'Algorithm',
    cell: (info) => (
      <span className="font-mono font-medium text-[color:var(--color-ink)]">
        {info.getValue() as string}
      </span>
    ),
  },
  { accessorKey: 'usage_context', header: 'Context' },
  {
    id: 'status',
    header: 'Quantum',
    cell: ({ row }) => <VerdictChip asset={row.original} />,
  },
  {
    id: 'risk',
    header: 'Risk',
    cell: ({ row }) => <RiskBar score={row.original.risk?.score} />,
  },
  {
    id: 'location',
    header: 'Location',
    cell: ({ row }) => {
      const loc = row.original.location;
      const text = loc.file_path
        ? `${loc.file_path}${loc.line ? `:${loc.line}` : ''}`
        : loc.host
          ? `${loc.host}:${loc.service || ''}`
          : null;
      return text ? (
        <span className="font-mono text-xs text-[color:var(--color-ink-dim)]">{text}</span>
      ) : (
        <span className="italic text-[color:var(--color-ink-faint)]">unknown</span>
      );
    },
  },
  {
    accessorKey: 'risk.priority_rank',
    header: 'Rank',
    cell: (info) => {
      const val = info.getValue();
      return val ? (
        <span className="font-semibold">{val as number}</span>
      ) : (
        <span className="text-[color:var(--color-ink-faint)]">—</span>
      );
    },
  },
];

function RecommendationDrawer({ asset, onClose }: { asset: CryptoAsset; onClose: () => void }) {
  // Only vulnerable assets have a recommendation; the API 404s otherwise (treated as "no action").
  const enabled = asset.quantum_vulnerable.vulnerable;
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['recommendation', asset.id],
    queryFn: () => fetchRecommendation(asset.id),
    enabled,
    retry: false,
  });
  const notFound = isError && error instanceof ApiError && error.status === 404;
  const target = data?.target as { algorithm?: string; mode?: string } | undefined;

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <aside className="glass-card relative z-50 flex h-full w-full max-w-md flex-col gap-4 overflow-y-auto rounded-none p-6">
        <header className="flex items-start justify-between">
          <div>
            <div className="font-mono text-lg font-semibold">{asset.algorithm}</div>
            <div className="text-xs uppercase tracking-wide text-[color:var(--color-ink-faint)]">
              {asset.usage_context} · {asset.quantum_vulnerable.vulnerable ? `vuln · ${asset.quantum_vulnerable.attack}` : 'quantum-safe'}
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1 hover:bg-white/10" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </header>

        {asset.location.file_path && (
          <div className="font-mono text-xs text-[color:var(--color-ink-dim)]">
            {asset.location.file_path}
            {asset.location.line ? `:${asset.location.line}` : ''}
          </div>
        )}

        <section className="flex flex-col gap-2">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Lightbulb className="h-4 w-4 text-amber-300" /> PQC Recommendation
          </div>

          {!enabled && (
            <p className="text-sm text-[color:var(--color-ink-dim)]">
              This asset is quantum-safe — no migration needed.
            </p>
          )}
          {enabled && isLoading && (
            <p className="text-sm text-[color:var(--color-ink-faint)]">Loading recommendation…</p>
          )}
          {enabled && notFound && (
            <p className="text-sm text-[color:var(--color-ink-dim)]">
              No recommendation available for this algorithm/context.
            </p>
          )}
          {enabled && isError && !notFound && (
            <p className="text-sm text-rose-300">
              Could not load: {error instanceof Error ? error.message : 'unknown error'}
            </p>
          )}
          {data && (
            <div className="flex flex-col gap-3">
              <div className="glass-input flex items-center justify-between gap-3 py-2">
                <span className="text-xs text-[color:var(--color-ink-faint)]">Target</span>
                <span className="font-mono text-sm font-medium text-emerald-200">
                  → {target?.algorithm ?? '—'}
                  {target?.mode ? ` (${target.mode})` : ''}
                </span>
              </div>
              {(data.library?.name || data.library?.min_version) && (
                <div className="glass-input flex items-center justify-between gap-3 py-2">
                  <span className="text-xs text-[color:var(--color-ink-faint)]">Library</span>
                  <span className="font-mono text-sm">
                    {data.library.name}
                    {data.library.min_version ? ` ≥ ${data.library.min_version}` : ''}
                  </span>
                </div>
              )}
              <div className="flex items-center justify-between gap-3 text-xs">
                <span className="chip chip-safe">source: {data.source}</span>
                <span className="text-[color:var(--color-ink-faint)]">
                  confidence {data.confidence.toFixed(2)}
                </span>
              </div>
              {data.rationale && (
                <p className="text-sm leading-relaxed text-[color:var(--color-ink-dim)]">
                  {data.rationale}
                </p>
              )}
            </div>
          )}
        </section>
      </aside>
    </div>
  );
}

export function AssetTable({ data }: { data: CryptoAsset[] }) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });
  const [selected, setSelected] = useState<CryptoAsset | null>(null);

  return (
    <div className="glass-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-b border-white/10">
                {hg.headers.map((h) => (
                  <th
                    key={h.id}
                    className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[color:var(--color-ink-faint)]"
                  >
                    {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                onClick={() => setSelected(row.original)}
                className="cursor-pointer border-b border-white/5 transition-colors hover:bg-white/5"
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="whitespace-nowrap px-5 py-3.5">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {data.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-5 py-10 text-center text-[color:var(--color-ink-faint)]"
                >
                  No cryptographic assets found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {selected && <RecommendationDrawer asset={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
