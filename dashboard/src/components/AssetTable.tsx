import { useReactTable, getCoreRowModel, flexRender } from '@tanstack/react-table';
import type { ColumnDef } from '@tanstack/react-table';
import type { CryptoAsset } from '../api/types';

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

export function AssetTable({ data }: { data: CryptoAsset[] }) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });

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
              <tr key={row.id} className="border-b border-white/5 transition-colors hover:bg-white/5">
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
    </div>
  );
}
