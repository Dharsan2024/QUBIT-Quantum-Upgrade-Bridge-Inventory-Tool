import { useState } from 'react';
import { createPortal } from 'react-dom';
import { useReactTable, getCoreRowModel, flexRender } from '@tanstack/react-table';
import type { ColumnDef } from '@tanstack/react-table';
import { useQuery } from '@tanstack/react-query';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { X, Radar, Code2, ShieldCheck, Bolt, Copy, ExternalLink } from 'lucide-react';
import type { CryptoAsset } from '../api/types';
import { fetchRecommendation, ApiError } from '../api/client';
import { displayAlgorithm, shortPath } from '../lib/assetLabels';

/** True for the HNDL exposure surface (hardcoded secrets / PII), not a crypto algorithm. */
function isHndlFinding(a: CryptoAsset): boolean {
  return a.asset_type === 'secret' || a.asset_type === 'sensitive-data';
}

/** The HUD severity band drives every colour decision for a row. */
type Band = 'critical' | 'high' | 'medium' | 'safe';

/**
 * Severity band. The scored HNDL risk wins when the risk engine has run, so the word
 * ("High") never contradicts the number next to it; the quantum verdict is the fallback
 * for assets that have not been scored yet.
 */
function band(a: CryptoAsset): Band {
  const score = a.risk?.score;
  if (score != null) {
    if (score >= 0.66) return 'critical';
    if (score >= 0.33) return 'high';
    if (score >= 0.15) return 'medium';
    // A zero-risk score still deserves a warning colour if the algorithm itself is broken.
    return a.quantum_vulnerable.vulnerable || isHndlFinding(a) ? 'medium' : 'safe';
  }
  if (isHndlFinding(a)) return 'high';
  if (!a.quantum_vulnerable.vulnerable) return 'safe';
  return a.quantum_vulnerable.attack === 'shor' ? 'high' : 'medium';
}

const displayName = (a: CryptoAsset): string => displayAlgorithm(a.algorithm);

const BAND_TEXT: Record<Band, string> = {
  critical: 'text-[color:var(--color-danger)]',
  high: 'text-[color:var(--color-danger)]',
  medium: 'text-[color:var(--color-warn)]',
  safe: 'text-[color:var(--color-safe)]',
};
const BAND_LABEL: Record<Band, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  safe: 'Low',
};

/** Technical chip for the algorithm / finding type — violet for HNDL, severity hue otherwise. */
function TypeChip({ asset }: { asset: CryptoAsset }) {
  const cls = isHndlFinding(asset)
    ? 'chip chip-violet'
    : `chip ${band(asset) === 'safe' ? 'chip-safe' : band(asset) === 'medium' ? 'chip-warn' : 'chip-danger'}`;
  return (
    <span className={cls} title={asset.algorithm}>
      {displayName(asset)}
    </span>
  );
}

/** Human-readable quantum verdict. HNDL findings state the exposure, not an attack name. */
function quantumStatus(a: CryptoAsset): string {
  if (isHndlFinding(a)) return a.asset_type === 'secret' ? 'Harvestable secret' : 'Harvestable data';
  const qv = a.quantum_vulnerable;
  if (!qv.vulnerable) return 'Quantum-safe';
  return qv.attack === 'shor' ? 'Shor-breakable' : `Weakened · ${qv.attack}`;
}

/**
 * Segmented risk readout (DESIGN.md "Risk Bars"): 10 vertical blocks that transition
 * mint -> violet -> red rather than a smooth fill.
 */
function RiskBar({ score }: { score: number | null | undefined }) {
  if (score == null) {
    return <span className="text-[color:var(--color-ink-faint)]">—</span>;
  }
  const filled = Math.max(1, Math.round(score * 10));
  const tone = score >= 0.66 ? 'danger' : score >= 0.33 ? 'mid' : 'safe';
  return (
    <div className="flex items-center gap-2.5">
      <div className="risk-bar w-24">
        {Array.from({ length: 10 }, (_, i) => (
          <span key={i} className={`risk-seg ${i < filled ? `risk-seg-on-${tone}` : ''}`} />
        ))}
      </div>
      <span className="w-9 tabular-nums text-xs text-[color:var(--color-ink-dim)]">
        {score.toFixed(2)}
      </span>
    </div>
  );
}

const columns: ColumnDef<CryptoAsset>[] = [
  {
    accessorKey: 'risk.priority_rank',
    header: 'Rank',
    cell: (info) => {
      const val = info.getValue();
      return (
        <span className="text-[color:var(--color-accent)]/60">{val ? `#${val as number}` : '—'}</span>
      );
    },
  },
  {
    accessorKey: 'algorithm',
    header: 'Algorithm / Type',
    cell: ({ row }) => <TypeChip asset={row.original} />,
  },
  {
    accessorKey: 'usage_context',
    header: 'Context',
    cell: ({ row }) => (
      <span className="text-[color:var(--color-accent-soft)]">{row.original.usage_context}</span>
    ),
  },
  {
    id: 'status',
    header: 'Quantum status',
    cell: ({ row }) => (
      <span className={isHndlFinding(row.original) ? 'text-[color:var(--color-accent-2)]' : BAND_TEXT[band(row.original)]}>
        {quantumStatus(row.original)}
      </span>
    ),
  },
  {
    id: 'severity',
    header: 'Risk',
    cell: ({ row }) => {
      const b = band(row.original);
      return (
        <span className={`${BAND_TEXT[b]} ${b === 'critical' ? 'font-bold' : ''}`}>
          {BAND_LABEL[b]}
        </span>
      );
    },
  },
  {
    id: 'score',
    header: 'Score',
    cell: ({ row }) => <RiskBar score={row.original.risk?.score} />,
  },
  {
    id: 'location',
    header: 'Location',
    cell: ({ row }) => {
      const loc = row.original.location;
      const full = loc.file_path
        ? `${loc.file_path}${loc.line ? `:${loc.line}` : ''}`
        : loc.host
          ? `${loc.host}:${loc.service || ''}`
          : null;
      if (!full) return <span className="italic text-[color:var(--color-ink-faint)]">unknown</span>;
      // Absolute Windows paths are long enough to push the table off-screen; show the tail
      // and keep the full path on hover.
      return (
        <span className="text-xs text-[color:var(--color-ink-dim)]" title={full}>
          {loc.file_path ? shortPath(full) : full}
        </span>
      );
    },
  },
  {
    id: 'action',
    header: '',
    cell: () => (
      <ExternalLink className="ml-auto h-3.5 w-3.5 text-[color:var(--color-accent)]/60" />
    ),
  },
];

/** A short "what an HNDL attacker gains" line. Prefers the scanner's own narrative. */
function exposureNarrative(asset: CryptoAsset): string {
  const fromScanner = asset.evidence?.context?.extra?.hndl_narrative;
  if (typeof fromScanner === 'string' && fromScanner) return fromScanner;

  const where = asset.location.file_path ?? asset.location.host ?? 'this asset';
  if (!asset.quantum_vulnerable.vulnerable) {
    return `${asset.algorithm} at ${where} is not broken by a known quantum attack. Traffic harvested today stays protected after a CRQC arrives.`;
  }
  if (asset.quantum_vulnerable.attack === 'shor') {
    return `${asset.algorithm} at ${where} is broken outright by Shor's algorithm. Under harvest-now-decrypt-later an adversary records this traffic today and decrypts it retroactively the moment a cryptographically-relevant quantum computer exists — so the exposure starts now, not on CRQC day.`;
  }
  return `${asset.algorithm} at ${where} loses roughly half its security margin to Grover's algorithm. That is a weakening rather than a break, but harvested data is still exposed for the remainder of its shelf life.`;
}

function Section({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-2.5">
      <h3 className="label-caps flex items-center gap-2 text-[color:var(--color-accent)]/70">
        {icon}
        {title}
      </h3>
      {children}
    </section>
  );
}

function RecommendationDrawer({ asset, onClose }: { asset: CryptoAsset; onClose: () => void }) {
  // Only vulnerable assets have a recommendation; the API 404s otherwise (treated as "no action").
  const enabled = asset.quantum_vulnerable.vulnerable;
  const reduce = useReducedMotion();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['recommendation', asset.id],
    queryFn: () => fetchRecommendation(asset.id),
    enabled,
    retry: false,
  });
  const notFound = isError && error instanceof ApiError && error.status === 404;
  const target = data?.target as { algorithm?: string; mode?: string } | undefined;
  const b = band(asset);
  const snippet = asset.evidence?.snippet ?? '';
  const locText = asset.location.file_path
    ? `${asset.location.file_path}${asset.location.line ? `:${asset.location.line}` : ''}`
    : (asset.location.host ?? '—');

  // Purpose: spatial consistency — the panel enters from and exits to the same (right) edge it lives
  // on, so it reads as "slid in from the side" rather than teleporting. transform+opacity only.
  // Reduced-motion collapses the slide to a plain fade (gentler, not zero).
  const drawerAnim = reduce
    ? { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }
    : {
        initial: { transform: 'translateX(100%)' },
        animate: { transform: 'translateX(0%)' },
        exit: { transform: 'translateX(100%)' },
      };

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <motion.div
        className="absolute inset-0 bg-black/65 backdrop-blur-sm"
        onClick={onClose}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2, ease: [0.23, 1, 0.32, 1] }}
      />
      {/* Level-2 elevated glass. Opaque enough that the table can't bleed through. */}
      <motion.aside
        className="relative z-50 flex h-full w-full max-w-xl flex-col border-l border-[color:var(--edge-lume)] bg-[#0b0e14]/97 shadow-[-20px_0_50px_rgba(0,0,0,0.6)] backdrop-blur-2xl"
        {...drawerAnim}
        transition={{ duration: 0.3, ease: [0.32, 0.72, 0, 1] }}
      >
        <header className="flex-none border-b border-[color:var(--edge)] bg-[color:var(--color-accent)]/4 p-6">
          <button
            onClick={onClose}
            className="absolute right-5 top-5 text-[color:var(--color-ink-faint)] transition-colors hover:text-[color:var(--color-accent)]"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span
              className={`chip ${b === 'safe' ? 'chip-safe' : b === 'medium' ? 'chip-warn' : 'chip-danger'}`}
            >
              {BAND_LABEL[b]} risk
            </span>
            <span className={isHndlFinding(asset) ? 'chip chip-violet' : 'chip chip-info'}>
              {quantumStatus(asset)}
            </span>
            {asset.confidence && <span className="chip chip-info">{asset.confidence} confidence</span>}
          </div>
          <h2 className="flex items-center gap-3 font-mono text-2xl font-semibold tracking-tight text-[color:var(--color-accent)]">
            {displayName(asset)}
            <button
              onClick={() => navigator.clipboard?.writeText(asset.algorithm)}
              className="text-[color:var(--color-ink-faint)] transition-colors hover:text-[color:var(--color-accent)]"
              title="Copy"
              aria-label="Copy algorithm name"
            >
              <Copy className="h-4 w-4" />
            </button>
          </h2>
          <div className="label-caps mt-1.5 normal-case tracking-normal text-[color:var(--color-ink-dim)]">
            {locText}
          </div>
        </header>

        <div className="flex flex-1 flex-col gap-7 overflow-y-auto p-6">
          <Section icon={<Radar className="h-3.5 w-3.5" />} title="HNDL exposure">
            <div className="border-l-2 border-[color:var(--color-accent-2)]/50 pl-4">
              <p className="text-sm leading-relaxed text-[color:var(--color-ink-dim)]">
                {exposureNarrative(asset)}
              </p>
            </div>
          </Section>

          {snippet && (
            <Section icon={<Code2 className="h-3.5 w-3.5" />} title="Evidence">
              <div className="glass no-ticks overflow-hidden">
                <div className="flex items-center justify-between gap-3 border-b border-[color:var(--edge)] px-3 py-2">
                  <span className="label-caps">Path</span>
                  <span className="truncate font-mono text-xs text-[color:var(--color-accent-3)]">
                    {locText}
                  </span>
                </div>
                <pre className="overflow-x-auto bg-black/50 p-3 font-mono text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                  {snippet}
                </pre>
              </div>
              {asset.rule_id && (
                <div className="label-caps">
                  Rule <span className="text-[color:var(--color-accent-soft)]">{asset.rule_id}</span>
                </div>
              )}
            </Section>
          )}

          {asset.risk && (
            <Section icon={<Bolt className="h-3.5 w-3.5" />} title="Risk breakdown">
              <div className="grid grid-cols-2 gap-4">
                <div className="glass p-4">
                  <div className="label-caps mb-2.5">HNDL score (90% CI)</div>
                  <div className="mb-2 flex items-end gap-2">
                    <span className={`metric text-[2rem] ${BAND_TEXT[b]}`}>
                      {asset.risk.score.toFixed(2)}
                    </span>
                    <span className="pb-1 font-mono text-[11px] text-[color:var(--color-ink-faint)]">
                      [{asset.risk.ci_low.toFixed(2)}, {asset.risk.ci_high.toFixed(2)}]
                    </span>
                  </div>
                  <RiskBar score={asset.risk.score} />
                </div>
                <div className="glass p-4">
                  <div className="label-caps mb-2.5">Mosca margin</div>
                  <div className="flex items-end gap-2">
                    <span
                      className={`metric text-[2rem] ${
                        asset.risk.mosca_margin_years < 0
                          ? 'text-[color:var(--color-danger)]'
                          : 'text-[color:var(--color-accent-2)]'
                      }`}
                    >
                      {asset.risk.mosca_margin_years > 0 ? '+' : ''}
                      {asset.risk.mosca_margin_years.toFixed(1)}
                    </span>
                    <span className="pb-1 font-mono text-[11px] text-[color:var(--color-ink-faint)]">
                      years
                    </span>
                  </div>
                  <p className="mt-2 font-mono text-[11px] leading-relaxed text-[color:var(--color-ink-faint)]">
                    Z − (X + Y). Negative means migration is already overdue.
                  </p>
                </div>
              </div>
            </Section>
          )}
        </div>

        <footer className="flex-none border-t border-[color:var(--edge)] bg-black/30 p-6">
          <h3 className="label-caps mb-2 flex items-center gap-2 text-[color:var(--color-safe)]">
            <ShieldCheck className="h-3.5 w-3.5" />
            PQC recommendation
          </h3>

          {!enabled && (
            <p className="text-sm text-[color:var(--color-ink-dim)]">
              {isHndlFinding(asset)
                ? 'Remove the secret from source and rotate it; then ensure the channel and store protecting it use quantum-safe crypto.'
                : 'This asset is quantum-safe — no migration needed.'}
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
            <p className="text-sm text-[color:var(--color-danger)]">
              Could not load: {error instanceof Error ? error.message : 'unknown error'}
            </p>
          )}
          {data && (
            <div className="flex flex-col gap-3">
              <p className="text-sm text-[color:var(--color-ink)]">
                Migrate to{' '}
                <span className="chip chip-safe">
                  {target?.algorithm ?? '—'}
                  {target?.mode ? ` · ${target.mode}` : ''}
                </span>
                {data.library?.name && (
                  <>
                    {' '}
                    using{' '}
                    <span className="font-mono text-[color:var(--color-accent-soft)]">
                      {data.library.name}
                      {data.library.min_version ? ` ≥ ${data.library.min_version}` : ''}
                    </span>
                  </>
                )}
                .
              </p>
              {data.rationale && (
                <p className="text-sm leading-relaxed text-[color:var(--color-ink-dim)]">
                  {data.rationale}
                </p>
              )}
              <div className="flex items-center justify-between gap-3">
                <span className="chip chip-info">source: {data.source}</span>
                <span className="label-caps">confidence {data.confidence.toFixed(2)}</span>
              </div>
            </div>
          )}
        </footer>
      </motion.aside>
    </div>
  );
}

export function AssetTable({ data }: { data: CryptoAsset[] }) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });
  const [selected, setSelected] = useState<CryptoAsset | null>(null);

  return (
    <div className="glass-card no-tilt scan-panel" style={{ ['--scan-h' as string]: '100%' }}>
      <div className="overflow-x-auto">
        <table className="hud-table min-w-full">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className="px-5 py-3">
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
                className={`data-row cursor-pointer ${
                  isHndlFinding(row.original) ? 'bg-[color:var(--color-accent-2)]/6' : ''
                }`}
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
                  className="px-5 py-12 text-center text-[color:var(--color-ink-faint)]"
                >
                  No assets found in this scan.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {/* Portalled to <body>: the table's panel sets `will-change: transform` for the HUD hover
          lift, which makes it a containing block for position:fixed children — the drawer would
          otherwise be clipped to the table instead of covering the window. */}
      {createPortal(
        <AnimatePresence>
          {selected && <RecommendationDrawer asset={selected} onClose={() => setSelected(null)} />}
        </AnimatePresence>,
        document.body,
      )}
    </div>
  );
}
