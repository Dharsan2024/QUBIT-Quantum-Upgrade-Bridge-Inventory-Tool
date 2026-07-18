import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { Terminal, RefreshCw, ArrowRight } from 'lucide-react';
import { fetchScanAssets } from '../api/client';
import { useActiveScan } from '../hooks/useActiveScan';
import type { CryptoAsset } from '../api/types';

// Recommended post-quantum / hardened replacement for a vulnerable asset. Heuristic by attack +
// usage; the authoritative codemod target is chosen by the `qubit migrate` planner on the backend.
function recommend(asset: CryptoAsset): string {
  const ctx = asset.usage_context;
  if (asset.quantum_vulnerable.attack === 'shor') {
    if (ctx === 'signature' || ctx === 'token') return 'ML-DSA-65';
    return 'ML-KEM-768';
  }
  if (asset.quantum_vulnerable.attack === 'grover') {
    if (ctx === 'hash') return 'SHA-256';
    if (ctx === 'password') return 'Argon2id';
    return 'AES-256';
  }
  return '—';
}

function locOf(a: CryptoAsset): string {
  const l = a.location;
  if (l.file_path) return `${l.file_path}${l.line ? `:${l.line}` : ''}`;
  if (l.host) return `${l.host}:${l.service ?? ''}`;
  return 'unknown';
}

export function Migrations() {
  const { activeScanId, activeScan } = useActiveScan();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['assets', activeScanId],
    queryFn: () => fetchScanAssets(activeScanId as string),
    enabled: !!activeScanId,
  });

  const candidates = (data?.items ?? [])
    .filter((a) => a.quantum_vulnerable.vulnerable)
    .sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0));

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Migration Queue</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            {activeScan
              ? `Recommended replacements for vulnerable assets · scan #${activeScan.seq}`
              : 'Prioritized cryptographic migration candidates.'}
          </p>
        </div>
      </header>

      <div className="glass-card flex items-start gap-3 border-indigo-400/30 bg-indigo-500/5 p-4 text-sm text-[color:var(--color-ink-dim)]">
        <Terminal className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-300" />
        <div>
          Patch generation and apply run through the CLI in M1:{' '}
          <span className="font-mono text-indigo-300">
            qubit migrate plan {activeScan?.targets.join(' ') ?? '<path>'}
          </span>
          . The interactive approve/apply workflow via the API lands in M2.
        </div>
      </div>

      {!activeScanId && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link to="/scans" className="text-indigo-300 hover:text-indigo-200">
            Run a scan
          </Link>{' '}
          to find migration candidates.
        </div>
      )}

      {isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load candidates: {error instanceof Error ? error.message : 'unknown error'}.
        </div>
      )}

      {isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading candidates…
        </div>
      )}

      {data && (
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-[color:var(--color-ink-dim)]">
              <thead className="border-b border-[color:var(--glass-border)] bg-black/10 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Asset</th>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Current</th>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Recommended</th>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[color:var(--glass-border)]">
                {candidates.map((a) => (
                  <tr key={a.id} className="transition-colors hover:bg-black/10">
                    <td className="px-6 py-4 font-mono text-xs text-[color:var(--color-ink)]">
                      {locOf(a)}
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex rounded border border-rose-500/20 bg-rose-500/10 px-2 py-1 text-xs text-[color:var(--color-danger)]">
                        {a.algorithm}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center gap-1 rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-xs text-[color:var(--color-safe)]">
                        <ArrowRight className="h-3 w-3" /> {recommend(a)}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 overflow-hidden rounded-full border border-[color:var(--glass-border)] bg-black/40">
                          <div
                            className="h-full bg-gradient-to-r from-amber-500 to-rose-500"
                            style={{ width: `${Math.round((a.risk?.score ?? 0) * 100)}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums">
                          {(a.risk?.score ?? 0).toFixed(2)}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
                {candidates.length === 0 && (
                  <tr>
                    <td
                      colSpan={4}
                      className="px-6 py-10 text-center text-[color:var(--color-ink-faint)]"
                    >
                      No vulnerable assets — nothing to migrate. 🎉
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </AnimatedPage>
  );
}
