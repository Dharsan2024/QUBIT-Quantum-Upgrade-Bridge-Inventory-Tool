import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import Plot from 'react-plotly.js';
import { Shield, TrendingUp, AlertTriangle, ShieldCheck, RefreshCw } from 'lucide-react';
import { AnimatedPage } from '../components/AnimatedPage';
import { fetchRiskSummary } from '../api/client';
import { useActiveScan } from '../hooks/useActiveScan';

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

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// Bucket risk scores into 10 bins of width 0.1 -> [count per bin].
function histogram(xs: number[]): { edges: number[]; counts: number[] } {
  const counts = new Array(10).fill(0);
  for (const x of xs) {
    const bin = Math.min(9, Math.max(0, Math.floor(x * 10)));
    counts[bin] += 1;
  }
  const edges = Array.from({ length: 10 }, (_, i) => i / 10 + 0.05);
  return { edges, counts };
}

export function Risk() {
  const { activeScanId, activeScan } = useActiveScan();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['risk-summary', activeScanId],
    queryFn: () => fetchRiskSummary(activeScanId as string),
    enabled: !!activeScanId,
  });

  const total = data?.total_assets ?? 0;
  const vulnerable = data
    ? Object.values(data.by_algorithm).reduce((n, a) => n + a.vulnerable, 0)
    : 0;
  const vulnPct = total ? Math.round((vulnerable / total) * 100) : 0;
  const med = data ? median(data.risk_scores) : 0;
  const { edges, counts } = histogram(data?.risk_scores ?? []);

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Risk Posture</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            {activeScan
              ? `HNDL risk assessment · scan #${activeScan.seq}`
              : 'Overall cryptographic risk assessment'}
          </p>
        </div>
      </header>

      {!activeScanId && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link to="/scans" className="text-indigo-300 hover:text-indigo-200">
            Run a scan
          </Link>{' '}
          to compute risk.
        </div>
      )}

      {isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load risk summary: {error instanceof Error ? error.message : 'unknown error'}.
        </div>
      )}

      {isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading risk summary…
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Kpi
              label="Total Assets"
              value={total}
              icon={<Shield className="h-5 w-5 text-indigo-200" />}
              accent="bg-indigo-500/20 border border-indigo-400/30"
            />
            <Kpi
              label="Quantum Vulnerable"
              value={`${vulnPct}%`}
              icon={<AlertTriangle className="h-5 w-5 text-rose-200" />}
              accent="bg-rose-500/20 border border-rose-400/30"
            />
            <Kpi
              label="Median Risk Score"
              value={med.toFixed(2)}
              icon={<TrendingUp className="h-5 w-5 text-amber-200" />}
              accent="bg-amber-500/20 border border-amber-400/30"
            />
            <Kpi
              label="Safe Assets"
              value={`${100 - vulnPct}%`}
              icon={<ShieldCheck className="h-5 w-5 text-emerald-200" />}
              accent="bg-emerald-500/20 border border-emerald-400/30"
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="glass-card flex flex-col p-4">
              <h3 className="mb-4 text-sm font-medium uppercase tracking-wide text-[color:var(--color-ink-dim)]">
                Risk Score Distribution
              </h3>
              <div className="h-72 w-full rounded-lg">
                <Plot
                  data={[
                    {
                      x: edges,
                      y: counts,
                      type: 'bar',
                      marker: { color: '#6366f1' },
                      hovertemplate: 'score ~%{x:.1f}: %{y} assets<extra></extra>',
                    },
                  ]}
                  layout={{
                    autosize: true,
                    margin: { l: 40, r: 20, t: 10, b: 40 },
                    paper_bgcolor: 'transparent',
                    plot_bgcolor: 'transparent',
                    font: { color: '#9aa3b8' },
                    bargap: 0.05,
                    xaxis: {
                      title: 'Risk Score (HNDL)',
                      gridcolor: 'rgba(255,255,255,0.05)',
                      range: [0, 1],
                    },
                    yaxis: { title: 'Asset Count', gridcolor: 'rgba(255,255,255,0.05)' },
                  }}
                  useResizeHandler
                  style={{ width: '100%', height: '100%' }}
                  config={{ displayModeBar: false }}
                />
              </div>
            </div>

            <div className="glass-card flex flex-col p-4">
              <h3 className="mb-4 text-sm font-medium uppercase tracking-wide text-[color:var(--color-ink-dim)]">
                Highest-Risk Assets
              </h3>
              <div className="flex flex-col gap-2">
                {data.top_10_risk.length === 0 && (
                  <div className="py-8 text-center text-sm text-[color:var(--color-ink-faint)]">
                    No scored assets.
                  </div>
                )}
                {data.top_10_risk.map((a, i) => (
                  <div
                    key={a.asset_id}
                    className="flex items-center gap-3 rounded-lg border border-white/5 px-3 py-2"
                  >
                    <span className="w-5 text-xs text-[color:var(--color-ink-faint)]">{i + 1}</span>
                    <span className="flex-1 font-mono text-sm">{a.algorithm}</span>
                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-white/10">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${Math.round(a.risk_score * 100)}%`,
                          background:
                            a.risk_score >= 0.66
                              ? 'var(--color-danger)'
                              : a.risk_score >= 0.33
                                ? 'var(--color-warn)'
                                : 'var(--color-safe)',
                        }}
                      />
                    </div>
                    <span className="w-10 text-right font-mono text-xs tabular-nums">
                      {a.risk_score.toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </AnimatedPage>
  );
}
