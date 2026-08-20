import { useState } from 'react';
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import Plot from 'react-plotly.js';
import { Kpi } from '../components/Kpi';
import {
  Shield,
  TrendingUp,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { AnimatedPage } from '../components/AnimatedPage';
import { fetchAssetHndl, fetchRiskSummary } from '../api/client';
import { useActiveScan } from '../hooks/useActiveScan';
import { useUiStore } from '../stores/ui';
import { ProjectGrid } from '../components/ProjectGrid';
import { ProjectScopeBar } from '../components/ProjectScopeBar';
import { displayAlgorithm } from '../lib/assetLabels';

function riskColor(score: number): string {
  return score >= 0.66
    ? 'var(--color-danger)'
    : score >= 0.33
      ? 'var(--color-warn)'
      : 'var(--color-safe)';
}

function scoreSourceLabel(source: "closed-form" | "xgb" | undefined): string {
  if (source === "xgb") {
    return "XGBoost (calibrated)";
  }
  if (source === "closed-form") {
    return "Closed-form HNDL";
  }
  return "Unknown";
}

function Factor({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/40 px-2.5 py-1.5">
      <div className="metric-label text-[10px]">{label}</div>
      <div className="font-mono text-sm tabular-nums text-[color:var(--color-accent-soft)]">
        {value}
      </div>
    </div>
  );
}

function RiskRow({
  rank,
  item,
}: {
  rank: number;
  item: { asset_id: string; algorithm: string; risk_score: number };
}) {
  const [open, setOpen] = useState(false);
  const { data, isLoading, isError } = useQuery({
    queryKey: ['hndl', item.asset_id],
    queryFn: () => fetchAssetHndl(item.asset_id),
    enabled: open,
  });

  return (
    <div className="rounded-[3px] border border-[color:var(--edge)]">
      <button
        onClick={() => setOpen((o) => !o)}
        className="data-row flex w-full items-center gap-3 border-b-0 px-3 py-2.5 text-left"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 flex-none text-[color:var(--color-accent)]" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 flex-none text-[color:var(--color-ink-faint)]" />
        )}
        <span className="w-6 font-mono text-xs text-[color:var(--color-accent)]/60">#{rank}</span>
        <span
          className="flex-1 truncate font-mono text-sm text-[color:var(--color-accent-soft)]"
          title={item.algorithm}
        >
          {displayAlgorithm(item.algorithm)}
        </span>
        <SegBar score={item.risk_score} />
        <span
          className="w-10 text-right font-mono text-xs tabular-nums"
          style={{ color: riskColor(item.risk_score) }}
        >
          {item.risk_score.toFixed(2)}
        </span>
      </button>
      {open && (
        <div className="border-t border-[color:var(--edge)] px-3 py-3">
          {isLoading && (
            <div className="flex items-center gap-2 text-xs text-[color:var(--color-ink-dim)]">
              <RefreshCw className="h-3 w-3 animate-spin" /> Computing HNDL factors…
            </div>
          )}
          {isError && (
            <div className="text-xs text-rose-300">Could not load HNDL explanation.</div>
          )}
          {data && data.note && (
            <div className="text-xs text-[color:var(--color-ink-dim)]">{data.note}</div>
          )}
          {data && data.shor && (
            <div className="flex flex-col gap-2">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <Factor label="Exposure" value={data.exposure ?? '—'} />
                <Factor label={`Sensitivity (${data.tier})`} value={data.sensitivity ?? '—'} />
                <Factor label="P(harvest)" value={data.harvest_prob?.toFixed(3) ?? '—'} />
                <Factor label="P(decrypt)" value={data.p_decrypt?.toFixed(3) ?? '—'} />
              </div>
              <div className="text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                HNDL = P(harvest) × P(decrypt-before-obsolete) ={' '}
                <span className="font-mono text-[color:var(--color-ink)]">
                  {data.p_hndl_closed_form?.toFixed(3)}
                </span>{' '}
                (closed-form). Bayesian net:{' '}
                <span className="font-mono text-[color:var(--color-ink)]">
                  {data.p_hndl_bayes_net?.toFixed(3)}
                </span>{' '}
                — agree to {data.bn_closed_form_agreement?.toFixed(3)}. CRQC median{' '}
                {data.crqc_median_year ?? '—'}.
              </div>
              {data.score_source && (
                <div className="text-[11px] uppercase tracking-wide text-[color:var(--color-ink-faint)]">
                  Score source:{" "}
                  <span className="font-mono text-[color:var(--color-ink)]">
                    {scoreSourceLabel(data.score_source)}
                  </span>
                </div>
              )}

              {data.regressor && (
                <div className="mt-1 rounded-lg border border-indigo-400/20 bg-indigo-500/5 p-3">
                  <div className="mb-2 flex items-center justify-between text-xs">
                    <span className="font-medium text-[color:var(--color-ink)]">
                      XGBoost score{' '}
                      <span className="text-[color:var(--color-ink-faint)]">
                        (90% conformal CI)
                      </span>
                    </span>
                    <span className="font-mono tabular-nums">
                      {data.regressor.score.toFixed(3)}{' '}
                      <span className="text-[color:var(--color-ink-faint)]">
                        [{data.regressor.ci_low.toFixed(3)}, {data.regressor.ci_high.toFixed(3)}]
                      </span>
                    </span>
                  </div>
                  <div className="text-[10px] uppercase tracking-wide text-[color:var(--color-ink-faint)]">
                    Top SHAP contributions
                  </div>
                  {data.regressor.shap_top.length > 0 ? (
                    <div className="mt-1 flex flex-col gap-1">
                      {data.regressor.shap_top.slice(0, 6).map((s) => (
                        <div key={s.feature} className="flex items-center gap-2 text-xs">
                          <span className="w-40 truncate font-mono text-[color:var(--color-ink-dim)]">
                            {s.feature}
                          </span>
                          <div className="relative h-1.5 flex-1 rounded-full bg-white/5">
                            <div
                              className="absolute top-0 h-full rounded-full"
                              style={{
                                left: s.contribution >= 0 ? '50%' : undefined,
                                right: s.contribution < 0 ? '50%' : undefined,
                                width: `${Math.min(50, Math.abs(s.contribution) * 300)}%`,
                                background:
                                  s.contribution >= 0
                                    ? 'var(--color-danger)'
                                    : 'var(--color-safe)',
                              }}
                            />
                          </div>
                          <span className="w-14 text-right font-mono tabular-nums text-[color:var(--color-ink-faint)]">
                            {s.contribution >= 0 ? '+' : ''}
                            {s.contribution.toFixed(3)}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="mt-1 text-xs text-[color:var(--color-ink-dim)]">
                      SHAP contributions unavailable for this asset.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Segmented risk readout, matching the inventory table's HUD bar. */
function SegBar({ score }: { score: number }) {
  const filled = Math.max(1, Math.round(score * 10));
  const tone = score >= 0.66 ? 'danger' : score >= 0.33 ? 'mid' : 'safe';
  return (
    <div className="risk-bar w-24 flex-none">
      {Array.from({ length: 10 }, (_, i) => (
        <span key={i} className={`risk-seg ${i < filled ? `risk-seg-on-${tone}` : ''}`} />
      ))}
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
  const projectId = useUiStore((s) => s.projectId);

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

  // Placed below every hook on purpose. React requires the same hooks to run in the same order on
  // every render, so an early return above `useQuery` makes the hook count change the moment a
  // project is chosen — which crashed this page with React error #310 (caught by the browser
  // suite, not by tsc, which cannot see hook order).
  if (!projectId) {
    return (
      <AnimatedPage className="flex flex-col gap-5 py-4">
        <header>
          <h1>Risk Posture</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            HNDL risk is scored per project. Open one to see its distribution, top exposures and
            Mosca margins.
          </p>
        </header>

        <ProjectGrid
          metric="risk"
          title="Risk by project"
          subtitle="Mean HNDL risk score across each project's scored assets."
        />
      </AnimatedPage>
    );
  }

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-end justify-between">
        <div>
          <h1>Risk Posture</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            {activeScan
              ? `HNDL risk assessment · scan #${activeScan.seq}`
              : 'Overall cryptographic risk assessment'}
          </p>
        </div>
      </header>

      <ProjectScopeBar />

      {!activeScanId && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link to="/scans" className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]">
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
          <div className="stagger grid grid-cols-2 gap-5 md:grid-cols-4">
            <Kpi
              label="Total assets"
              value={total}
              icon={<Shield className="h-9 w-9" />}
              color="var(--color-accent)"
            />
            <Kpi
              label="Quantum-vulnerable"
              value={`${vulnPct}%`}
              icon={<AlertTriangle className="h-9 w-9" />}
              color="var(--color-danger)"
            />
            <Kpi
              label="Median risk score"
              value={med.toFixed(2)}
              icon={<TrendingUp className="h-9 w-9" />}
              color="var(--color-warn)"
            />
            <Kpi
              label="Quantum-safe"
              value={`${100 - vulnPct}%`}
              icon={<ShieldCheck className="h-9 w-9" />}
              color="var(--color-safe)"
            />
          </div>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <div className="glass-card flex flex-col p-5">
              <h2 className="mb-4">Risk score distribution</h2>
              <div className="h-80 w-full">
                <Plot
                  data={[
                    {
                      x: edges,
                      y: counts,
                      type: 'bar',
                      // Neon bars, tinted per bucket so the tail reads as the danger zone.
                      marker: {
                        color: edges.map((e) =>
                          e >= 0.66 ? '#ffb4ab' : e >= 0.33 ? '#b9aaff' : '#38e0ff',
                        ),
                        line: { color: 'rgba(56,224,255,0.35)', width: 1 },
                      },
                      hovertemplate: 'score ~%{x:.1f}: %{y} assets<extra></extra>',
                    },
                  ]}
                  layout={{
                    autosize: true,
                    margin: { l: 48, r: 20, t: 10, b: 46 },
                    paper_bgcolor: 'transparent',
                    plot_bgcolor: 'transparent',
                    font: { color: '#859397', family: 'JetBrains Mono, monospace', size: 11 },
                    bargap: 0.08,
                    xaxis: {
                      title: 'HNDL risk score',
                      gridcolor: 'rgba(56,224,255,0.07)',
                      zerolinecolor: 'rgba(56,224,255,0.15)',
                      range: [0, 1],
                    },
                    yaxis: {
                      title: 'Asset count',
                      gridcolor: 'rgba(56,224,255,0.07)',
                      zerolinecolor: 'rgba(56,224,255,0.15)',
                    },
                  }}
                  useResizeHandler
                  style={{ width: '100%', height: '100%' }}
                  config={{ displayModeBar: false }}
                />
              </div>
            </div>

            <div className="glass-card flex flex-col p-5">
              <h2 className="mb-4">Highest-risk assets</h2>
              <div className="flex flex-col gap-2">
                {data.top_10_risk.length === 0 && (
                  <div className="py-8 text-center text-sm text-[color:var(--color-ink-faint)]">
                    No scored assets.
                  </div>
                )}
                {data.top_10_risk.map((a, i) => (
                  <RiskRow key={a.asset_id} rank={i + 1} item={a} />
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </AnimatedPage>
  );
}
