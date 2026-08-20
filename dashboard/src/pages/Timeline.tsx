import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Plot from 'react-plotly.js';
import { RefreshCw } from 'lucide-react';
import { AnimatedPage } from '../components/AnimatedPage';
import { fetchProjectsOverview, fetchTimeline } from '../api/client';
import { ProjectScopeBar } from '../components/ProjectScopeBar';
import { useUiStore } from '../stores/ui';

// Shor-vulnerable public-key algorithms the registry can model a CRQC arrival curve for.
const ALGORITHMS = ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDH-P256'];

function Stat({
  label,
  value,
  unit,
  color = 'var(--color-accent-soft)',
}: {
  label: string;
  value: string | number;
  unit?: string;
  color?: string;
}) {
  return (
    <div className="glass-card flex flex-col justify-between gap-3 p-5">
      <div className="metric-label">{label}</div>
      <div className="flex items-end gap-2">
        <span className="metric" style={{ color }}>
          {value}
        </span>
        {unit && (
          <span className="pb-1 font-mono text-xs text-[color:var(--color-ink-faint)]">{unit}</span>
        )}
      </div>
    </div>
  );
}

export function Timeline() {
  const [algorithm, setAlgorithm] = useState('RSA-2048');
  const [blend, setBlend] = useState(false);
  const [weight, setWeight] = useState(0.5);
  const projectId = useUiStore((s) => s.projectId);

  // This page is a Monte-Carlo simulator, not a view of an inventory: the curve is a property of
  // the algorithm and the hardware model, not of your code. So it is deliberately NOT gated behind
  // choosing a project the way Inventory, Risk, CNSA 2.0 and the Migration Hub are — gating it
  // would block a page that works perfectly well on its own.
  //
  // What the project DOES decide is which algorithm is worth opening on. Landing on RSA-2048 for a
  // project whose actual exposure is RSA-1024 makes the page decorative.
  const overviewQ = useQuery({
    queryKey: ['projects-overview'],
    queryFn: fetchProjectsOverview,
    enabled: !!projectId,
  });
  const project = overviewQ.data?.find((p) => p.id === projectId);
  // Only Shor-broken public-key algorithms have a modelled arrival curve, so the project's most
  // common exposure is used only when it is one this page can actually chart.
  const projectAlgorithm = project?.top_algorithms.find((a) => ALGORITHMS.includes(a));
  // Seed once per project, then leave the dropdown alone — re-applying it would fight the user
  // every time the overview query refetched.
  const seededFor = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!projectId || !projectAlgorithm) return;
    if (seededFor.current === projectId) return;
    seededFor.current = projectId;
    setAlgorithm(projectAlgorithm);
  }, [projectId, projectAlgorithm]);

  // Hardware-only Monte-Carlo curve (always shown as the physics baseline).
  const hwQuery = useQuery({
    queryKey: ['timeline', algorithm],
    queryFn: () => fetchTimeline(algorithm),
    staleTime: 5 * 60 * 1000,
  });
  // Survey-blended curve (only when the toggle is on); weight is the hardware share w.
  const blendQuery = useQuery({
    queryKey: ['timeline-blend', algorithm, weight],
    queryFn: () => fetchTimeline(algorithm, { blend: true, weight }),
    enabled: blend,
    staleTime: 5 * 60 * 1000,
  });

  const data = blend ? (blendQuery.data ?? hwQuery.data) : hwQuery.data;
  const isLoading = hwQuery.isLoading || (blend && blendQuery.isLoading);
  const isFetching = hwQuery.isFetching || blendQuery.isFetching;
  const isError = hwQuery.isError || blendQuery.isError;
  const error = hwQuery.error ?? blendQuery.error;

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1>CRQC Timeline</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            Monte-Carlo simulation of Cryptographically Relevant Quantum Computer arrival
            (surface-code resource model{blend ? ', blended with the GRI-2025 expert survey' : ''}).
          </p>
          {projectAlgorithm && (
            <p className="metric-label mt-1.5 normal-case tracking-normal">
              Opened on {projectAlgorithm} — this project&apos;s most common Shor-breakable
              algorithm.
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {isFetching && (
            <RefreshCw className="h-4 w-4 animate-spin text-[color:var(--color-ink-faint)]" />
          )}
          <label className="flex cursor-pointer items-center gap-2 text-sm text-[color:var(--color-ink-dim)]">
            <input
              type="checkbox"
              checked={blend}
              onChange={(e) => setBlend(e.target.checked)}
              className="accent-indigo-500"
            />
            Blend survey
          </label>
          {blend && (
            <label className="flex items-center gap-2 text-xs text-[color:var(--color-ink-faint)]">
              w={weight.toFixed(2)}
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={weight}
                onChange={(e) => setWeight(Number(e.target.value))}
                className="accent-indigo-500"
                title="Hardware share w in F = w·F_hw + (1−w)·F_survey"
              />
            </label>
          )}
          <select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
            className="glass-input text-sm"
          >
            {ALGORITHMS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>
      </header>

      <ProjectScopeBar />

      {data && (
        <div className="stagger grid grid-cols-2 gap-5 md:grid-cols-4">
          <Stat
            label="Earliest (P05)"
            value={data.p05_year}
            unit="year"
            color="var(--color-accent-2)"
          />
          <Stat label="Median (P50)" value={data.median_year} unit="year" />
          <Stat label="Latest (P95)" value={data.p95_year} unit="year" color="var(--color-accent-2)" />
          <Stat
            label={blend ? 'Survey weight' : 'Simulation trials'}
            value={blend ? (1 - weight).toFixed(2) : data.n_trials.toLocaleString()}
            unit={blend ? '1 − w' : 'iterations'}
          />
        </div>
      )}

      {isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load timeline: {error instanceof Error ? error.message : 'unknown error'}.
          <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
        </div>
      )}

      <div className="glass-card flex flex-col p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2>Monte-Carlo probability curve</h2>
            <p className="metric-label mt-1 normal-case tracking-normal">
              Likelihood of CRQC arrival by year
            </p>
          </div>
          <span className="chip chip-danger">Mosca: X + Y &gt; Z ⇒ already exposed</span>
        </div>
        <div className="h-[520px] w-full">
          {isLoading && (
            <div className="flex h-full items-center justify-center gap-3 text-[color:var(--color-ink-dim)]">
              <RefreshCw className="h-4 w-4 animate-spin" /> Running Monte-Carlo simulation…
            </div>
          )}
          {data && (
            <Plot
              data={[
                {
                  x: data.years,
                  y: data.cdf,
                  type: 'scatter',
                  mode: 'lines',
                  line: { color: '#38e0ff', width: 3, shape: 'spline' },
                  name: blend
                    ? `Blended (w=${weight.toFixed(2)}) · ${data.algorithm}`
                    : `P(CRQC ≤ year) · ${data.algorithm}`,
                  fill: 'tozeroy',
                  fillcolor: 'rgba(56, 224, 255, 0.13)',
                  hovertemplate: '%{x}: %{y:.1%}<extra></extra>',
                },
                // overlay the pure-hardware baseline for contrast when blending
                ...(blend && hwQuery.data
                  ? [
                      {
                        x: hwQuery.data.years,
                        y: hwQuery.data.cdf,
                        type: 'scatter' as const,
                        mode: 'lines' as const,
                        line: { color: '#859397', width: 2, dash: 'dot' as const },
                        name: 'Hardware only',
                        hovertemplate: '%{x}: %{y:.1%}<extra></extra>',
                      },
                    ]
                  : []),
              ]}
              layout={{
                autosize: true,
                margin: { l: 60, r: 20, t: 24, b: 52 },
                paper_bgcolor: 'transparent',
                plot_bgcolor: 'transparent',
                font: { color: '#859397', family: 'JetBrains Mono, monospace', size: 11 },
                xaxis: {
                  title: 'Year',
                  gridcolor: 'rgba(56,224,255,0.07)',
                  zerolinecolor: 'rgba(56,224,255,0.15)',
                  dtick: 10,
                },
                yaxis: {
                  title: 'Probability',
                  gridcolor: 'rgba(56,224,255,0.07)',
                  zerolinecolor: 'rgba(56,224,255,0.15)',
                  tickformat: ',.0%',
                  // Headroom above 100% so the P05/P50/P95 callouts sit above the curve
                  // instead of being clipped at the plot edge.
                  range: [0, 1.16],
                },
                shapes: [
                  // HNDL exposure window: everything harvested before the earliest plausible CRQC
                  // is still at risk, so the region left of P05 is shaded as the danger zone.
                  {
                    type: 'rect',
                    x0: data.years[0],
                    x1: data.p05_year,
                    y0: 0,
                    y1: 1,
                    fillcolor: 'rgba(255,143,133,0.09)',
                    line: { color: 'rgba(255,143,133,0.45)', width: 1, dash: 'dot' },
                    layer: 'below',
                  },
                  ...[data.p05_year, data.median_year, data.p95_year].map((yr, i) => ({
                    type: 'line' as const,
                    x0: yr,
                    x1: yr,
                    y0: 0,
                    y1: 1.02,
                    line: {
                      color: i === 1 ? '#38e0ff' : '#b9aaff',
                      width: i === 1 ? 2 : 1.5,
                      dash: i === 1 ? ('solid' as const) : ('dash' as const),
                    },
                  })),
                ],
                annotations: [
                  { x: data.p05_year, y: 1.06, text: `P05 (${data.p05_year})`, showarrow: false, font: { size: 11, color: '#b9aaff' }, bgcolor: 'rgba(5,7,12,0.8)', bordercolor: 'rgba(185,170,255,0.5)', borderpad: 3 },
                  { x: data.median_year, y: 1.13, text: `P50 (${data.median_year})`, showarrow: false, font: { size: 11, color: '#38e0ff' }, bgcolor: 'rgba(5,7,12,0.8)', bordercolor: 'rgba(56,224,255,0.6)', borderpad: 3 },
                  { x: data.p95_year, y: 1.06, text: `P95 (${data.p95_year})`, showarrow: false, font: { size: 11, color: '#b9aaff' }, bgcolor: 'rgba(5,7,12,0.8)', bordercolor: 'rgba(185,170,255,0.5)', borderpad: 3 },
                  {
                    x: (data.years[0] + data.p05_year) / 2,
                    y: 0.06,
                    text: 'HNDL EXPOSURE WINDOW',
                    showarrow: false,
                    font: { size: 9, color: '#ff8f85' },
                    bgcolor: 'rgba(5,7,12,0.85)',
                    bordercolor: 'rgba(255,143,133,0.5)',
                    borderpad: 3,
                  },
                ],
                showlegend: true,
                legend: {
                  // Bottom-right: the curve occupies the top-left→top-right sweep, and the
                  // top-left corner is where the P05/P50 callouts sit.
                  x: 0.985,
                  y: 0.04,
                  xanchor: 'right',
                  yanchor: 'bottom',
                  bgcolor: 'rgba(5,7,12,0.8)',
                  bordercolor: 'rgba(56,224,255,0.3)',
                  borderwidth: 1,
                  font: { color: '#bbc9cd' },
                },
              }}
              useResizeHandler
              style={{ width: '100%', height: '100%' }}
              config={{
                displayModeBar: true,
                displaylogo: false,
                modeBarButtonsToRemove: ['lasso2d', 'select2d'],
              }}
            />
          )}
        </div>
      </div>
    </AnimatedPage>
  );
}
