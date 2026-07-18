import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Plot from 'react-plotly.js';
import { RefreshCw } from 'lucide-react';
import { AnimatedPage } from '../components/AnimatedPage';
import { fetchTimeline } from '../api/client';

// Shor-vulnerable public-key algorithms the registry can model a CRQC arrival curve for.
const ALGORITHMS = ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDH-P256'];

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="glass-card px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-[color:var(--color-ink-faint)]">{label}</div>
      <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

export function Timeline() {
  const [algorithm, setAlgorithm] = useState('RSA-2048');

  const { data, isLoading, isError, error, isFetching } = useQuery({
    queryKey: ['timeline', algorithm],
    queryFn: () => fetchTimeline(algorithm),
    staleTime: 5 * 60 * 1000,
  });

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">CRQC Timeline</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            Monte-Carlo simulation of Cryptographically Relevant Quantum Computer arrival
            (surface-code resource model).
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isFetching && (
            <RefreshCw className="h-4 w-4 animate-spin text-[color:var(--color-ink-faint)]" />
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

      {data && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <Stat label="Median (P50)" value={data.median_year} />
          <Stat label="Earliest (P05)" value={data.p05_year} />
          <Stat label="Latest (P95)" value={data.p95_year} />
          <Stat label="Trials" value={data.n_trials.toLocaleString()} />
        </div>
      )}

      {isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load timeline: {error instanceof Error ? error.message : 'unknown error'}.
          <span className="text-[color:var(--color-ink-faint)]"> Is the API running on :8787?</span>
        </div>
      )}

      <div className="glass-card flex flex-col p-4">
        <div className="h-[500px] w-full rounded-lg">
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
                  line: { color: '#6366f1', width: 3 },
                  name: `P(CRQC ≤ year) · ${data.algorithm}`,
                  fill: 'tozeroy',
                  fillcolor: 'rgba(99, 102, 241, 0.12)',
                  hovertemplate: '%{x}: %{y:.1%}<extra></extra>',
                },
              ]}
              layout={{
                autosize: true,
                margin: { l: 55, r: 20, t: 20, b: 50 },
                paper_bgcolor: 'transparent',
                plot_bgcolor: 'transparent',
                font: { color: '#9aa3b8' },
                xaxis: { title: 'Year', gridcolor: 'rgba(255,255,255,0.05)', dtick: 10 },
                yaxis: {
                  title: 'Probability',
                  gridcolor: 'rgba(255,255,255,0.05)',
                  tickformat: ',.0%',
                  range: [0, 1.02],
                },
                shapes: [data.p05_year, data.median_year, data.p95_year].map((yr, i) => ({
                  type: 'line',
                  x0: yr,
                  x1: yr,
                  y0: 0,
                  y1: 1,
                  line: {
                    color: i === 1 ? '#f43f5e' : 'rgba(244,63,94,0.4)',
                    width: i === 1 ? 2 : 1,
                    dash: 'dash',
                  },
                })),
                annotations: [
                  { x: data.p05_year, y: 1.02, text: 'P05', showarrow: false, font: { size: 10 } },
                  { x: data.median_year, y: 1.02, text: 'P50', showarrow: false, font: { size: 10 } },
                  { x: data.p95_year, y: 1.02, text: 'P95', showarrow: false, font: { size: 10 } },
                ],
                showlegend: true,
                legend: {
                  x: 0.02,
                  y: 0.98,
                  bgcolor: 'rgba(0, 0, 0, 0.4)',
                  bordercolor: 'rgba(255,255,255,0.1)',
                  borderwidth: 1,
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
