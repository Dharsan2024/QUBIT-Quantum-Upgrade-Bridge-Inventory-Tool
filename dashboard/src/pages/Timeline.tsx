import { AnimatedPage } from '../components/AnimatedPage';
import Plot from 'react-plotly.js';

// MOCK data from qubit_risk simulator
const MOCK_CDF = {
  years: Array.from({ length: 35 }, (_, i) => 2026 + i),
  cdf: [
    0.001, 0.002, 0.005, 0.01, 0.02, 0.04, 0.07, 0.12, 0.18, 0.27, 
    0.38, 0.50, 0.62, 0.73, 0.82, 0.88, 0.93, 0.96, 0.98, 0.99,
    0.995, 0.998, 0.999, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    1.0, 1.0, 1.0, 1.0, 1.0
  ]
};

export function Timeline() {
  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">CRQC Timeline</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">Monte Carlo simulation of Cryptographically Relevant Quantum Computer arrival (Surface Code resource model).</p>
        </div>
      </header>

      <div className="glass-card flex flex-col p-4">
        <div className="w-full h-[500px] rounded-lg">
          <Plot
            data={[
              {
                x: MOCK_CDF.years,
                y: MOCK_CDF.cdf,
                type: 'scatter',
                mode: 'lines',
                line: { color: '#6366f1', width: 3 },
                name: 'P(CRQC ≤ year)',
                fill: 'tozeroy',
                fillcolor: 'rgba(99, 102, 241, 0.1)',
              },
              // Dummy Mosca overlay for demonstration
              {
                x: [2028, 2028, 2038, 2038],
                y: [0, 1, 1, 0],
                fill: 'toself',
                fillcolor: 'rgba(244, 63, 94, 0.2)', // rose-500
                line: { color: 'transparent' },
                name: 'Asset Lifecycle (Mosca)',
                hoverinfo: 'skip'
              }
            ]}
            layout={{
              autosize: true,
              margin: { l: 50, r: 20, t: 30, b: 50 },
              paper_bgcolor: 'transparent',
              plot_bgcolor: 'transparent',
              font: { color: '#9aa3b8' },
              xaxis: { 
                title: 'Year', 
                gridcolor: 'rgba(255,255,255,0.05)',
                dtick: 5
              },
              yaxis: { 
                title: 'Probability', 
                gridcolor: 'rgba(255,255,255,0.05)',
                tickformat: ',.0%'
              },
              showlegend: true,
              legend: {
                x: 0.02,
                y: 0.98,
                bgcolor: 'rgba(0, 0, 0, 0.4)',
                bordercolor: 'rgba(255,255,255,0.1)',
                borderwidth: 1
              }
            }}
            useResizeHandler={true}
            style={{ width: '100%', height: '100%' }}
            config={{ 
              displayModeBar: true,
              displaylogo: false,
              modeBarButtonsToRemove: ['lasso2d', 'select2d']
            }}
          />
        </div>
      </div>
    </AnimatedPage>
  );
}
