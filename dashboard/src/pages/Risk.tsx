import { AnimatedPage } from '../components/AnimatedPage';
import { Shield, TrendingUp, AlertTriangle, ShieldCheck } from 'lucide-react';
import Plot from 'react-plotly.js';

const MOCK_HISTOGRAM = {
  x: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
  y: [12, 18, 5, 2, 8, 14, 25, 42, 60, 15],
};

function Kpi({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
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

export function Risk() {
  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Risk Posture</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">Overall cryptographic risk assessment across the portfolio.</p>
        </div>
      </header>

      {/* KPI Tiles */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Kpi
          label="Total Assets"
          value={201}
          icon={<Shield className="h-5 w-5 text-indigo-200" />}
          accent="bg-indigo-500/20 border border-indigo-400/30"
        />
        <Kpi
          label="Quantum Vulnerable"
          value="18%"
          icon={<AlertTriangle className="h-5 w-5 text-rose-200" />}
          accent="bg-rose-500/20 border border-rose-400/30"
        />
        <Kpi
          label="Median Risk Score"
          value={0.72}
          icon={<TrendingUp className="h-5 w-5 text-amber-200" />}
          accent="bg-amber-500/20 border border-amber-400/30"
        />
        <Kpi
          label="Safe Assets"
          value="82%"
          icon={<ShieldCheck className="h-5 w-5 text-emerald-200" />}
          accent="bg-emerald-500/20 border border-emerald-400/30"
        />
      </div>

      {/* Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="glass-card flex flex-col p-4">
          <h3 className="mb-4 text-sm font-medium tracking-wide text-[color:var(--color-ink-dim)]">RISK SCORE DISTRIBUTION</h3>
          <div className="w-full h-72 rounded-lg">
            <Plot
              data={[
                {
                  x: MOCK_HISTOGRAM.x,
                  y: MOCK_HISTOGRAM.y,
                  type: 'bar',
                  marker: { color: '#6366f1' },
                }
              ]}
              layout={{
                autosize: true,
                margin: { l: 40, r: 20, t: 10, b: 40 },
                paper_bgcolor: 'transparent',
                plot_bgcolor: 'transparent',
                font: { color: '#9aa3b8' },
                xaxis: { title: 'Risk Score (HNDL)', gridcolor: 'rgba(255,255,255,0.05)' },
                yaxis: { title: 'Asset Count', gridcolor: 'rgba(255,255,255,0.05)' }
              }}
              useResizeHandler={true}
              style={{ width: '100%', height: '100%' }}
              config={{ displayModeBar: false }}
            />
          </div>
        </div>
        
        <div className="glass-card flex items-center justify-center p-4">
          <div className="text-[color:var(--color-ink-faint)] text-center">
            <p className="mb-2 text-sm uppercase tracking-wide">Treemap Visualization</p>
            <p className="text-xs">(Slated for M3 release)</p>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
