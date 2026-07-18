import { AnimatedPage } from '../components/AnimatedPage';
import { Shield, TrendingUp, AlertTriangle, ShieldCheck } from 'lucide-react';
import Plot from 'react-plotly.js';
import { useLiquidGlass } from '../hooks/useLiquidGlass';

const MOCK_HISTOGRAM = {
  x: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
  y: [12, 18, 5, 2, 8, 14, 25, 42, 60, 15],
};

export function Risk() {
  const glassRef1 = useLiquidGlass({ scale: -112 });
  const glassRef2 = useLiquidGlass({ scale: -112 });
  const glassRef3 = useLiquidGlass({ scale: -112 });
  const glassRef4 = useLiquidGlass({ scale: -112 });
  const glassRefChart = useLiquidGlass({ scale: -80 });

  return (
    <AnimatedPage className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white">Risk Posture</h1>
        <p className="text-slate-400 mt-1">Overall cryptographic risk assessment across the portfolio.</p>
      </div>

      {/* KPI Tiles */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div ref={glassRef1} className="liquid-panel rounded-xl p-6 ">
          <div className="flex justify-between items-start mb-2">
            <div className="text-slate-400 text-sm font-medium">Total Assets</div>
            <Shield className="w-5 h-5 text-indigo-400 relative z-10" />
          </div>
          <div className="text-3xl font-bold text-slate-100 relative z-10">201</div>
        </div>
        
        <div ref={glassRef2} className="liquid-panel rounded-xl p-6 ">
          <div className="flex justify-between items-start mb-2">
            <div className="text-slate-400 text-sm font-medium">Quantum Vulnerable</div>
            <AlertTriangle className="w-5 h-5 text-rose-400 relative z-10" />
          </div>
          <div className="text-3xl font-bold text-slate-100 relative z-10">18%</div>
        </div>

        <div ref={glassRef3} className="liquid-panel rounded-xl p-6 ">
          <div className="flex justify-between items-start mb-2">
            <div className="text-slate-400 text-sm font-medium">Median Risk Score</div>
            <TrendingUp className="w-5 h-5 text-amber-400 relative z-10" />
          </div>
          <div className="text-3xl font-bold text-slate-100 relative z-10">0.72</div>
        </div>

        <div ref={glassRef4} className="liquid-panel rounded-xl p-6 ">
          <div className="flex justify-between items-start mb-2">
            <div className="text-slate-400 text-sm font-medium">Safe Assets</div>
            <ShieldCheck className="w-5 h-5 text-emerald-400 relative z-10" />
          </div>
          <div className="text-3xl font-bold text-slate-100 relative z-10">82%</div>
        </div>
      </div>

      {/* Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div ref={glassRefChart} className="liquid-panel rounded-xl p-6 ">
          <h3 className="text-lg font-semibold text-slate-200 mb-4 relative z-10">Risk Score Distribution</h3>
          <div className="w-full h-72 rounded-lg overflow-hidden relative z-10">
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
                margin: { l: 40, r: 20, t: 20, b: 40 },
                paper_bgcolor: 'transparent',
                plot_bgcolor: 'transparent',
                font: { color: '#94a3b8' },
                xaxis: { title: 'Risk Score (HNDL)', gridcolor: '#334155' },
                yaxis: { title: 'Asset Count', gridcolor: '#334155' }
              }}
              useResizeHandler={true}
              style={{ width: '100%', height: '100%' }}
              config={{ displayModeBar: false }}
            />
          </div>
        </div>
        
        <div className="liquid-panel rounded-xl p-6 flex items-center justify-center">
          <div className="text-slate-500 text-center">
            <p className="mb-2">Treemap Visualization</p>
            <p className="text-sm">(Slated for M3 release)</p>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
