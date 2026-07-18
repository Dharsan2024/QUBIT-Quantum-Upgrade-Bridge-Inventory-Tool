import { AnimatedPage } from '../components/AnimatedPage';
import { Download, Check, AlertCircle, Terminal, FileJson } from 'lucide-react';
import { useLiquidGlass } from '../hooks/useLiquidGlass';

export function Cbom() {
  const glassRef = useLiquidGlass({ scale: -100 });
  const glassRef2 = useLiquidGlass({ scale: -90 });

  return (
    <AnimatedPage className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white">CBOM Export</h1>
        <p className="text-slate-400 mt-1">Export your cryptographic inventory as a CycloneDX v1.7 Software Bill of Materials.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div ref={glassRef} className="liquid-panel rounded-xl p-8 ">
          <div className="relative z-10 space-y-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-indigo-500/20 rounded-xl text-indigo-400 border border-indigo-500/30">
                <FileJson className="w-8 h-8" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">CycloneDX 1.7 JSON</h3>
                <p className="text-sm text-slate-400">Includes `cryptoprimitive` properties.</p>
              </div>
            </div>

            <div className="flex gap-4">
              <button className="flex-1 flex items-center justify-center gap-2 bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2.5 rounded-lg font-medium transition-colors shadow-lg shadow-indigo-500/20">
                <Download className="w-4 h-4" /> Download JSON
              </button>
              <button className="flex-1 flex items-center justify-center gap-2 border border-slate-700 hover:bg-slate-800 text-slate-300 px-4 py-2.5 rounded-lg font-medium transition-colors">
                <Check className="w-4 h-4 text-emerald-400" /> Validate Schema
              </button>
            </div>
          </div>
        </div>

        <div ref={glassRef2} className="liquid-panel rounded-xl p-8 ">
          <div className="relative z-10 space-y-4">
            <h3 className="font-medium text-slate-300 flex items-center gap-2">
              <Terminal className="w-5 h-5 text-slate-400" /> CLI Export Equivalent
            </h3>
            <div className="p-4 bg-slate-950/80 rounded-lg border border-slate-800/80 font-mono text-sm text-indigo-300 overflow-x-auto">
              qubit cbom export demo-lab --format json
            </div>
            <div className="flex items-start gap-3 p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg text-sm text-amber-200/80 mt-6">
              <AlertCircle className="w-5 h-5 text-amber-500 flex-shrink-0" />
              <p>The interactive JSON tree viewer is slated for the M3 release. For now, use the downloaded file in your preferred editor.</p>
            </div>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
