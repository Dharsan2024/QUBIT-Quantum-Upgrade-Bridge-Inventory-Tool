import { AnimatedPage } from '../components/AnimatedPage';
import { Download, Check, AlertCircle, Terminal, FileJson } from 'lucide-react';

export function Cbom() {
  return (
    <AnimatedPage className="flex flex-col gap-5 py-4 max-w-7xl mx-auto">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">CBOM Export</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">Export your cryptographic inventory as a CycloneDX v1.7 Software Bill of Materials.</p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-card p-8">
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <FileJson className="w-8 h-8" />
              </div>
              <div>
                <h3 className="text-xl font-bold tracking-tight">CycloneDX 1.7 JSON</h3>
                <p className="text-sm text-[color:var(--color-ink-faint)]">Includes `cryptoprimitive` properties.</p>
              </div>
            </div>

            <div className="flex gap-4">
              <button className="flex-1 flex items-center justify-center gap-2 bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2.5 rounded-lg font-medium transition-colors shadow-lg shadow-indigo-500/20 text-sm">
                <Download className="w-4 h-4" /> Download JSON
              </button>
              <button className="glass-input flex-1 flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium hover:border-[color:var(--color-ink-dim)]">
                <Check className="w-4 h-4 text-[color:var(--color-safe)]" /> Validate Schema
              </button>
            </div>
          </div>
        </div>

        <div className="glass-card p-8">
          <div className="space-y-4">
            <h3 className="font-medium text-[color:var(--color-ink-dim)] flex items-center gap-2 text-sm uppercase tracking-wide">
              <Terminal className="w-4 h-4" /> CLI Export Equivalent
            </h3>
            <div className="p-4 bg-black/40 rounded-lg border border-[color:var(--glass-border)] font-mono text-sm text-indigo-300 overflow-x-auto">
              qubit cbom export demo-lab --format json
            </div>
            <div className="flex items-start gap-3 p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg text-sm text-amber-200/80 mt-6">
              <AlertCircle className="w-5 h-5 text-[color:var(--color-warn)] flex-shrink-0" />
              <p>The interactive JSON tree viewer is slated for the M3 release. For now, use the downloaded file in your preferred editor.</p>
            </div>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
