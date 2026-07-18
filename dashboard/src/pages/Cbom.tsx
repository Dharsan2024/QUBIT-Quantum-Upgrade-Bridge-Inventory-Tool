import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { Download, Terminal, FileJson, RefreshCw } from 'lucide-react';
import { fetchCbom } from '../api/client';
import { useActiveScan } from '../hooks/useActiveScan';

export function Cbom() {
  const { activeScanId, activeScan } = useActiveScan();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['cbom', activeScanId],
    queryFn: () => fetchCbom(activeScanId as string),
    enabled: !!activeScanId,
  });

  const components = Array.isArray((data as { components?: unknown[] })?.components)
    ? ((data as { components: unknown[] }).components as unknown[])
    : [];
  const specVersion = (data as { specVersion?: string })?.specVersion ?? '1.7';
  const pretty = data ? JSON.stringify(data, null, 2) : '';

  const download = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom-scan-${activeScan?.seq ?? activeScanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AnimatedPage className="mx-auto flex max-w-7xl flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">CBOM Export</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            {activeScan
              ? `CycloneDX ${specVersion} SBOM · scan #${activeScan.seq}`
              : 'Export your cryptographic inventory as a CycloneDX v1.7 SBOM.'}
          </p>
        </div>
      </header>

      {!activeScanId && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link to="/scans" className="text-indigo-300 hover:text-indigo-200">
            Run a scan
          </Link>{' '}
          to generate a CBOM.
        </div>
      )}

      {isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load CBOM: {error instanceof Error ? error.message : 'unknown error'}.
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="glass-card p-8">
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-indigo-500/20 bg-indigo-500/10 text-indigo-400">
                <FileJson className="h-8 w-8" />
              </div>
              <div>
                <h3 className="text-xl font-bold tracking-tight">CycloneDX {specVersion} JSON</h3>
                <p className="text-sm text-[color:var(--color-ink-faint)]">
                  {data ? `${components.length} components` : 'includes cryptographic assets'}
                </p>
              </div>
            </div>

            <button
              onClick={download}
              disabled={!data}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-500 px-4 py-2.5 text-sm font-medium text-white shadow-lg shadow-indigo-500/20 transition-colors hover:bg-indigo-400 disabled:opacity-50"
            >
              {isLoading ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              Download JSON
            </button>
          </div>
        </div>

        <div className="glass-card p-8">
          <div className="space-y-4">
            <h3 className="flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-[color:var(--color-ink-dim)]">
              <Terminal className="h-4 w-4" /> CLI Export Equivalent
            </h3>
            <div className="overflow-x-auto rounded-lg border border-[color:var(--glass-border)] bg-black/40 p-4 font-mono text-sm text-indigo-300">
              qubit cbom export {activeScan?.targets.join(' ') ?? '<path>'} --format json
            </div>
          </div>
        </div>
      </div>

      {data && (
        <div className="glass-card overflow-hidden p-0">
          <div className="border-b border-[color:var(--glass-border)] px-5 py-3 text-xs font-medium uppercase tracking-wide text-[color:var(--color-ink-faint)]">
            Preview
          </div>
          <pre className="max-h-[420px] overflow-auto p-5 font-mono text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
            {pretty}
          </pre>
        </div>
      )}
    </AnimatedPage>
  );
}
