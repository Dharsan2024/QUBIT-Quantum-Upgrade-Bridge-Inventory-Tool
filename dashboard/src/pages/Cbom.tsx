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
    <AnimatedPage className="flex flex-col gap-6 py-5">
      <header className="flex items-end justify-between">
        <div>
          <h1>CBOM Export</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            {activeScan
              ? `CycloneDX ${specVersion} SBOM · scan #${activeScan.seq}`
              : 'Export your cryptographic inventory as a CycloneDX v1.7 SBOM.'}
          </p>
        </div>
      </header>

      {!activeScanId && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link to="/scans" className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]">
            Run a scan
          </Link>{' '}
          to generate a CBOM.
        </div>
      )}

      {isError && (
        <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)]">
          Could not load CBOM: {error instanceof Error ? error.message : 'unknown error'}.
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="glass-card flex flex-col gap-6 p-6">
          <div className="flex items-center gap-4">
            <div className="flex h-14 w-14 flex-none items-center justify-center rounded-[3px] border border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent)]/10 text-[color:var(--color-accent)]">
              <FileJson className="h-7 w-7" />
            </div>
            <div>
              <h3 className="text-[color:var(--color-accent-soft)]">CycloneDX {specVersion} JSON</h3>
              <p className="metric-label mt-1">
                {data ? `${components.length} components` : 'includes cryptographic assets'}
              </p>
            </div>
          </div>

          <button onClick={download} disabled={!data} className="hud-btn w-full py-3">
            {isLoading ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            Download JSON
          </button>
        </div>

        <div className="glass-card flex flex-col gap-4 p-6">
          <h3 className="label-caps flex items-center gap-2 text-[color:var(--color-accent)]/70">
            <Terminal className="h-4 w-4" /> CLI equivalent
          </h3>
          <div className="overflow-x-auto rounded-[3px] border border-[color:var(--edge)] bg-black/50 p-4 font-mono text-sm text-[color:var(--color-accent)]">
            qubit cbom export {activeScan?.targets.join(' ') ?? '<path>'} --format json
          </div>
        </div>
      </div>

      {data && (
        <div className="glass-card overflow-hidden p-0">
          <div className="label-caps border-b border-[color:var(--edge)] px-5 py-3">Preview</div>
          <pre className="max-h-[420px] overflow-auto p-5 font-mono text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
            {pretty}
          </pre>
        </div>
      )}
    </AnimatedPage>
  );
}
