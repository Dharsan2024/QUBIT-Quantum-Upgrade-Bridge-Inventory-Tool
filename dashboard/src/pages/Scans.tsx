import { useState } from 'react';
import { useNavigate } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { Activity, CheckCircle2, XCircle, FileCode, Plus, Loader2, Trash2 } from 'lucide-react';
import { createScan, deleteScan, fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import type { ScanSummary } from '../api/types';

function StatusBadge({ status }: { status: string }) {
  if (status === 'succeeded')
    return (
      <span className="flex items-center gap-1.5 text-[color:var(--color-safe)]">
        <CheckCircle2 className="h-4 w-4" /> Succeeded
      </span>
    );
  if (status === 'failed')
    return (
      <span className="flex items-center gap-1.5 text-[color:var(--color-danger)]">
        <XCircle className="h-4 w-4" /> Failed
      </span>
    );
  return (
    <span className="flex items-center gap-1.5 text-[color:var(--color-accent)]">
      <Loader2 className="h-4 w-4 animate-spin" /> {status}
    </span>
  );
}

function timeAgo(iso: string | null): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  const mins = Math.round((Date.now() - then) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

export function Scans() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const setScanId = useUiStore((s) => s.setScanId);
  const setProjectId = useUiStore((s) => s.setProjectId);
  const [target, setTarget] = useState('demo-lab');

  const {
    data: scans,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    // Poll while any scan is still running so the table updates live.
    refetchInterval: (q) =>
      (q.state.data as ScanSummary[] | undefined)?.some(
        (s) => s.status === 'running' || s.status === 'queued',
      )
        ? 2000
        : false,
  });

  const newScan = useMutation({
    mutationFn: (paths: string[]) => createScan(`scan-${Date.now()}`, paths),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });

  const removeScan = useMutation({
    mutationFn: (id: string) => deleteScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });

  const openScan = (scan: ScanSummary) => {
    setScanId(scan.id);
    setProjectId(scan.project_id);
    navigate('/inventory');
  };

  const running = (scans ?? []).filter((s) => s.status === 'running' || s.status === 'queued');

  return (
    <AnimatedPage className="mx-auto flex max-w-7xl flex-col gap-5 py-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scans &amp; Jobs</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            Run a scan over a path; assets and risk are computed and stored in the registry.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="path or repo to scan"
            className="glass-input w-56 text-sm"
          />
          <button
            onClick={() => newScan.mutate([target])}
            disabled={newScan.isPending || !target.trim()}
            className="glass-input flex items-center gap-2 border-indigo-400/40 text-sm font-medium hover:border-indigo-400/70 disabled:opacity-50"
          >
            {newScan.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Plus className="h-4 w-4" />
            )}
            New Scan
          </button>
        </div>
      </header>

      {newScan.isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-3 text-sm text-rose-200">
          Scan failed: {newScan.error instanceof Error ? newScan.error.message : 'unknown error'}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-1">
          <div className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <Activity className="h-5 w-5 text-[color:var(--color-accent)]" />
            Live Jobs
          </div>
          {running.length === 0 && (
            <div className="glass-card p-4 text-sm text-[color:var(--color-ink-faint)]">
              No jobs running.
            </div>
          )}
          {running.map((job) => (
            <div key={job.id} className="glass-card p-4">
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className="font-medium">Scan #{job.seq}</span>
                <Loader2 className="h-4 w-4 animate-spin text-[color:var(--color-accent)]" />
              </div>
              <div className="truncate text-xs text-[color:var(--color-ink-faint)]">
                {job.targets.join(', ')}
              </div>
            </div>
          ))}
        </div>

        <div className="space-y-4 lg:col-span-2">
          <div className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <FileCode className="h-5 w-5 text-[color:var(--color-ink-dim)]" />
            Scan History
          </div>

          {isError && (
            <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
              Could not load scans: {error instanceof Error ? error.message : 'unknown error'}.
              <span className="text-[color:var(--color-ink-faint)]"> Is the API running on :8787?</span>
            </div>
          )}

          <div className="glass-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-[color:var(--color-ink-dim)]">
                <thead className="border-b border-[color:var(--glass-border)] bg-black/10 text-xs uppercase tracking-wide">
                  <tr>
                    <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Scan</th>
                    <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Target</th>
                    <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Date</th>
                    <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Assets</th>
                    <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Status</th>
                    <th className="px-6 py-4 text-right font-medium text-[color:var(--color-ink)]">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[color:var(--glass-border)]">
                  {(scans ?? []).map((scan) => (
                    <tr key={scan.id} className="transition-colors hover:bg-black/10">
                      <td className="px-6 py-4 font-mono text-sm text-[color:var(--color-ink)]">
                        #{scan.seq}{' '}
                        <span className="text-[color:var(--color-ink-faint)]">
                          {scan.id.slice(0, 8)}
                        </span>
                      </td>
                      <td className="px-6 py-4 font-mono text-xs">{scan.targets.join(', ')}</td>
                      <td className="px-6 py-4">{timeAgo(scan.created_at)}</td>
                      <td className="px-6 py-4 font-medium text-[color:var(--color-ink)]">
                        {scan.stats?.assets ?? '—'}
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={() => openScan(scan)}
                          disabled={scan.status !== 'succeeded'}
                          className="mr-3 font-medium text-[color:var(--color-accent)] transition-colors hover:text-[color:var(--color-accent-2)] disabled:opacity-40"
                        >
                          Open
                        </button>
                        <button
                          onClick={() => removeScan.mutate(scan.id)}
                          className="font-medium text-[color:var(--color-danger)] transition-colors hover:text-rose-400"
                          title="Delete scan"
                        >
                          <Trash2 className="inline h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                  {isLoading && (
                    <tr>
                      <td colSpan={6} className="px-6 py-10 text-center">
                        <Loader2 className="inline h-4 w-4 animate-spin" /> Loading scans…
                      </td>
                    </tr>
                  )}
                  {!isLoading && (scans ?? []).length === 0 && (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-6 py-10 text-center text-[color:var(--color-ink-faint)]"
                      >
                        No scans yet. Run one above.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
