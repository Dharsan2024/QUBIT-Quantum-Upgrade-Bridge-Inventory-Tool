import { useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { FolderGit2, Activity, FileScan, Plus, RefreshCw } from 'lucide-react';
import { fetchProjects, fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import type { ScanSummary } from '../api/types';

export function Projects() {
  const navigate = useNavigate();
  const setScanId = useUiStore((s) => s.setScanId);
  const setProjectId = useUiStore((s) => s.setProjectId);

  const projectsQ = useQuery({ queryKey: ['projects'], queryFn: fetchProjects });
  const scansQ = useQuery({ queryKey: ['scans'], queryFn: fetchScans });

  const scansByProject = new Map<string, ScanSummary[]>();
  for (const s of scansQ.data ?? []) {
    const list = scansByProject.get(s.project_id) ?? [];
    list.push(s);
    scansByProject.set(s.project_id, list);
  }

  const openLatest = (projectId: string) => {
    const scans = (scansByProject.get(projectId) ?? []).filter((s) => s.status === 'succeeded');
    const latest = scans[0];
    setProjectId(projectId);
    if (latest) setScanId(latest.id);
    navigate('/inventory');
  };

  const projects = projectsQ.data ?? [];

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            Manage your scanned codebases and configurations.
          </p>
        </div>
        <button
          onClick={() => navigate('/scans')}
          className="glass-input flex items-center gap-2 text-sm font-medium hover:border-indigo-400/60"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </header>

      {projectsQ.isError && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load projects:{' '}
          {projectsQ.error instanceof Error ? projectsQ.error.message : 'unknown error'}.
          <span className="text-[color:var(--color-ink-faint)]"> Is the API running on :8787?</span>
        </div>
      )}

      {projectsQ.isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading projects…
        </div>
      )}

      {projectsQ.data && projects.length === 0 && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No projects yet. Start by running a scan on the{' '}
          <button
            onClick={() => navigate('/scans')}
            className="text-indigo-300 hover:text-indigo-200"
          >
            Scans
          </button>{' '}
          page.
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {projects.map((project) => {
          const scans = scansByProject.get(project.id) ?? [];
          const latest = scans.find((s) => s.status === 'succeeded') ?? scans[0];
          const assets = latest?.stats?.assets ?? 0;
          return (
            <div
              key={project.id}
              className="group glass-card p-6 transition-colors hover:border-indigo-500/30"
            >
              <div className="mb-6 flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-indigo-500/20 bg-indigo-500/10 text-indigo-400 transition-colors group-hover:bg-indigo-500/20">
                    <FolderGit2 className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold tracking-tight">{project.name}</h3>
                    <p className="mt-0.5 font-mono text-xs uppercase tracking-wide text-[color:var(--color-ink-dim)]">
                      {project.id.slice(0, 8)}
                    </p>
                  </div>
                </div>
              </div>

              <div className="mb-6 grid grid-cols-2 gap-3">
                <div className="glass-card bg-black/20 p-3">
                  <div className="mb-1 flex items-center gap-2 text-xs uppercase tracking-wide text-[color:var(--color-ink-faint)]">
                    <Activity className="h-3.5 w-3.5" /> Assets
                  </div>
                  <div className="text-xl font-semibold">{assets}</div>
                </div>
                <div className="glass-card bg-black/20 p-3">
                  <div className="mb-1 flex items-center gap-2 text-xs uppercase tracking-wide text-[color:var(--color-ink-faint)]">
                    <FileScan className="h-3.5 w-3.5" /> Scans
                  </div>
                  <div className="text-xl font-semibold">{scans.length}</div>
                </div>
              </div>

              <div className="mt-auto flex items-center justify-between text-sm">
                <span className="text-xs text-[color:var(--color-ink-faint)]">
                  {latest ? new Date(latest.created_at).toLocaleDateString() : 'never scanned'}
                </span>
                <button
                  onClick={() => openLatest(project.id)}
                  disabled={!latest}
                  className="flex items-center gap-1 text-sm font-medium text-[color:var(--color-accent)] transition-colors hover:text-[color:var(--color-accent-2)] disabled:opacity-40"
                >
                  View Details &rarr;
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </AnimatedPage>
  );
}
