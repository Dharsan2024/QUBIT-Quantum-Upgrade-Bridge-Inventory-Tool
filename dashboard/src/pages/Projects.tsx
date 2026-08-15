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
      <header className="flex items-end justify-between">
        <div>
          <h1>Projects</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            Every scanned codebase and configuration tracked by this installation.
          </p>
        </div>
        <button onClick={() => navigate('/scans')} className="hud-btn">
          <Plus className="h-3.5 w-3.5" />
          New scan
        </button>
      </header>

      {projectsQ.isError && (
        <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)]">
          Could not load projects:{' '}
          {projectsQ.error instanceof Error ? projectsQ.error.message : 'unknown error'}.
          <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
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
            className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]"
          >
            Scans
          </button>{' '}
          page.
        </div>
      )}

      <div className="stagger grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {projects.map((project) => {
          const scans = scansByProject.get(project.id) ?? [];
          const latest = scans.find((s) => s.status === 'succeeded') ?? scans[0];
          const assets = latest?.stats?.assets ?? 0;
          return (
            <div key={project.id} className="group glass-card flex flex-col p-6">
              <div className="mb-6 flex items-start gap-3">
                <div className="flex h-11 w-11 flex-none items-center justify-center rounded-[3px] border border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent)]/10 text-[color:var(--color-accent)] transition-all group-hover:bg-[color:var(--color-accent)]/20 group-hover:shadow-[0_0_14px_rgba(56,224,255,0.35)]">
                  <FolderGit2 className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <h3 className="truncate text-[color:var(--color-accent-soft)]">{project.name}</h3>
                  <p className="metric-label mt-1">{project.id.slice(0, 8)}</p>
                </div>
              </div>

              <div className="mb-6 grid grid-cols-2 gap-3">
                <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/40 p-3">
                  <div className="metric-label mb-1.5 flex items-center gap-2">
                    <Activity className="h-3.5 w-3.5" /> Assets
                  </div>
                  <div className="metric text-[1.6rem] text-[color:var(--color-accent)]">{assets}</div>
                </div>
                <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/40 p-3">
                  <div className="metric-label mb-1.5 flex items-center gap-2">
                    <FileScan className="h-3.5 w-3.5" /> Scans
                  </div>
                  <div className="metric text-[1.6rem] text-[color:var(--color-accent-2)]">
                    {scans.length}
                  </div>
                </div>
              </div>

              <div className="mt-auto flex items-center justify-between gap-3">
                <span className="metric-label">
                  {latest ? new Date(latest.created_at).toLocaleDateString() : 'never scanned'}
                </span>
                <button
                  onClick={() => openLatest(project.id)}
                  disabled={!latest}
                  className="label-caps text-[color:var(--color-accent)] transition-colors hover:text-[color:var(--color-accent-soft)] disabled:opacity-40"
                >
                  Open inventory &rarr;
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </AnimatedPage>
  );
}
