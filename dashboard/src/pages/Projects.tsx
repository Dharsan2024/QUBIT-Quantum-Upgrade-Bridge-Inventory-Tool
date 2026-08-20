import { useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { ProjectGrid } from '../components/ProjectGrid';
import {
  Activity,
  ArrowLeft,
  Boxes,
  FileScan,
  FileText,
  GitPullRequestDraft,
  Landmark,
  Plus,
  RefreshCw,
  ShieldAlert,
  Clock,
  Download,
} from 'lucide-react';
import { fetchProjectsOverview, fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';
import { displayAlgorithm } from '../lib/assetLabels';

/**
 * Projects: the grid of everything scanned, and — once you pick one — that project on its own.
 *
 * The detail view is deliberately a hub rather than another table. Every other tab is now scoped to
 * the selected project, so the useful thing to show here is that project's shape (what was scanned,
 * when, how much of it is vulnerable, whether it has a current migration plan) plus the way into
 * each of those tabs, already scoped.
 */

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return '—';
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (!Number.isFinite(mins)) return '—';
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

function ProjectDetail({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const clearProject = useUiStore((s) => s.clearProject);
  const openScan = useUiStore((s) => s.openScan);
  const setScanId = useUiStore((s) => s.setScanId);

  const overviewQ = useQuery({ queryKey: ['projects-overview'], queryFn: fetchProjectsOverview });
  const scansQ = useQuery({ queryKey: ['scans'], queryFn: fetchScans });

  const project = overviewQ.data?.find((p) => p.id === projectId);
  const scans = (scansQ.data ?? []).filter((s) => s.project_id === projectId);

  if (overviewQ.isLoading) {
    return (
      <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading project…
      </div>
    );
  }

  if (!project) {
    // The selected project was deleted, or this is a stale id remembered from a previous session.
    return (
      <div className="glass-card flex flex-col items-center gap-4 p-10 text-center text-sm text-[color:var(--color-ink-dim)]">
        This project no longer exists.
        <button onClick={clearProject} className="hud-btn">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to all projects
        </button>
      </div>
    );
  }

  const safe = project.assets - project.vulnerable;
  const tiles = [
    { label: 'Assets', value: project.assets, icon: Boxes, color: 'var(--color-accent)' },
    {
      label: 'Quantum-vulnerable',
      value: project.vulnerable,
      icon: ShieldAlert,
      color: 'var(--color-danger)',
    },
    { label: 'Not vulnerable', value: safe, icon: Boxes, color: 'var(--color-safe)' },
    { label: 'Scans', value: project.scans, icon: FileScan, color: 'var(--color-accent-2)' },
  ];

  /** Enter a tab already scoped to this project. */
  const go = (path: string) => navigate(path);

  const destinations = [
    { path: '/inventory', label: 'Inventory', icon: Boxes, detail: `${project.assets} assets` },
    {
      path: '/risk',
      label: 'Risk Posture',
      icon: ShieldAlert,
      detail: project.mean_risk == null ? 'not scored' : `mean ${project.mean_risk.toFixed(3)}`,
    },
    { path: '/compliance', label: 'CNSA 2.0', icon: Landmark, detail: 'milestone verdicts' },
    {
      path: '/migrations',
      label: 'Migration Hub',
      icon: GitPullRequestDraft,
      detail: project.plan
        ? `${project.plan.tasks} tasks${project.plan.stale ? ' · outdated' : ''}`
        : 'no plan yet',
    },
    { path: '/timeline', label: 'CRQC Timeline', icon: Clock, detail: 'arrival simulation' },
    { path: '/cbom', label: 'CBOM Export', icon: Download, detail: 'CycloneDX 1.7' },
  ];

  return (
    <div className="flex flex-col gap-6" data-testid="project-detail">
      <div className="glass-card flex flex-wrap items-center gap-x-5 gap-y-3 px-5 py-3">
        <button
          onClick={clearProject}
          className="label-caps flex items-center gap-2 text-[color:var(--color-ink-dim)] transition-colors hover:text-[color:var(--color-accent)]"
          data-testid="leave-project"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> All projects
        </button>
        <span className="h-5 w-px bg-[color:var(--edge)]" />
        <span className="truncate font-medium text-[color:var(--color-accent-soft)]">
          {project.name}
        </span>
        <span className="metric-label ml-auto">
          last scanned {timeAgo(project.latest_scan?.created_at)}
        </span>
      </div>

      <div className="stagger grid grid-cols-2 gap-5 lg:grid-cols-4">
        {tiles.map((t) => {
          const Icon = t.icon;
          return (
            <div key={t.label} className="glass-card flex items-center justify-between gap-3 p-5">
              <div>
                <div className="metric text-[1.9rem] leading-none" style={{ color: t.color }}>
                  {t.value}
                </div>
                <div className="metric-label mt-1.5">{t.label}</div>
              </div>
              <Icon className="h-8 w-8 flex-none opacity-25" style={{ color: t.color }} />
            </div>
          );
        })}
      </div>

      {project.top_algorithms.length > 0 && (
        <div className="glass-card flex flex-wrap items-center gap-3 p-5">
          <span className="label-caps text-[color:var(--color-accent)]">Most common exposures</span>
          {project.top_algorithms.map((a) => (
            <span key={a} className="chip chip-danger" title={a}>
              {displayAlgorithm(a)}
            </span>
          ))}
          {project.shor > 0 && (
            <span className="metric-label ml-auto">
              {project.shor} Shor-breakable · {project.grover} Grover-weakened
            </span>
          )}
        </div>
      )}

      <section className="flex flex-col gap-3">
        <h2>Open this project in</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {destinations.map((d) => {
            const Icon = d.icon;
            return (
              <button
                key={d.path}
                onClick={() => go(d.path)}
                data-testid={`goto-${d.label.toLowerCase().replace(/\s+/g, '-')}`}
                className="group glass-card flex items-center gap-4 p-4 text-left transition-all hover:border-[color:var(--edge-lume)]"
              >
                <div className="flex h-10 w-10 flex-none items-center justify-center rounded-[3px] border border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent)]/10 text-[color:var(--color-accent)] group-hover:bg-[color:var(--color-accent)]/20">
                  <Icon className="h-4.5 w-4.5" />
                </div>
                <div className="min-w-0">
                  <div className="truncate text-[color:var(--color-accent-soft)]">{d.label}</div>
                  <div className="metric-label mt-0.5 truncate">{d.detail}</div>
                </div>
              </button>
            );
          })}
        </div>
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-[color:var(--color-accent)]" />
          Scans in this project
        </h2>
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="hud-table w-full">
              <thead>
                <tr>
                  <th className="px-5 py-3">Scan</th>
                  <th className="px-5 py-3">Target</th>
                  <th className="px-5 py-3">When</th>
                  <th className="px-5 py-3">Assets</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} className="data-row">
                    <td className="px-5 py-3.5 text-[color:var(--color-accent-soft)]">#{s.seq}</td>
                    <td
                      className="max-w-[24rem] truncate px-5 py-3.5 text-xs text-[color:var(--color-ink-dim)]"
                      title={s.targets.join(', ')}
                    >
                      {s.targets.join(', ')}
                    </td>
                    <td className="px-5 py-3.5 text-xs text-[color:var(--color-ink-faint)]">
                      {timeAgo(s.created_at)}
                    </td>
                    <td className="px-5 py-3.5 text-[color:var(--color-accent)]">
                      {s.stats?.assets ?? '—'}
                    </td>
                    <td className="px-5 py-3.5 text-xs text-[color:var(--color-ink-dim)]">
                      {s.status}
                    </td>
                    <td className="whitespace-nowrap px-5 py-3.5 text-right">
                      <button
                        onClick={() => {
                          setScanId(s.id);
                          navigate('/inventory');
                        }}
                        disabled={s.status !== 'succeeded'}
                        className="label-caps mr-4 text-[color:var(--color-accent)] transition-colors hover:text-[color:var(--color-accent-soft)] disabled:opacity-40"
                      >
                        Open
                      </button>
                      {s.status === 'succeeded' && (
                        <button
                          onClick={() => {
                            openScan(s.project_id, s.id);
                            navigate(`/report/${s.id}`);
                          }}
                          className="label-caps text-[color:var(--color-accent-2)] transition-colors hover:text-[color:var(--color-accent)]"
                        >
                          <FileText className="mr-1 inline h-3.5 w-3.5" />
                          Report
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {scans.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-5 py-10 text-center text-[color:var(--color-ink-faint)]"
                    >
                      This project has no scans.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}

export function Projects() {
  const navigate = useNavigate();
  const projectId = useUiStore((s) => s.projectId);

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1>Projects</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            {projectId
              ? 'Everything QUBIT knows about this project, and every tab scoped to it.'
              : 'One project per thing you scan. Open one to work inside it.'}
          </p>
        </div>
        <button onClick={() => navigate('/scans')} className="hud-btn">
          <Plus className="h-3.5 w-3.5" />
          New scan
        </button>
      </header>

      {projectId ? <ProjectDetail projectId={projectId} /> : <ProjectGrid />}
    </AnimatedPage>
  );
}
