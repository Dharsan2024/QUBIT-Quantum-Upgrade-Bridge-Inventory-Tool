import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import {
  Activity,
  AlertTriangle,
  FolderGit2,
  GitPullRequestDraft,
  Plus,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { fetchProjectsOverview } from '../api/client';
import { useUiStore } from '../stores/ui';
import { displayAlgorithm } from '../lib/assetLabels';
import type { ProjectOverview } from '../api/types';

/**
 * The project-wise landing every data tab opens on.
 *
 * Each tab used to render one merged view of whatever scan happened to be newest, which on a real
 * installation meant ten unrelated scans — two source trees, a git remote and three network probes
 * — presented as a single 872-asset inventory. There was no way to tell, from the screen, which
 * finding belonged to which system. This grid is the missing step: pick the project first, and the
 * tab then shows only that project's assets.
 *
 * `metric` lets each tab lead with the number that tab is about, so the same grid reads correctly
 * on Inventory (assets) and on CNSA 2.0 (vulnerable) without becoming a different component.
 */

export type ProjectMetric = 'assets' | 'vulnerable' | 'risk' | 'migration';

function relative(iso: string): string {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (!Number.isFinite(mins)) return '—';
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  const days = Math.round(hrs / 24);
  if (days < 31) return `${days} d ago`;
  return new Date(iso).toLocaleDateString();
}

/** The single number this tab leads with, plus its label. */
function headline(p: ProjectOverview, metric: ProjectMetric): { value: string; label: string } {
  switch (metric) {
    case 'vulnerable':
      return { value: String(p.vulnerable), label: 'Quantum-vulnerable' };
    case 'risk':
      return {
        // An unscored project shows a dash, never "0.00" — those mean very different things and
        // printing the second for the first is how a blank page starts looking like a safe one.
        value: p.mean_risk == null ? '—' : p.mean_risk.toFixed(3),
        label: 'Mean risk score',
      };
    case 'migration':
      return { value: String(p.plan?.tasks ?? 0), label: 'Migration tasks' };
    default:
      return { value: String(p.assets), label: 'Assets discovered' };
  }
}

export function ProjectGrid({
  metric = 'assets',
  title = 'Choose a project',
  subtitle,
}: {
  metric?: ProjectMetric;
  title?: string;
  subtitle?: string;
}) {
  const navigate = useNavigate();
  const setProjectId = useUiStore((s) => s.setProjectId);
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['projects-overview'],
    queryFn: fetchProjectsOverview,
  });

  const projects = data ?? [];
  // Projects with findings first — an empty project is rarely the one you came to look at.
  const ordered = [...projects].sort(
    (a, b) => b.assets - a.assets || a.name.localeCompare(b.name),
  );

  if (isError) {
    return (
      <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)]">
        Could not load projects: {error instanceof Error ? error.message : 'unknown error'}.
        <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading projects…
      </div>
    );
  }

  if (!ordered.length) {
    return (
      <div className="glass-card flex flex-col items-center gap-4 p-12 text-center">
        <FolderGit2 className="h-8 w-8 text-[color:var(--color-ink-faint)]" />
        <div className="text-sm text-[color:var(--color-ink-dim)]">
          Nothing has been scanned yet. A project appears here for each thing you point QUBIT at.
        </div>
        <button onClick={() => navigate('/scans')} className="hud-btn" data-testid="grid-new-scan">
          <Plus className="h-3.5 w-3.5" /> Run the first scan
        </button>
      </div>
    );
  }

  return (
    <section className="flex flex-col gap-4" data-testid="project-grid">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[color:var(--color-accent-soft)]">{title}</h2>
          {subtitle && (
            <p className="mt-1.5 text-sm text-[color:var(--color-ink-dim)]">{subtitle}</p>
          )}
        </div>
        <span className="metric-label">
          {ordered.length} project{ordered.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="stagger grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
        {ordered.map((p) => {
          const h = headline(p, metric);
          const scanned = p.latest_scan;
          return (
            <button
              key={p.id}
              type="button"
              data-testid={`project-card-${p.slug}`}
              onClick={() => setProjectId(p.id)}
              className="group glass-card flex flex-col p-5 text-left transition-all hover:border-[color:var(--edge-lume)]"
            >
              <div className="mb-4 flex items-start gap-3">
                <div className="flex h-10 w-10 flex-none items-center justify-center rounded-[3px] border border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent)]/10 text-[color:var(--color-accent)] transition-all group-hover:bg-[color:var(--color-accent)]/20">
                  <FolderGit2 className="h-4.5 w-4.5" />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="truncate text-[color:var(--color-accent-soft)]" title={p.name}>
                    {p.name}
                  </h3>
                  <p
                    className="metric-label mt-1 truncate"
                    title={scanned?.targets.join(', ') ?? p.description ?? ''}
                  >
                    {scanned?.targets.join(', ') || p.description || 'no scan target recorded'}
                  </p>
                </div>
              </div>

              <div className="mb-4 flex items-end justify-between gap-4">
                <div>
                  <div
                    className="metric text-[2rem] leading-none"
                    style={{
                      color:
                        metric === 'vulnerable' && p.vulnerable > 0
                          ? 'var(--color-danger)'
                          : 'var(--color-accent)',
                    }}
                  >
                    {h.value}
                  </div>
                  <div className="metric-label mt-1.5">{h.label}</div>
                </div>
                <div className="flex flex-col items-end gap-1.5 text-right">
                  <span className="metric-label flex items-center gap-1.5">
                    <Activity className="h-3 w-3" /> {p.scans} scan{p.scans === 1 ? '' : 's'}
                  </span>
                  {p.vulnerable > 0 && metric !== 'vulnerable' && (
                    <span className="flex items-center gap-1.5 text-xs text-[color:var(--color-danger)]">
                      <ShieldAlert className="h-3 w-3" /> {p.vulnerable} vulnerable
                    </span>
                  )}
                </div>
              </div>

              {p.top_algorithms.length > 0 && (
                <div className="mb-4 flex flex-wrap gap-1.5">
                  {p.top_algorithms.map((a) => (
                    <span key={a} className="chip chip-danger" title={a}>
                      {displayAlgorithm(a)}
                    </span>
                  ))}
                </div>
              )}

              <div className="mt-auto flex items-center justify-between gap-3 border-t border-[color:var(--edge)] pt-3">
                <span className="metric-label">
                  {scanned ? relative(scanned.created_at) : 'never scanned'}
                </span>
                {p.plan ? (
                  <span
                    className={p.plan.stale ? 'chip chip-warn' : 'chip chip-safe'}
                    title={
                      p.plan.stale
                        ? 'A scan finished after this plan was built — rebuild it to match'
                        : `${p.plan.tasks} tasks, ${p.plan.automatable} with a codemod`
                    }
                  >
                    {p.plan.stale ? (
                      <>
                        <AlertTriangle className="mr-1 inline h-3 w-3" /> plan outdated
                      </>
                    ) : (
                      <>
                        <GitPullRequestDraft className="mr-1 inline h-3 w-3" /> {p.plan.tasks} tasks
                      </>
                    )}
                  </span>
                ) : (
                  p.vulnerable > 0 && <span className="chip chip-warn">no plan yet</span>
                )}
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}
