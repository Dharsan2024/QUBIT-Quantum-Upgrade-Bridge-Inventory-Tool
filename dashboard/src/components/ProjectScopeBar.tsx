import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, FolderGit2, Radar } from 'lucide-react';
import { fetchProjects } from '../api/client';
import { useActiveScan } from '../hooks/useActiveScan';
import { useUiStore } from '../stores/ui';

/**
 * The bar that sits at the top of a project-scoped page: which project you are inside, which of its
 * scans is being displayed, and the way back out.
 *
 * It exists because scoping a page is only half the fix. Once a tab shows one project's data, the
 * screen has to say *which* project and *which scan within it* — otherwise the numbers are just as
 * ambiguous as the merged view they replaced, only smaller. The scan selector is deliberately here
 * rather than buried in a page: a project accumulates scans over time, and comparing "before" with
 * "after" is the normal reason to be looking.
 */
export function ProjectScopeBar({ children }: { children?: React.ReactNode }) {
  const clearProject = useUiStore((s) => s.clearProject);
  const setScanId = useUiStore((s) => s.setScanId);
  const { activeScanId, projectScans, projectId } = useActiveScan();
  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: fetchProjects });
  const project = projects?.find((p) => p.id === projectId);

  if (!projectId) return null;

  return (
    <div
      className="glass-card flex flex-wrap items-center gap-x-5 gap-y-3 px-5 py-3"
      data-testid="project-scope-bar"
    >
      <button
        onClick={clearProject}
        className="label-caps flex items-center gap-2 text-[color:var(--color-ink-dim)] transition-colors hover:text-[color:var(--color-accent)]"
        data-testid="leave-project"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        All projects
      </button>

      <span className="h-5 w-px bg-[color:var(--edge)]" />

      <span className="flex min-w-0 items-center gap-2">
        <FolderGit2 className="h-4 w-4 flex-none text-[color:var(--color-accent)]" />
        <span
          className="truncate font-medium text-[color:var(--color-accent-soft)]"
          data-testid="scope-project-name"
        >
          {project?.name ?? 'Project'}
        </span>
      </span>

      {projectScans.length > 0 && (
        <label className="flex items-center gap-2 text-xs text-[color:var(--color-ink-dim)]">
          <Radar className="h-3.5 w-3.5 text-[color:var(--color-accent)]" />
          <span className="label-caps">Scan</span>
          <select
            value={activeScanId ?? ''}
            onChange={(e) => setScanId(e.target.value || undefined)}
            className="glass-input px-2 py-1.5 text-xs"
            data-testid="scope-scan-select"
            aria-label="Scan to display"
          >
            {projectScans.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.seq} · {s.targets.join(', ').slice(0, 48) || 'no target'} ·{' '}
                {s.stats?.assets ?? 0} assets
                {s.status === 'succeeded' ? '' : ` · ${s.status}`}
              </option>
            ))}
          </select>
        </label>
      )}

      {children && <div className="ml-auto flex items-center gap-3">{children}</div>}
    </div>
  );
}
