import { Outlet, Link, useLocation } from 'react-router';
import {
  LayoutDashboard,
  ShieldAlert,
  Clock,
  GitPullRequestDraft,
  Activity,
  Settings,
  FileCode2,
  ShieldCheck,
  Rocket,
  Radar,
  Landmark,
  FolderGit2,
} from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { DepsBanner, DepsLeds } from './BootGate';
import { PageErrorBoundary } from './PageErrorBoundary';
import { useQuery } from '@tanstack/react-query';
import { fetchProjects, fetchScans } from '../api/client';
import { useUiStore } from '../stores/ui';

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

/** Sidebar order follows the order the work happens in: scan something, see the projects it
 *  produced, then read that project's inventory, risk, timeline, compliance and migration. Scans &
 *  Jobs leads because it is both the first thing a new installation needs and the page people
 *  return to most; it used to sit second from the bottom, below five tabs that are empty until a
 *  scan has run. */
const NAV_ITEMS = [
  { path: '/scans', label: 'Scans & Jobs', icon: Activity },
  { path: '/', label: 'Projects', icon: LayoutDashboard, exact: true },
  { path: '/inventory', label: 'Inventory', icon: FileCode2 },
  { path: '/risk', label: 'Risk Posture', icon: ShieldAlert },
  { path: '/timeline', label: 'CRQC Timeline', icon: Clock },
  { path: '/compliance', label: 'CNSA 2.0', icon: Landmark },
  { path: '/migrations', label: 'Migration Hub', icon: GitPullRequestDraft },
  { path: '/settings', label: 'Settings', icon: Settings },
];

/** Routes reachable from inside a page but absent from the sidebar — the rail still names them. */
const OFF_NAV_LABELS: { prefix: string; label: string }[] = [
  { prefix: '/cbom', label: 'CBOM Export' },
  { prefix: '/report', label: 'Detailed Report' },
];

export function Layout() {
  const location = useLocation();
  const normalizedPath = location.pathname.replace(/^\/p\/[^/]+/, '') || '/';
  const current = NAV_ITEMS.find((i) =>
    i.exact ? normalizedPath === i.path : normalizedPath.startsWith(i.path),
  );
  const railLabel =
    current?.label ??
    OFF_NAV_LABELS.find((o) => normalizedPath.startsWith(o.prefix))?.label ??
    'Command';

  // Resolve the active project + scan for the HUD context chips — reuses the shared React Query
  // cache, so this costs no extra request.
  const scanId = useUiStore((s) => s.scanId);
  const projectId = useUiStore((s) => s.projectId);
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: fetchProjects });
  const activeScan = scans?.find((s) => s.id === scanId);
  const activeProject = projects?.find((p) => p.id === projectId);

  // Pages where showing scan context makes sense (not projects list or settings).
  const showScanContext = !['/', '/settings'].includes(normalizedPath);

  return (
    <div className="relative flex h-screen w-full overflow-hidden text-[color:var(--color-ink)]">
      {/* Level 0 — deep-space wash + blueprint grid */}
      <div className="aurora" aria-hidden />

      {/* Sidebar — holographic glass rail */}
      <aside className="sidebar-vibrancy relative z-10 m-3 mr-0 flex w-[15.5rem] flex-shrink-0 flex-col">
        <div className="flex h-16 items-center gap-3 px-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-[3px] border border-[color:var(--color-accent)] bg-[color:var(--color-accent)]/12 shadow-[0_0_18px_-2px_rgba(56,224,255,0.55),inset_0_1px_0_rgba(255,255,255,0.35)]">
            <ShieldCheck className="h-5 w-5 text-[color:var(--color-accent)]" />
          </div>
          <div>
            <div className="text-gradient text-[1.45rem] font-bold leading-none">QUBIT</div>
            <div className="label-caps mt-1 text-[color:var(--color-accent)]/55">PQC Migration</div>
          </div>
        </div>

        <div className="mx-4 h-px bg-[color:var(--edge)]" />

        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = item.exact
              ? normalizedPath === item.path
              : normalizedPath.startsWith(item.path);
            return (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  'nav-pill flex items-center gap-3 px-3 py-2.5',
                  active
                    ? 'nav-pill-active'
                    : 'text-[color:var(--color-ink-dim)] hover:text-[color:var(--color-accent-soft)]',
                )}
              >
                <Icon
                  className={cn(
                    'h-[17px] w-[17px] flex-none',
                    active ? 'text-[color:var(--color-accent)]' : 'text-[color:var(--color-ink-faint)]',
                  )}
                />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="px-3 pb-3">
          <Link to="/migrations" className="hud-btn w-full">
            <Rocket className="h-3.5 w-3.5" />
            Initiate migration
          </Link>
        </div>

        <div className="glass m-3 mt-0 p-3 text-xs text-[color:var(--color-ink-dim)]">
          <div className="label-caps mb-1.5 flex items-center gap-2 text-[color:var(--color-safe)]">
            <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--color-safe)] shadow-[0_0_8px_2px_rgba(135,255,225,0.55)]" />
            Offline · local
          </div>
          No telemetry. Your code never leaves the machine.
        </div>
      </aside>

      {/* Main column */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        {/* Top HUD rail. The page's own <h1> names the view, so the rail carries live
            system telltales and global actions instead of repeating the title. */}
        <header className="glass no-ticks m-3 flex h-14 items-center justify-between gap-6 rounded-[4px] px-5">
          <div className="label-caps flex min-w-0 items-center gap-2 text-[color:var(--color-accent)]/70">
            <span className="text-[color:var(--color-ink-faint)]">QUBIT</span>
            <span className="text-[color:var(--color-ink-faint)]">//</span>
            <span className="truncate text-[color:var(--color-accent-soft)]">{railLabel}</span>
            {/* Which project (and scan) the page below is showing. Without the project name the
                numbers on a data page are unattributed — the exact ambiguity that scoping the
                tabs was meant to remove. */}
            {showScanContext && activeProject && (
              <>
                <span className="text-[color:var(--color-ink-faint)]">·</span>
                <span
                  className="flex max-w-[16rem] items-center gap-1 truncate rounded-[2px] border border-[color:var(--color-accent)]/25 bg-[color:var(--color-accent)]/10 px-2 py-0.5 font-mono text-[10px] text-[color:var(--color-accent)]"
                  title={`Showing project: ${activeProject.name}`}
                  data-testid="rail-project-chip"
                >
                  <FolderGit2 className="h-2.5 w-2.5 flex-none" />
                  {activeProject.name}
                </span>
              </>
            )}
            {showScanContext && activeScan && (
              <span
                className="flex items-center gap-1 rounded-[2px] border border-[color:var(--color-accent-2)]/25 bg-[color:var(--color-accent-2)]/10 px-2 py-0.5 font-mono text-[10px] text-[color:var(--color-accent-2)]"
                title={`Active scan: ${activeScan.targets.join(', ')}`}
              >
                <Radar className="h-2.5 w-2.5" />
                scan #{activeScan.seq}
              </span>
            )}
          </div>
          <div className="flex items-center gap-5">
            <DepsLeds />
            <span className="chip chip-info">CycloneDX 1.7</span>
            <Link to="/scans" className="hud-btn py-2">
              <Activity className="h-3.5 w-3.5" />
              New scan
            </Link>
          </div>
        </header>

        <DepsBanner />
        {/* Fill the window: content spans the full width with comfortable gutters.
            PageErrorBoundary resets per-pathname so navigating away from a broken page
            always starts fresh. */}
        <main className="min-h-0 flex-1 overflow-y-auto px-6 pb-8 lg:px-8">
          <div className="mx-auto w-full max-w-[1920px]">
            <PageErrorBoundary key={location.pathname}>
              <Outlet />
            </PageErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  );
}
