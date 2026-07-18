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
} from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

const NAV_ITEMS = [
  { path: '/', label: 'Projects', icon: LayoutDashboard, exact: true },
  { path: '/inventory', label: 'Inventory', icon: FileCode2 },
  { path: '/risk', label: 'Risk Posture', icon: ShieldAlert },
  { path: '/timeline', label: 'CRQC Timeline', icon: Clock },
  { path: '/migrations', label: 'Migrations', icon: GitPullRequestDraft },
  { path: '/scans', label: 'Scans & Jobs', icon: Activity },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export function Layout() {
  const location = useLocation();
  const normalizedPath = location.pathname.replace(/^\/p\/[^/]+/, '') || '/';
  const current = NAV_ITEMS.find((i) =>
    i.exact ? normalizedPath === i.path : normalizedPath.startsWith(i.path),
  );

  return (
    <div className="relative flex h-screen w-full overflow-hidden text-[color:var(--color-ink)]">
      <div className="aurora" aria-hidden />
      <div className="grain" aria-hidden />

      {/* Sidebar */}
      <aside className="glass relative z-10 m-3 mr-0 flex w-64 flex-shrink-0 flex-col rounded-[var(--radius)]">
        <div className="flex h-16 items-center gap-3 px-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-indigo-400/40 bg-gradient-to-br from-indigo-500/30 to-cyan-400/20 shadow-[0_8px_24px_-8px_rgba(99,102,241,0.7)]">
            <ShieldCheck className="h-5 w-5 text-indigo-200" />
          </div>
          <div>
            <div className="text-gradient text-lg font-semibold leading-none tracking-tight">QUBIT</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-[0.18em] text-[color:var(--color-ink-faint)]">
              PQC Migration
            </div>
          </div>
        </div>

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
                  'nav-pill flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium',
                  active
                    ? 'nav-pill-active'
                    : 'text-[color:var(--color-ink-dim)] hover:text-[color:var(--color-ink)]',
                )}
              >
                <Icon className={cn('h-[18px] w-[18px]', active ? 'text-cyan-300' : 'text-slate-500')} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="m-3 rounded-xl border border-white/10 bg-white/5 p-3 text-xs text-[color:var(--color-ink-dim)]">
          <div className="mb-1 flex items-center gap-2 font-semibold text-[color:var(--color-ink)]">
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_2px_rgba(52,211,153,0.6)]" />
            Offline · local
          </div>
          No telemetry. Your code never leaves the machine.
        </div>
      </aside>

      {/* Main column */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        <header className="glass m-3 flex h-16 items-center justify-between rounded-[var(--radius)] px-6">
          <div>
            <h2 className="text-base font-semibold tracking-tight">{current?.label ?? 'QUBIT'}</h2>
            <p className="text-xs text-[color:var(--color-ink-faint)]">
              Quantum Upgrade Bridge &amp; Inventory Tool
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="chip chip-safe">CycloneDX 1.7</span>
            <button className="glass-input text-sm font-medium hover:border-indigo-400/60">New scan</button>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto px-3 pb-3">
          <div className="mx-auto max-w-[1400px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
