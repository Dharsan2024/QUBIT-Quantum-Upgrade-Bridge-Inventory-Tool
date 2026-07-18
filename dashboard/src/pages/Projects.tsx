import { AnimatedPage } from '../components/AnimatedPage';
import { FolderGit2, Activity, ShieldAlert, Plus } from 'lucide-react';
import { Link } from 'react-router';

// In a real implementation this comes from useQuery('/api/v1/projects')
const MOCK_PROJECTS = [
  { id: 'demo-123', name: 'demo-lab', lastScan: '10 mins ago', assets: 25, vulnerable: 3, risk: 'High' },
  { id: 'app-456', name: 'payment-gateway', lastScan: '2 hours ago', assets: 142, vulnerable: 12, risk: 'Critical' },
];

export function Projects() {
  const setRef = (el: HTMLDivElement | null) => {
    if (el) {
      window.liquidGlass?.(el, { scale: -80 });
    }
  };

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">Manage your scanned codebases and configurations.</p>
        </div>
        <button className="glass-input flex items-center gap-2 text-sm font-medium hover:border-indigo-400/60">
          <Plus className="w-4 h-4" />
          New Scan
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {MOCK_PROJECTS.map((project) => (
          <div key={project.id} ref={setRef} className="group glass-card p-6 transition-colors hover:border-indigo-500/30">
            <div className="flex justify-between items-start mb-6">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 group-hover:bg-indigo-500/20 transition-colors">
                  <FolderGit2 className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold tracking-tight">{project.name}</h3>
                  <p className="text-xs text-[color:var(--color-ink-dim)] uppercase tracking-wide mt-0.5">ID: {project.id}</p>
                </div>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-3 mb-6">
              <div className="glass-card bg-black/20 p-3">
                <div className="flex items-center gap-2 text-[color:var(--color-ink-faint)] text-xs uppercase tracking-wide mb-1">
                  <Activity className="w-3.5 h-3.5" /> Assets
                </div>
                <div className="text-xl font-semibold">{project.assets}</div>
              </div>
              <div className="glass-card bg-black/20 p-3">
                <div className="flex items-center gap-2 text-[color:var(--color-ink-faint)] text-xs uppercase tracking-wide mb-1">
                  <ShieldAlert className="w-3.5 h-3.5 text-[color:var(--color-danger)]" /> Vulnerable
                </div>
                <div className="text-xl font-semibold text-[color:var(--color-danger)]">{project.vulnerable}</div>
              </div>
            </div>

            <div className="flex items-center justify-between text-sm mt-auto">
              <span className="text-[color:var(--color-ink-faint)] text-xs">Last scan: {project.lastScan}</span>
              <Link 
                to={`/p/${project.id}/inventory`}
                className="text-[color:var(--color-accent)] font-medium hover:text-[color:var(--color-accent-2)] transition-colors text-sm flex items-center gap-1"
              >
                View Details &rarr;
              </Link>
            </div>
          </div>
        ))}
      </div>
    </AnimatedPage>
  );
}
