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
    <AnimatedPage className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Projects</h1>
          <p className="text-slate-400 mt-1">Manage your scanned codebases and configurations.</p>
        </div>
        <button className="flex items-center gap-2 bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2 rounded-lg font-medium transition-colors shadow-lg shadow-indigo-500/20">
          <Plus className="w-4 h-4" />
          New Scan
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {MOCK_PROJECTS.map((project) => (
          <div key={project.id} ref={setRef} className="group liquid-panel rounded-xl p-6 transition-colors">
            <div className="relative z-10">
              <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-slate-800 rounded-lg group-hover:bg-indigo-500/20 transition-colors">
                    <FolderGit2 className="w-6 h-6 text-indigo-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">{project.name}</h3>
                    <p className="text-sm text-slate-400">ID: {project.id}</p>
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800/60">
                  <div className="flex items-center gap-2 text-slate-400 text-xs mb-1">
                    <Activity className="w-3.5 h-3.5" /> Total Assets
                  </div>
                  <div className="text-xl font-semibold text-slate-200">{project.assets}</div>
                </div>
                <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800/60">
                  <div className="flex items-center gap-2 text-slate-400 text-xs mb-1">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-500" /> Vulnerable
                  </div>
                  <div className="text-xl font-semibold text-slate-200">{project.vulnerable}</div>
                </div>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-500">Last scan: {project.lastScan}</span>
                <Link 
                  to={`/p/${project.id}/inventory`}
                  className="text-indigo-400 font-medium hover:text-indigo-300 transition-colors"
                >
                  View Details &rarr;
                </Link>
              </div>
            </div>
          </div>
        ))}
      </div>
    </AnimatedPage>
  );
}
