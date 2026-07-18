import { AnimatedPage } from '../components/AnimatedPage';
import { Activity, Clock, CheckCircle2, XCircle, FileCode } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useLiquidGlass } from '../hooks/useLiquidGlass';

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

const MOCK_JOBS = [
  { id: 'j-1', type: 'Scan', target: 'demo-lab', progress: 100, status: 'succeeded', time: '2m 14s' },
  { id: 'j-2', type: 'Risk Analysis', target: 'demo-lab (sid: a1b2)', progress: 100, status: 'succeeded', time: '0m 45s' },
  { id: 'j-3', type: 'Patch Generation', target: 'src/auth/hash.py', progress: 45, status: 'running', time: 'ongoing' },
];

function JobProgress({ progress, status }: { progress: number, status: string }) {
  if (status === 'succeeded') {
    return <div className="h-1.5 w-full bg-emerald-500 rounded-full" />;
  }
  if (status === 'failed') {
    return <div className="h-1.5 w-full bg-rose-500 rounded-full" />;
  }
  
  return (
    <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
      <div 
        className="h-full bg-indigo-500 relative" 
        style={{ width: `${progress}%` }}
      >
        <div className="absolute inset-0 bg-white/20 animate-[shimmer_1s_infinite_linear]" style={{ backgroundImage: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)' }} />
      </div>
    </div>
  );
}

export function Scans() {
  const glassRefTable = useLiquidGlass({ scale: -100 });
  const glassRefJob1 = useLiquidGlass({ scale: -80 });
  const glassRefJob2 = useLiquidGlass({ scale: -80 });
  const glassRefJob3 = useLiquidGlass({ scale: -80 });
  
  // Array of refs just for mock mapping simplicity
  const jobRefs = [glassRefJob1, glassRefJob2, glassRefJob3];

  return (
    <AnimatedPage className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white">Scans & Jobs</h1>
        <p className="text-slate-400 mt-1">Live background task orchestration and historical scan runs.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Live Jobs Panel */}
        <div className="lg:col-span-1 space-y-4">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <Activity className="w-5 h-5 text-indigo-400 animate-pulse" />
            Live Jobs
          </div>
          
          <div className="space-y-3">
            {MOCK_JOBS.map((job, idx) => (
              <div key={job.id} ref={jobRefs[idx]} className="liquid-panel rounded-xl p-4 ">
                <div className="relative z-10">
                  <div className="flex justify-between items-center mb-2 text-sm">
                    <span className="font-medium text-slate-200">{job.type}</span>
                    <span className="text-slate-500">{job.progress}%</span>
                  </div>
                  <div className="text-xs text-slate-400 mb-3 truncate">{job.target}</div>
                  <JobProgress progress={job.progress} status={job.status} />
                  <div className="flex justify-between items-center mt-3 text-xs">
                    <span className={cn(
                      "capitalize",
                      job.status === 'succeeded' && 'text-emerald-400',
                      job.status === 'failed' && 'text-rose-400',
                      job.status === 'running' && 'text-indigo-400',
                    )}>
                      {job.status}
                    </span>
                    <span className="text-slate-500 flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {job.time}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Historical Scans */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <FileCode className="w-5 h-5 text-slate-400" />
            Scan History
          </div>
          
          <div ref={glassRefTable} className="liquid-panel rounded-xl overflow-hidden relative">
            <table className="w-full text-left text-sm text-slate-400 relative z-10">
              <thead className="bg-slate-950/50 text-slate-300 uppercase text-xs font-semibold">
                <tr>
                  <th className="px-6 py-4">Scan ID</th>
                  <th className="px-6 py-4">Date</th>
                  <th className="px-6 py-4">Assets</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                <tr className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-4 font-mono text-slate-300">#42 (a1b2...)</td>
                  <td className="px-6 py-4">10 mins ago</td>
                  <td className="px-6 py-4 text-slate-200 font-medium">201</td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-1.5 text-emerald-400">
                      <CheckCircle2 className="w-4 h-4" /> Success
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-indigo-400 hover:text-indigo-300 font-medium mr-3">Compare</button>
                    <button className="text-rose-400 hover:text-rose-300 font-medium">Delete</button>
                  </td>
                </tr>
                <tr className="hover:bg-slate-800/30 transition-colors opacity-60">
                  <td className="px-6 py-4 font-mono text-slate-300">#41 (f8c9...)</td>
                  <td className="px-6 py-4">2 hours ago</td>
                  <td className="px-6 py-4 text-slate-200 font-medium">142</td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-1.5 text-rose-400">
                      <XCircle className="w-4 h-4" /> Failed
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-indigo-400 hover:text-indigo-300 font-medium mr-3" disabled>Compare</button>
                    <button className="text-rose-400 hover:text-rose-300 font-medium">Delete</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </AnimatedPage>
  );
}
