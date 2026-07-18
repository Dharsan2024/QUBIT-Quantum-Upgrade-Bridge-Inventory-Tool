import { AnimatedPage } from '../components/AnimatedPage';
import { Activity, Clock, CheckCircle2, XCircle, FileCode } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

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
    return <div className="h-1.5 w-full bg-[color:var(--color-safe)] rounded-full" />;
  }
  if (status === 'failed') {
    return <div className="h-1.5 w-full bg-[color:var(--color-danger)] rounded-full" />;
  }
  
  return (
    <div className="h-1.5 w-full bg-black/40 rounded-full overflow-hidden border border-[color:var(--glass-border)]">
      <div 
        className="h-full bg-[color:var(--color-accent)] relative" 
        style={{ width: `${progress}%` }}
      >
        <div className="absolute inset-0 bg-white/20 animate-[shimmer_1s_infinite_linear]" style={{ backgroundImage: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)' }} />
      </div>
    </div>
  );
}

export function Scans() {
  return (
    <AnimatedPage className="flex flex-col gap-5 py-4 max-w-7xl mx-auto">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scans & Jobs</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">Live background task orchestration and historical scan runs.</p>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Live Jobs Panel */}
        <div className="lg:col-span-1 space-y-4">
          <div className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <Activity className="w-5 h-5 text-[color:var(--color-accent)] animate-pulse" />
            Live Jobs
          </div>
          
          <div className="space-y-3">
            {MOCK_JOBS.map((job) => (
              <div key={job.id} className="glass-card p-4">
                <div className="flex justify-between items-center mb-2 text-sm">
                  <span className="font-medium">{job.type}</span>
                  <span className="text-[color:var(--color-ink-dim)]">{job.progress}%</span>
                </div>
                <div className="text-xs text-[color:var(--color-ink-faint)] mb-3 truncate">{job.target}</div>
                <JobProgress progress={job.progress} status={job.status} />
                <div className="flex justify-between items-center mt-3 text-xs">
                  <span className={cn(
                    "capitalize",
                    job.status === 'succeeded' && 'text-[color:var(--color-safe)]',
                    job.status === 'failed' && 'text-[color:var(--color-danger)]',
                    job.status === 'running' && 'text-[color:var(--color-accent)]',
                  )}>
                    {job.status}
                  </span>
                  <span className="text-[color:var(--color-ink-dim)] flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {job.time}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Historical Scans */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <FileCode className="w-5 h-5 text-[color:var(--color-ink-dim)]" />
            Scan History
          </div>
          
          <div className="glass-card overflow-hidden">
            <table className="w-full text-left text-sm text-[color:var(--color-ink-dim)]">
              <thead className="border-b border-[color:var(--glass-border)] bg-black/10 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Scan ID</th>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Date</th>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Assets</th>
                  <th className="px-6 py-4 font-medium text-[color:var(--color-ink)]">Status</th>
                  <th className="px-6 py-4 text-right font-medium text-[color:var(--color-ink)]">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[color:var(--glass-border)]">
                <tr className="hover:bg-black/10 transition-colors">
                  <td className="px-6 py-4 font-mono text-[color:var(--color-ink)] text-sm">#42 (a1b2...)</td>
                  <td className="px-6 py-4">10 mins ago</td>
                  <td className="px-6 py-4 text-[color:var(--color-ink)] font-medium">201</td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-1.5 text-[color:var(--color-safe)]">
                      <CheckCircle2 className="w-4 h-4" /> Success
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)] font-medium mr-3 transition-colors">Compare</button>
                    <button className="text-[color:var(--color-danger)] hover:text-rose-400 font-medium transition-colors">Delete</button>
                  </td>
                </tr>
                <tr className="hover:bg-black/10 transition-colors opacity-60">
                  <td className="px-6 py-4 font-mono text-[color:var(--color-ink)] text-sm">#41 (f8c9...)</td>
                  <td className="px-6 py-4">2 hours ago</td>
                  <td className="px-6 py-4 text-[color:var(--color-ink)] font-medium">142</td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-1.5 text-[color:var(--color-danger)]">
                      <XCircle className="w-4 h-4" /> Failed
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)] font-medium mr-3 transition-colors" disabled>Compare</button>
                    <button className="text-[color:var(--color-danger)] hover:text-rose-400 font-medium transition-colors">Delete</button>
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
