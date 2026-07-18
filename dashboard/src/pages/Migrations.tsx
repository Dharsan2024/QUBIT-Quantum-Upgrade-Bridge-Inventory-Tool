import { AnimatedPage } from '../components/AnimatedPage';
import { Play, CheckCircle2, XCircle, Clock, AlertCircle } from 'lucide-react';
import { Link } from 'react-router';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useLiquidGlass } from '../hooks/useLiquidGlass';

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

const MOCK_MIGRATIONS = [
  { id: 'm-101', asset: 'src/auth/hash.py:42', algo: 'MD5', recommendation: 'argon2', status: 'pending', risk: 0.95 },
  { id: 'm-102', asset: 'src/crypto/tls.py:12', algo: 'TLSv1.1', recommendation: 'TLSv1.3', status: 'generated', risk: 0.88 },
  { id: 'm-103', asset: 'config/nginx.conf:24', algo: 'RSA-2048', recommendation: 'ML-KEM-768', status: 'approved', risk: 0.72 },
  { id: 'm-104', asset: 'src/utils/sign.py:105', algo: 'SHA1', recommendation: 'SHA256', status: 'applied', risk: 0.65 },
];

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
    generated: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
    approved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    applied: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    rejected: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  };

  const Icon: Record<string, any> = {
    pending: Clock,
    generated: AlertCircle,
    approved: CheckCircle2,
    applied: CheckCircle2,
    rejected: XCircle,
  };

  const SelectedIcon = Icon[status] || Clock;

  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border relative z-10", styles[status] || styles.pending)}>
      <SelectedIcon className="w-3.5 h-3.5" />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

export function Migrations() {
  const glassRef = useLiquidGlass({ scale: -100 });

  return (
    <AnimatedPage className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Migration Queue</h1>
          <p className="text-slate-400 mt-1">Review and execute prioritized cryptographic patches.</p>
        </div>
        <button className="flex items-center gap-2 bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2 rounded-lg font-medium transition-colors shadow-lg shadow-indigo-500/20 relative z-10">
          <Play className="w-4 h-4 fill-current" />
          Generate All Planned
        </button>
      </div>

      <div ref={glassRef} className="liquid-panel rounded-xl overflow-hidden relative">
        <table className="w-full text-left text-sm text-slate-400 relative z-10">
          <thead className="bg-slate-950/50 text-slate-300 uppercase text-xs font-semibold">
            <tr>
              <th className="px-6 py-4">Asset</th>
              <th className="px-6 py-4">Current</th>
              <th className="px-6 py-4">Recommendation</th>
              <th className="px-6 py-4">Risk</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {MOCK_MIGRATIONS.map((migration) => (
              <tr key={migration.id} className="hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-4 font-mono text-slate-300">{migration.asset}</td>
                <td className="px-6 py-4">
                  <span className="px-2 py-1 bg-rose-500/10 text-rose-400 rounded text-xs border border-rose-500/20">
                    {migration.algo}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 py-1 bg-emerald-500/10 text-emerald-400 rounded text-xs border border-emerald-500/20">
                    {migration.recommendation}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-amber-500 to-rose-500"
                        style={{ width: `${migration.risk * 100}%` }}
                      />
                    </div>
                    <span className="text-xs">{migration.risk.toFixed(2)}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <StatusBadge status={migration.status} />
                </td>
                <td className="px-6 py-4 text-right">
                  <Link 
                    to={`/m/${migration.id}`}
                    className="text-indigo-400 hover:text-indigo-300 font-medium"
                  >
                    Review &rarr;
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AnimatedPage>
  );
}
