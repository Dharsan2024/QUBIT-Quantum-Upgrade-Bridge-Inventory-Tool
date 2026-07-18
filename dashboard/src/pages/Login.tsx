import { AnimatedPage } from '../components/AnimatedPage';
import { KeyRound, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router';

export function Login() {
  const navigate = useNavigate();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // In a real app we'd validate the token here
    navigate('/');
  };

  return (
    <AnimatedPage className="min-h-screen w-full flex items-center justify-center p-4">
      <div className="glass-card w-full max-w-md rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        <div className="relative z-10 flex flex-col items-center">
          <div className="w-16 h-16 rounded-2xl bg-[color:var(--glass-highlight)] border border-[color:var(--glass-border)] flex items-center justify-center mb-6 shadow-lg shadow-[color:var(--color-accent)]/20">
            <span className="text-[color:var(--color-ink)] font-bold text-4xl leading-none tracking-tighter">Q</span>
          </div>
          
          <h1 className="text-2xl font-bold tracking-tight text-white mb-2">Welcome to QUBIT</h1>
          <p className="text-[color:var(--color-ink-dim)] text-center text-sm mb-8">
            Enter your API token to access the platform.
          </p>

          <form onSubmit={handleLogin} className="w-full space-y-4">
            <div>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[color:var(--color-ink-faint)]" />
                <input 
                  type="password" 
                  placeholder="API Token"
                  className="glass-input w-full rounded-xl pl-10 pr-4 py-3 text-[color:var(--color-ink)] font-mono text-sm"
                />
              </div>
            </div>
            
            <button 
              type="submit"
              className="w-full flex items-center justify-center gap-2 bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-3 rounded-xl font-semibold transition-all shadow-lg shadow-indigo-500/20 group text-sm"
            >
              Authenticate
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </button>
          </form>
        </div>
      </div>
    </AnimatedPage>
  );
}
