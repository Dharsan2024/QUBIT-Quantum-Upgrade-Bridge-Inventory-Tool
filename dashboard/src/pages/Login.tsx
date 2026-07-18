import { AnimatedPage } from '../components/AnimatedPage';
import { KeyRound, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router';
import { useLiquidGlass } from '../hooks/useLiquidGlass';

export function Login() {
  const navigate = useNavigate();
  const glassRef = useLiquidGlass({ scale: -100, blur: 5 });

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // In a real app we'd validate the token here
    navigate('/');
  };

  return (
    <AnimatedPage className="min-h-screen w-full flex items-center justify-center bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-4">
      <div className="absolute inset-0 bg-[url('/noise.png')] opacity-[0.03] pointer-events-none mix-blend-overlay"></div>
      
      <div ref={glassRef} className="w-full max-w-md bg-slate-900/50 backdrop-blur-xl border border-slate-800/60 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        <div className="relative z-10 flex flex-col items-center">
          <div className="w-16 h-16 rounded-2xl bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
            <span className="text-indigo-400 font-bold text-4xl leading-none">Q</span>
          </div>
          
          <h1 className="text-2xl font-bold tracking-tight text-white mb-2">Welcome to QUBIT</h1>
          <p className="text-slate-400 text-center text-sm mb-8">
            Enter your API token to access the platform.
          </p>

          <form onSubmit={handleLogin} className="w-full space-y-4">
            <div>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                <input 
                  type="password" 
                  placeholder="API Token"
                  className="w-full bg-slate-950/50 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-shadow font-mono text-sm"
                />
              </div>
            </div>
            
            <button 
              type="submit"
              className="w-full flex items-center justify-center gap-2 bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-3 rounded-xl font-semibold transition-all shadow-lg shadow-indigo-500/20 group"
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
