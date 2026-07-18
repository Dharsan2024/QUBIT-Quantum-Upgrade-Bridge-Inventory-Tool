import { useState } from 'react';
import { AnimatedPage } from '../components/AnimatedPage';
import { KeyRound, ArrowRight, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router';
import { getToken, setToken, whoami } from '../api/client';

export function Login() {
  const navigate = useNavigate();
  const [token, setTokenInput] = useState(getToken());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    setToken(token.trim());
    try {
      await whoami(); // validate the token against the API before entering
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
      setBusy(false);
    }
  };

  return (
    <AnimatedPage className="flex min-h-screen w-full items-center justify-center p-4">
      <div className="glass-card relative w-full max-w-md overflow-hidden rounded-2xl p-8 shadow-2xl">
        <div className="relative z-10 flex flex-col items-center">
          <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-2xl border border-[color:var(--glass-border)] bg-[color:var(--glass-highlight)] shadow-lg shadow-[color:var(--color-accent)]/20">
            <span className="text-4xl font-bold leading-none tracking-tighter text-[color:var(--color-ink)]">
              Q
            </span>
          </div>

          <h1 className="mb-2 text-2xl font-bold tracking-tight text-white">Welcome to QUBIT</h1>
          <p className="mb-8 text-center text-sm text-[color:var(--color-ink-dim)]">
            Enter your API token to access the platform.
          </p>

          <form onSubmit={handleLogin} className="w-full space-y-4">
            <div className="relative">
              <KeyRound className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-[color:var(--color-ink-faint)]" />
              <input
                type="password"
                value={token}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="API Token"
                className="glass-input w-full rounded-xl py-3 pl-10 pr-4 font-mono text-sm text-[color:var(--color-ink)]"
              />
            </div>

            {error && (
              <div className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="group flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-500 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-500/20 transition-all hover:bg-indigo-400 disabled:opacity-60"
            >
              {busy ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  Authenticate
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </AnimatedPage>
  );
}
