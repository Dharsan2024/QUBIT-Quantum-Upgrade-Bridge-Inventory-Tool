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
      <div className="glass-card glass-strong relative w-full max-w-md overflow-hidden p-8">
        <div className="relative z-10 flex flex-col items-center">
          <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-[4px] border border-[color:var(--color-accent)] bg-[color:var(--color-accent)]/12 shadow-[0_0_26px_-4px_rgba(56,224,255,0.6),inset_0_1px_0_rgba(255,255,255,0.35)]">
            <span className="font-[family-name:var(--font-display)] text-4xl font-bold leading-none text-[color:var(--color-accent)]">
              Q
            </span>
          </div>

          <h1 className="mb-2 text-center">QUBIT</h1>
          <p className="metric-label mb-8 text-center">Enter your API token to continue</p>

          <form onSubmit={handleLogin} className="w-full space-y-4">
            <div className="relative">
              <KeyRound className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-[color:var(--color-ink-faint)]" />
              <input
                type="password"
                value={token}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="API token"
                className="glass-input w-full py-3 pl-10 pr-4 text-sm"
              />
            </div>

            {error && (
              <div className="rounded-[3px] border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 px-3 py-2 font-mono text-sm text-[color:var(--color-danger)]">
                {error}
              </div>
            )}

            <button type="submit" disabled={busy} className="hud-btn group w-full py-3">
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
