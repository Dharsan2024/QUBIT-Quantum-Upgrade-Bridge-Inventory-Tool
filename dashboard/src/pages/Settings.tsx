import { useState } from 'react';
import { AnimatedPage } from '../components/AnimatedPage';
import { Settings as SettingsIcon, Server, Check, Loader2, XCircle } from 'lucide-react';
import { getToken, setToken, whoami } from '../api/client';

export function Settings() {
  const [token, setTokenInput] = useState(getToken());
  const [status, setStatus] = useState<'idle' | 'checking' | 'ok' | 'fail'>('idle');
  const [detail, setDetail] = useState('');

  const verify = async () => {
    setToken(token.trim());
    setStatus('checking');
    try {
      const who = await whoami();
      setDetail(`${who.name} · scopes: ${who.scopes}`);
      setStatus('ok');
    } catch (e) {
      setDetail(e instanceof Error ? e.message : 'connection failed');
      setStatus('fail');
    }
  };

  return (
    <AnimatedPage className="mx-auto flex max-w-4xl flex-col gap-5 py-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-tight">
            <SettingsIcon className="h-7 w-7 text-[color:var(--color-accent)]" />
            Platform Settings
          </h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            Configure the API connection and authentication token used by this browser.
          </p>
        </div>
      </header>

      <div className="glass-card p-6">
        <div className="space-y-6">
          <h2 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
            <Server className="h-5 w-5 text-[color:var(--color-accent)]" /> Connection
          </h2>

          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium text-[color:var(--color-ink-dim)]">
                API Endpoint
              </label>
              <input
                type="text"
                value={import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8787/api/v1'}
                readOnly
                className="glass-input w-full px-4 py-2.5 text-[color:var(--color-ink-dim)]"
              />
              <p className="mt-1 text-xs text-[color:var(--color-ink-faint)]">
                Set at build time via <span className="font-mono">VITE_API_BASE</span>.
              </p>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-[color:var(--color-ink-dim)]">
                Authentication Token
              </label>
              <div className="flex gap-3">
                <input
                  type="password"
                  value={token}
                  onChange={(e) => setTokenInput(e.target.value)}
                  className="glass-input flex-1 px-4 py-2.5 font-mono text-[color:var(--color-ink)]"
                />
                <button
                  onClick={verify}
                  className="glass-input flex items-center gap-2 px-4 py-2.5 text-sm font-medium hover:border-[color:var(--color-ink-dim)]"
                >
                  {status === 'checking' ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    'Save & Verify'
                  )}
                </button>
              </div>
            </div>

            {status === 'ok' && (
              <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-[color:var(--color-safe)]">
                <Check className="h-4 w-4" /> Connection verified — {detail}
              </div>
            )}
            {status === 'fail' && (
              <div className="flex items-center gap-2 rounded-lg border border-rose-500/20 bg-rose-500/10 px-4 py-2 text-sm font-medium text-[color:var(--color-danger)]">
                <XCircle className="h-4 w-4" /> {detail}
              </div>
            )}
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
