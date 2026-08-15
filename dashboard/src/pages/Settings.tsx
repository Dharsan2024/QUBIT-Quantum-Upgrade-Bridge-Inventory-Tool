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
    <AnimatedPage className="flex flex-col gap-6 py-5">
      <header>
        <h1 className="flex items-center gap-3">
          <SettingsIcon className="h-8 w-8 text-[color:var(--color-accent)]" />
          Settings
        </h1>
        <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
          The local engine connection and the token this window uses to talk to it.
        </p>
      </header>

      <div className="glass-card max-w-3xl p-6">
        <div className="space-y-6">
          <h2 className="flex items-center gap-2">
            <Server className="h-5 w-5 text-[color:var(--color-accent)]" /> Connection
          </h2>

          <div className="space-y-5">
            <div>
              <label className="metric-label mb-2 block">API endpoint</label>
              <input
                type="text"
                value={import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8787/api/v1'}
                readOnly
                className="glass-input w-full px-4 py-2.5 text-[color:var(--color-ink-dim)]"
              />
              <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
                Baked at build time via{' '}
                <span className="font-mono text-[color:var(--color-accent-soft)]">VITE_API_BASE</span>.
              </p>
            </div>

            <div>
              <label className="metric-label mb-2 block">Authentication token</label>
              <div className="flex gap-3">
                <input
                  type="password"
                  value={token}
                  onChange={(e) => setTokenInput(e.target.value)}
                  className="glass-input flex-1 px-4 py-2.5"
                />
                <button onClick={verify} className="hud-btn px-5">
                  {status === 'checking' ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    'Save & verify'
                  )}
                </button>
              </div>
            </div>

            {status === 'ok' && (
              <div className="flex items-center gap-2 rounded-[3px] border border-[color:var(--color-safe)]/40 bg-[color:var(--color-safe)]/8 px-4 py-2.5 font-mono text-sm text-[color:var(--color-safe)]">
                <Check className="h-4 w-4" /> Connection verified — {detail}
              </div>
            )}
            {status === 'fail' && (
              <div className="flex items-center gap-2 rounded-[3px] border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 px-4 py-2.5 font-mono text-sm text-[color:var(--color-danger)]">
                <XCircle className="h-4 w-4" /> {detail}
              </div>
            )}
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
