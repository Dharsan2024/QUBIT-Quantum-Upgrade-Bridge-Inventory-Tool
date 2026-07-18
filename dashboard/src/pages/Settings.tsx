import { AnimatedPage } from '../components/AnimatedPage';
import { Settings as SettingsIcon, Server, Shield, Trash2, Check } from 'lucide-react';

export function Settings() {
  return (
    <AnimatedPage className="flex flex-col gap-5 py-4 max-w-4xl mx-auto">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-3">
            <SettingsIcon className="w-7 h-7 text-[color:var(--color-accent)]" />
            Platform Settings
          </h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">Configure API connections, authentication, and local preferences.</p>
        </div>
      </header>

      <div className="glass-card p-6">
        <div className="space-y-6">
          <h2 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <Server className="w-5 h-5 text-[color:var(--color-accent)]" /> Connection
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-[color:var(--color-ink-dim)] mb-1">API Endpoint</label>
              <input 
                type="text" 
                defaultValue="http://127.0.0.1:8787/api/v1" 
                className="glass-input w-full px-4 py-2.5 text-[color:var(--color-ink)]"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-[color:var(--color-ink-dim)] mb-1">Authentication Token</label>
              <div className="flex gap-3">
                <input 
                  type="password" 
                  defaultValue="hardcoded-dev-token"
                  className="glass-input flex-1 px-4 py-2.5 text-[color:var(--color-ink)] font-mono"
                />
                <button className="glass-input px-4 py-2.5 text-sm font-medium hover:border-[color:var(--color-ink-dim)]">
                  Update
                </button>
              </div>
            </div>

            <div className="pt-2">
              <button className="flex items-center gap-2 text-sm text-[color:var(--color-safe)] font-medium px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                <Check className="w-4 h-4" /> Connection Verified
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="glass-card p-6 border-[color:var(--color-danger)]/30 bg-rose-500/5">
        <div className="space-y-4">
          <h2 className="text-xl font-semibold text-[color:var(--color-danger)] flex items-center gap-2 tracking-tight">
            <Shield className="w-5 h-5" /> Danger Zone
          </h2>
          <p className="text-sm text-[color:var(--color-ink-faint)]">
            Deleting a project removes all associated scans, inventory items, risk data, and migration tasks permanently.
          </p>
          <button className="flex items-center gap-2 px-4 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-[color:var(--color-danger)] border border-rose-500/30 rounded-lg transition-colors font-medium text-sm">
            <Trash2 className="w-4 h-4" /> Delete Current Project
          </button>
        </div>
      </div>
    </AnimatedPage>
  );
}
