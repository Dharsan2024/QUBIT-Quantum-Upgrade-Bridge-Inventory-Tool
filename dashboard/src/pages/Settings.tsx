import { AnimatedPage } from '../components/AnimatedPage';
import { Settings as SettingsIcon, Server, Shield, Trash2, Check } from 'lucide-react';
import { useLiquidGlass } from '../hooks/useLiquidGlass';

export function Settings() {
  const glassRef1 = useLiquidGlass({ scale: -100 });
  const glassRef2 = useLiquidGlass({ scale: -100 });

  return (
    <AnimatedPage className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <SettingsIcon className="w-8 h-8 text-indigo-400" />
          Platform Settings
        </h1>
        <p className="text-slate-400 mt-1">Configure API connections, authentication, and local preferences.</p>
      </div>

      <div ref={glassRef1} className="liquid-panel rounded-xl p-6 ">
        <div className="relative z-10 space-y-6">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-indigo-400" /> Connection
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">API Endpoint</label>
              <input 
                type="text" 
                defaultValue="http://127.0.0.1:8787/api/v1" 
                className="w-full bg-slate-950/50 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-shadow"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Authentication Token</label>
              <div className="flex gap-3">
                <input 
                  type="password" 
                  defaultValue="hardcoded-dev-token"
                  className="flex-1 bg-slate-950/50 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-shadow font-mono"
                />
                <button className="px-4 py-2 border border-slate-700 hover:bg-slate-800 text-slate-300 rounded-lg font-medium transition-colors">
                  Update
                </button>
              </div>
            </div>

            <div className="pt-2">
              <button className="flex items-center gap-2 text-sm text-emerald-400 font-medium px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                <Check className="w-4 h-4" /> Connection Verified
              </button>
            </div>
          </div>
        </div>
      </div>

      <div ref={glassRef2} className="liquid-panel rounded-xl p-6 ">
        <div className="relative z-10 space-y-4">
          <h2 className="text-xl font-semibold text-rose-400 flex items-center gap-2">
            <Shield className="w-5 h-5" /> Danger Zone
          </h2>
          <p className="text-sm text-slate-400">
            Deleting a project removes all associated scans, inventory items, risk data, and migration tasks permanently.
          </p>
          <button className="flex items-center gap-2 px-4 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-lg transition-colors font-medium">
            <Trash2 className="w-4 h-4" /> Delete Current Project
          </button>
        </div>
      </div>
    </AnimatedPage>
  );
}
