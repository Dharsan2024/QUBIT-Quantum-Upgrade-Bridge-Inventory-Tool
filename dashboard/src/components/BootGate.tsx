import { useEffect, useState } from 'react';
import { ShieldCheck, Loader2, Container, Cpu, RefreshCw } from 'lucide-react';
import { API_BASE } from '../api/client';

/**
 * Boot gate: the app's API is a child process that takes a few seconds to bind. Rendering the
 * dashboard immediately caused the first fetch to fail -> the "API not reachable" popup. This gate
 * polls /health until the API answers, then reveals the app. It also reports Docker/Ollama so the
 * user can start them and reconnect — no dead-ends, no scary error toasts on startup.
 */

type Deps = { docker: boolean; ollama: boolean };

// Use the SAME absolute base the API client uses. A relative URL would resolve against
// tauri.localhost (the desktop window's origin) and never reach the local engine.
async function ping(): Promise<boolean> {
  try {
    const r = await fetch(`${API_BASE}/health`, { cache: 'no-store' });
    return r.ok;
  } catch {
    return false;
  }
}

async function fetchDeps(): Promise<Deps | null> {
  try {
    const r = await fetch(`${API_BASE}/health/deps`, { cache: 'no-store' });
    if (!r.ok) return null;
    const d = await r.json();
    return { docker: !!d.docker, ollama: !!d.ollama };
  } catch {
    return null;
  }
}

export function BootGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let tries = 0;
    const started = Date.now();

    async function loop() {
      while (!cancelled) {
        if (await ping()) {
          if (!cancelled) setReady(true);
          return;
        }
        tries += 1;
        if (!cancelled) setElapsed(Math.round((Date.now() - started) / 1000));
        await new Promise((r) => setTimeout(r, Math.min(500 + tries * 150, 1500)));
      }
    }
    loop();
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  if (ready) return <>{children}</>;

  // Cold start (fresh process tree + AV scan of the venv) can legitimately take ~20-30s, so only
  // surface the troubleshooting hint well past that — otherwise a normal boot looks like a failure.
  const slow = elapsed >= 35;

  return (
    <div className="boot-screen">
      <div className="boot-card">
        <div className="boot-logo">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <div className="boot-title">QUBIT</div>
        <div className="boot-sub">Quantum Upgrade Bridge &amp; Inventory Tool</div>

        <div className="boot-status">
          <Loader2 className="h-4 w-4 animate-spin" />
          {slow ? 'Still starting the engine…' : 'Starting the engine…'}
        </div>

        {slow && (
          <p className="boot-hint">
            The local engine is taking longer than usual. It runs via <code>uv</code> — make sure
            that's installed and on PATH. You can retry below.
          </p>
        )}

        <button className="boot-retry" onClick={() => setAttempt((a) => a + 1)}>
          <RefreshCw className="h-3.5 w-3.5" /> Retry connection
        </button>

        <div className="boot-foot">Offline · local · no telemetry</div>
      </div>
    </div>
  );
}

/** Polls the optional local dependencies once, with a manual refresh. */
function useDeps() {
  const [deps, setDeps] = useState<Deps | null>(null);
  const [checking, setChecking] = useState(false);

  const refresh = async () => {
    setChecking(true);
    setDeps(await fetchDeps());
    setChecking(false);
  };
  useEffect(() => {
    refresh();
  }, []);

  return { deps, checking, refresh };
}

/**
 * Status LEDs for the top HUD rail: the engine is up (the boot gate guarantees it) and
 * Docker/Ollama are shown as live telltales rather than only as a warning banner.
 */
export function DepsLeds() {
  const { deps, checking, refresh } = useDeps();

  const led = (ok: boolean | undefined, label: string, Icon: typeof Container) => {
    const color = ok == null ? 'var(--color-ink-faint)' : ok ? 'var(--color-safe)' : 'var(--color-warn)';
    return (
      <span
        className="label-caps flex items-center gap-1.5"
        style={{ color }}
        title={`${label}: ${ok == null ? 'unknown' : ok ? 'connected' : 'not running'}`}
      >
        <Icon className="h-3.5 w-3.5" />
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: color, boxShadow: `0 0 6px ${color}` }}
        />
        {label}
      </span>
    );
  };

  return (
    <div className="flex items-center gap-4">
      {led(true, 'Engine', ShieldCheck)}
      {led(deps?.docker, 'Docker', Container)}
      {led(deps?.ollama, 'Ollama', Cpu)}
      <button
        onClick={refresh}
        disabled={checking}
        className="text-[color:var(--color-ink-faint)] transition-colors hover:text-[color:var(--color-accent)] disabled:opacity-50"
        title="Recheck local dependencies"
        aria-label="Recheck local dependencies"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${checking ? 'animate-spin' : ''}`} />
      </button>
    </div>
  );
}

/** Small banner shown inside the app when an optional dependency is down (Docker/Ollama). */
export function DepsBanner() {
  const { deps, checking, refresh } = useDeps();

  if (!deps || (deps.docker && deps.ollama)) return null;

  return (
    <div className="deps-banner">
      <div className="deps-items">
        {!deps.docker && (
          <span className="deps-item">
            <Container className="h-4 w-4" /> Docker not running — patch sandbox validation is
            disabled. Start Docker Desktop, then Recheck.
          </span>
        )}
        {!deps.ollama && (
          <span className="deps-item">
            <Cpu className="h-4 w-4" /> Ollama not running — LLM patches disabled (template patches
            still work). Run <code>ollama serve</code>, then Recheck.
          </span>
        )}
      </div>
      <button className="deps-recheck" onClick={refresh} disabled={checking}>
        {checking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        Recheck
      </button>
    </div>
  );
}
