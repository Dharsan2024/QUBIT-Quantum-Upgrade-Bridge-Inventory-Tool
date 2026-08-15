import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, Loader2, Container, Cpu, RefreshCw, Undo2 } from 'lucide-react';
import { getApiBase, setApiBase, fetchHealthDeps } from '../api/client';

/**
 * Boot gate: the app's API is a child process that takes a few seconds to bind. Rendering the
 * dashboard immediately caused the first fetch to fail -> the "API not reachable" popup. This gate
 * polls /health until the API answers, then reveals the app. It also reports Docker/Ollama so the
 * user can start them and reconnect — no dead-ends, no scary error toasts on startup.
 */

// Use the SAME absolute base the API client uses. A relative URL would resolve against
// tauri.localhost (the desktop window's origin) and never reach the local engine.
async function ping(): Promise<boolean> {
  try {
    const r = await fetch(`${getApiBase()}/health`, { cache: 'no-store' });
    return r.ok;
  } catch {
    return false;
  }
}


export function BootGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [attempt, setAttempt] = useState(0);
  const [failed, setFailed] = useState(false);

  // Caps total wait at ~117 s: retries back off from 0.5s to a 1.5s ceiling (reached at try 7),
  // so 6 short retries + 74 at the 1.5s cap. After this the user gets a hard-failure card with
  // actionable guidance instead of an infinite spinner.
  const MAX_TRIES = 80;

  useEffect(() => {
    let cancelled = false;
    let tries = 0;
    const started = Date.now();
    setFailed(false);

    async function loop() {
      while (!cancelled) {
        if (await ping()) {
          if (!cancelled) setReady(true);
          return;
        }
        tries += 1;
        if (!cancelled) setElapsed(Math.round((Date.now() - started) / 1000));
        if (tries >= MAX_TRIES) {
          if (!cancelled) setFailed(true);
          return;
        }
        await new Promise((r) => setTimeout(r, Math.min(500 + tries * 150, 1500)));
      }
    }
    loop();
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  if (ready) return <>{children}</>;

  // Hard failure: engine never answered within MAX_TRIES.
  if (failed) {
    // Settings lives behind this gate — if a custom API endpoint (Settings -> API Endpoint) is
    // set and wrong, the user would otherwise have no way back in to fix it. Detect that case and
    // offer to clear the override, rather than stranding them on this screen permanently.
    const defaultBase = (import.meta.env.VITE_API_BASE as string | undefined) ?? 'http://127.0.0.1:8787/api/v1';
    const usingOverride = getApiBase() !== defaultBase;

    return (
      <div className="boot-screen">
        <div className="boot-card">
          <div className="boot-logo" style={{ color: 'var(--color-danger)' }}>
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div className="boot-title">QUBIT</div>
          <div className="boot-sub" style={{ color: 'var(--color-danger)' }}>
            Engine not reachable
          </div>
          <p className="boot-hint">
            The local engine did not respond after ~2 minutes.
            {usingOverride ? ' A custom API endpoint is set:' : ' Common causes:'}
          </p>
          {usingOverride ? (
            <>
              <p className="boot-hint">
                <code>{getApiBase()}</code>
              </p>
              <button
                className="boot-retry"
                onClick={() => {
                  setApiBase(defaultBase);
                  setElapsed(0);
                  setAttempt((a) => a + 1);
                }}
              >
                <Undo2 className="h-3.5 w-3.5" /> Reset to local engine
              </button>
            </>
          ) : (
            <ul className="boot-hint" style={{ textAlign: 'left', paddingLeft: '1.2rem', listStyle: 'disc' }}>
              <li><code>uv</code> is not installed or not on PATH</li>
              <li>The engine process crashed — check the terminal for errors</li>
              <li>A firewall or antivirus blocked port 8787</li>
            </ul>
          )}
          <button
            className="boot-retry"
            style={usingOverride ? { marginTop: '0.6rem' } : undefined}
            onClick={() => { setElapsed(0); setAttempt((a) => a + 1); }}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry connection
          </button>
          <div className="boot-foot">Offline · local · no telemetry</div>
        </div>
      </div>
    );
  }

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


/**
 * Status LEDs for the top HUD rail: the engine is up (the boot gate guarantees it) and
 * Docker/Ollama are shown as live telltales rather than only as a warning banner.
 */
export function DepsLeds() {
  const { data: deps, isFetching: checking, refetch: refresh } = useQuery({
    queryKey: ['health-deps'],
    queryFn: fetchHealthDeps,
    refetchInterval: 15_000,
  });

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
        onClick={() => refresh()}
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
  const { data: deps, isFetching: checking, refetch: refresh } = useQuery({
    queryKey: ['health-deps'],
    queryFn: fetchHealthDeps,
    refetchInterval: 15_000,
  });

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
      <button className="deps-recheck" onClick={() => refresh()} disabled={checking}>
        {checking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        Recheck
      </button>
    </div>
  );
}
