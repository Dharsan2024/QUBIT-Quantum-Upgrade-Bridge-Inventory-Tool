import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import {
  Settings as SettingsIcon,
  Server,
  Check,
  Loader2,
  XCircle,
  Cpu,
  Container,
  Database,
  ShieldCheck,
  WifiOff,
  Code2,
  RefreshCw,
} from 'lucide-react';
import { fetchHealth, fetchHealthDeps, fetchLanguages, getToken, setToken, whoami, getApiBase, setApiBase } from '../api/client';

/** One labelled readout row inside a HUD panel. */
function Row({
  icon,
  label,
  value,
  tone = 'var(--color-accent-soft)',
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-[color:var(--edge)] py-2.5 last:border-b-0">
      <span className="label-caps flex items-center gap-2">
        {icon}
        {label}
      </span>
      <span className="font-mono text-sm" style={{ color: tone }}>
        {value}
      </span>
    </div>
  );
}

/** Display name for a tree-sitter grammar id. The grammar names are lowercase identifiers
    (`csharp`, `cpp`, `tsx`) and showing them raw makes the coverage list read like debug output. */
const LANGUAGE_LABELS: Record<string, string> = {
  bash: 'Bash / Shell',
  c: 'C',
  cpp: 'C++',
  csharp: 'C#',
  dart: 'Dart',
  go: 'Go',
  java: 'Java',
  javascript: 'JavaScript',
  kotlin: 'Kotlin',
  php: 'PHP',
  powershell: 'PowerShell',
  python: 'Python',
  ruby: 'Ruby',
  rust: 'Rust',
  scala: 'Scala',
  sql: 'SQL',
  swift: 'Swift',
  tsx: 'TSX',
  typescript: 'TypeScript',
};

export function Settings() {
  const [token, setTokenInput] = useState(getToken());
  const [apiBase, setApiBaseInput] = useState(getApiBase());
  const [status, setStatus] = useState<'idle' | 'checking' | 'ok' | 'fail'>('idle');
  const [detail, setDetail] = useState('');

  // Live engine facts — the page previously showed one card and left most of the window empty.
  const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth, refetchInterval: 15_000 });
  const deps = useQuery({
    queryKey: ['health-deps'],
    queryFn: fetchHealthDeps,
    refetchInterval: 15_000,
  });
  // Rule packs are static per install, so this never needs refetching.
  const languages = useQuery({
    queryKey: ['registry-languages'],
    queryFn: fetchLanguages,
    staleTime: Infinity,
  });

  const verify = async () => {
    setToken(token.trim());
    setApiBase(apiBase.trim());
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

  // Distinguish "still probing" from "definitely down" — a bare dash reads as a bug.
  const onOff = (v: boolean | undefined, up = 'connected', down = 'not running') =>
    v == null ? (deps.isLoading ? 'checking…' : 'unknown') : v ? up : down;
  const tone = (v: boolean | undefined) =>
    v == null ? 'var(--color-ink-faint)' : v ? 'var(--color-safe)' : 'var(--color-warn)';

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

      <div className="stagger grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="glass-card flex flex-col gap-5 p-6 xl:col-span-2">
          <h2 className="flex items-center gap-2">
            <Server className="h-5 w-5 text-[color:var(--color-accent)]" /> Connection
          </h2>

          <div>
            {/* `htmlFor`/`id`, not just a label ABOVE the field: a visual label is not a
                programmatic one, and a screen reader announced these two inputs as unlabelled
                ("edit text, blank"). Flagged by axe-core as a WCAG 3.3.2 / 4.1.2 failure. */}
            <label htmlFor="settings-api-endpoint" className="metric-label mb-2 block">
              API endpoint
            </label>
            <input
              id="settings-api-endpoint"
              type="text"
              value={apiBase}
              onChange={(e) => setApiBaseInput(e.target.value)}
              className="glass-input w-full px-4 py-2.5"
            />
            <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
              Defaults to <span className="font-mono text-[color:var(--color-accent-soft)]">VITE_API_BASE</span>.
              The desktop app starts this engine itself as a child process. Override here to point at a remote cluster.
            </p>
          </div>

          <div>
            <label htmlFor="settings-api-token" className="metric-label mb-2 block">
              Authentication token
            </label>
            <div className="flex gap-3">
              <input
                id="settings-api-token"
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

        <div className="flex flex-col gap-5">
          <div className="glass-card p-6">
            <h2 className="mb-3 flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-[color:var(--color-accent)]" /> Engine
            </h2>
            <Row
              icon={<Server className="h-3.5 w-3.5" />}
              label="Status"
              value={health.data?.status ?? (health.isLoading ? 'checking…' : 'unreachable')}
              tone={health.data?.status === 'ok' ? 'var(--color-safe)' : 'var(--color-warn)'}
            />
            <Row
              icon={<Database className="h-3.5 w-3.5" />}
              label="Registry DB"
              value={health.data?.db ?? '—'}
              tone={health.data?.db === 'ok' ? 'var(--color-safe)' : 'var(--color-warn)'}
            />
            <Row
              icon={<ShieldCheck className="h-3.5 w-3.5" />}
              label="Version"
              value={health.data?.version ?? '—'}
            />
            <Row
              icon={<Container className="h-3.5 w-3.5" />}
              label="Docker"
              value={onOff(deps.data?.docker)}
              tone={tone(deps.data?.docker)}
            />
            <Row
              icon={<Cpu className="h-3.5 w-3.5" />}
              label="Ollama"
              value={onOff(deps.data?.ollama)}
              tone={tone(deps.data?.ollama)}
            />
          </div>

          <div className="glass-card p-6">
            <h2 className="mb-1 flex items-center gap-2">
              <Code2 className="h-5 w-5 text-[color:var(--color-accent)]" /> Language coverage
            </h2>
            <p className="mb-3 text-xs text-[color:var(--color-ink-faint)]">
              {languages.data
                ? `${languages.data.length} grammars · ${languages.data.reduce((n, l) => n + l.rules, 0)} rules`
                : languages.isLoading
                  ? 'loading…'
                  : 'unavailable'}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {(languages.data ?? []).map((l) => (
                <span
                  key={l.language}
                  title={`${l.rules} rules · ${l.extensions.join(' ')}`}
                  className="rounded-[3px] border border-[color:var(--edge)] px-2 py-1 font-mono text-[11px] text-[color:var(--color-ink-dim)]"
                >
                  {LANGUAGE_LABELS[l.language] ?? l.language}
                  <span className="ml-1.5 text-[color:var(--color-accent-soft)]">{l.rules}</span>
                </span>
              ))}
            </div>
          </div>

          {/* The window loads the dashboard FROM the API (see src-tauri/main.rs
              `serve_ui_from_api`), not from a copy compiled into the .exe — so a rebuilt
              dashboard/dist is picked up by a plain reload. Before that change the bundled copy
              was frozen at build time and every UI change needed a full reinstall to be seen. */}
          <div className="glass-card p-6">
            <h2 className="mb-1 flex items-center gap-2">
              <RefreshCw className="h-5 w-5 text-[color:var(--color-accent)]" /> Updates
            </h2>
            <p className="mb-3 text-xs text-[color:var(--color-ink-faint)]">
              The engine runs from source and the interface is served by it, so both pick up changes
              without reinstalling. Reload to load the current build.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="hud-btn"
              title="Reload the dashboard from the engine"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Reload interface
            </button>
          </div>

          <div className="glass-card p-6">
            <h2 className="mb-3 flex items-center gap-2">
              <WifiOff className="h-5 w-5 text-[color:var(--color-safe)]" /> Local &amp; offline
            </h2>
            <ul className="flex flex-col gap-2 text-sm text-[color:var(--color-ink-dim)]">
              <li>No telemetry, no analytics, no crash reporting.</li>
              <li>Source code and scan results never leave this machine.</li>
              <li>
                Patch generation uses a{' '}
                <span className="font-mono text-[color:var(--color-accent-soft)]">local</span> Ollama
                model; no cloud LLM is contacted.
              </li>
              <li>
                Docker is used only as a throwaway sandbox to validate generated patches.
              </li>
            </ul>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
