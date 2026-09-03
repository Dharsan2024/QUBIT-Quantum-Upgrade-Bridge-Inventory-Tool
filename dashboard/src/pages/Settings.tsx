import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { LearningPanel } from '../components/LearningPanel';
import type { ThreatIntelSnapshot } from '../api/types';
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
  Radar,
  Clock,
  Brain,
  Info,
  SlidersHorizontal,
} from 'lucide-react';
import type { LlmProvider } from '../api/types';
import {
  fetchHealth,
  fetchHealthDeps,
  fetchLanguages,
  fetchThreatIntelConfig,
  fetchThreatIntelSnapshots,
  getToken,
  setToken,
  whoami,
  getApiBase,
  setApiBase,
  patchThreatIntelConfig,
  runThreatIntelCheckNow,
  reviewThreatIntelSnapshot,
  fetchLlmProviderConfig,
  fetchLlmProviderModels,
  patchLlmProviderConfig,
  verifyLlmProvider,
} from '../api/client';

/** Base URL presets for the external-provider fields. "Custom" leaves both blank for the user to
 *  fill in themselves (a company's own endpoint, or any other OpenAI-compatible server).
 *
 *  `recommended` is a genuine starting suggestion, not a hardcoded requirement — after saving,
 *  the Model field becomes a dropdown of what the provider LIVE reports it offers
 *  (`GET /llm-provider/models`), because free-tier lineups rotate and a list compiled into QUBIT
 *  would be wrong within months. Reasoning models are deliberately NOT recommended: QUBIT sends
 *  `think: false` and discards reasoning tokens (see `_ollama_generate_once`), so a reasoning
 *  model spends its output budget on text QUBIT throws away and the file comes back truncated. */
const LLM_PRESETS = {
  groq: {
    label: 'Groq (free)',
    baseUrl: 'https://api.groq.com/openai/v1',
    // Measured against Groq's live catalogue on a real key, on a structural RSA→ML-KEM rewrite —
    // the migration shape the local 7B model fails outright: gpt-oss-120b scored 6/6 in 3.6s,
    // gpt-oss-20b 5/6, qwen3.6-27b 4/6, groq/compound 5/6 but dropped most of the file.
    recommended: 'openai/gpt-oss-120b',
    why: 'a 120B model with a 131k-token context window — far beyond what this machine can host, answering in seconds rather than the ~23s a local call takes. The large window also means big files get a real patch instead of being routed to written guidance.',
    signupUrl: 'https://console.groq.com/keys',
  },
  openrouter: {
    label: 'OpenRouter (free)',
    baseUrl: 'https://openrouter.ai/api/v1',
    recommended: '',
    why: 'one key routes to many providers with automatic failover, but its free lineup rotates often — pick from the live list after saving.',
    signupUrl: 'https://openrouter.ai/keys',
  },
  custom: {
    label: 'Custom',
    baseUrl: '',
    recommended: '',
    why: 'your own endpoint — a company-internal vLLM/LM Studio server, Azure OpenAI, or anything else speaking the OpenAI chat-completions API.',
    signupUrl: '',
  },
} as const;
type LlmPreset = keyof typeof LLM_PRESETS;

/** One labelled readout row inside a HUD panel. */
function Row({
  icon,
  label,
  value,
  tone = 'var(--color-accent-soft)',
  valueTestId,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone?: string;
  valueTestId?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-[color:var(--edge)] py-2.5 last:border-b-0">
      <span className="label-caps flex items-center gap-2">
        {icon}
        {label}
      </span>
      <span className="font-mono text-sm" style={{ color: tone }} data-testid={valueTestId}>
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

  // Threat-intel: off by default, so both queries return instantly (a config row and an empty
  // snapshot list) even for a user who never opts in.
  const tiConfig = useQuery({ queryKey: ['threat-intel-config'], queryFn: fetchThreatIntelConfig });
  const tiSnapshots = useQuery({
    queryKey: ['threat-intel-snapshots'],
    queryFn: () => fetchThreatIntelSnapshots(10),
  });
  const [tiBusy, setTiBusy] = useState(false);

  const toggleThreatIntel = async () => {
    setTiBusy(true);
    try {
      await patchThreatIntelConfig({ enabled: !tiConfig.data?.enabled });
      await tiConfig.refetch();
    } finally {
      setTiBusy(false);
    }
  };

  const checkThreatIntelNow = async () => {
    setTiBusy(true);
    try {
      await runThreatIntelCheckNow();
      await Promise.all([tiConfig.refetch(), tiSnapshots.refetch()]);
    } finally {
      setTiBusy(false);
    }
  };

  const markSnapshotReviewed = async (id: string) => {
    await reviewThreatIntelSnapshot(id);
    await tiSnapshots.refetch();
  };

  // LLM provider: Ollama by default (byte-identical to today), an external OpenAI-compatible
  // endpoint on opt-in. Local edit state seeded from the saved config on first load, then the
  // user's own edits until they Save — refetching over an in-progress edit would be a worse bug
  // than a stale field.
  const llmConfig = useQuery({ queryKey: ['llm-provider-config'], queryFn: fetchLlmProviderConfig });
  const [llmProvider, setLlmProvider] = useState<LlmProvider>('ollama');
  const [llmPreset, setLlmPreset] = useState<LlmPreset>('custom');
  const [llmBaseUrl, setLlmBaseUrl] = useState('');
  const [llmModel, setLlmModel] = useState('');
  const [llmApiKey, setLlmApiKey] = useState('');
  const [llmBackupUrl, setLlmBackupUrl] = useState('');
  const [llmBackupModel, setLlmBackupModel] = useState('');
  const [llmBackupKey, setLlmBackupKey] = useState('');
  const [llmSeeded, setLlmSeeded] = useState(false);
  const [llmStatus, setLlmStatus] = useState<'idle' | 'checking' | 'ok' | 'fail'>('idle');
  const [llmDetail, setLlmDetail] = useState('');

  if (!llmSeeded && llmConfig.data) {
    setLlmSeeded(true);
    setLlmProvider(llmConfig.data.provider);
    setLlmBaseUrl(llmConfig.data.base_url ?? '');
    setLlmModel(llmConfig.data.model ?? '');
    setLlmBackupUrl(llmConfig.data.backup_base_url ?? '');
    setLlmBackupModel(llmConfig.data.backup_model ?? '');
  }

  // What the SAVED provider actually offers. Only fetched once a key is saved (an external
  // provider can't answer without one), and refetched after every save.
  const [llmModels, setLlmModels] = useState<string[]>([]);
  const [llmModelsError, setLlmModelsError] = useState('');

  const applyLlmPreset = (preset: LlmPreset) => {
    setLlmPreset(preset);
    setLlmBaseUrl(LLM_PRESETS[preset].baseUrl);
    setLlmModel(LLM_PRESETS[preset].recommended);
    setLlmModels([]);
    setLlmModelsError('');
  };

  const refreshLlmModels = async () => {
    try {
      const result = await fetchLlmProviderModels();
      setLlmModels(result.models);
      setLlmModelsError(result.error);
    } catch (e) {
      setLlmModels([]);
      setLlmModelsError(e instanceof Error ? e.message : 'could not read the model list');
    }
  };

  const saveAndVerifyLlmProvider = async () => {
    setLlmStatus('checking');
    try {
      await patchLlmProviderConfig({
        provider: llmProvider,
        base_url: llmProvider === 'openai-compatible' ? llmBaseUrl.trim() : undefined,
        model: llmProvider === 'openai-compatible' ? llmModel.trim() : undefined,
        // Omitted (not empty string) when left blank, so re-verifying an already-saved key
        // doesn't require retyping it every time.
        ...(llmApiKey.trim() ? { api_key: llmApiKey.trim() } : {}),
        ...(llmProvider === 'openai-compatible'
          ? {
              backup_base_url: llmBackupUrl.trim(),
              backup_model: llmBackupModel.trim(),
              ...(llmBackupKey.trim() ? { backup_api_key: llmBackupKey.trim() } : {}),
            }
          : {}),
      });
      await llmConfig.refetch();
      if (llmProvider === 'ollama') {
        setLlmStatus('ok');
        setLlmDetail('using the local Ollama model');
        await refreshLlmModels();
        return;
      }
      const result = await verifyLlmProvider();
      setLlmStatus(result.ok ? 'ok' : 'fail');
      setLlmDetail(result.detail);
      if (result.ok) {
        setLlmApiKey('');
        setLlmBackupKey('');
        // Pull the live catalogue now that the key is saved, so the Model field stops being a
        // guess and becomes a list of what this provider genuinely offers today.
        await refreshLlmModels();
      }
    } catch (e) {
      setLlmStatus('fail');
      setLlmDetail(e instanceof Error ? e.message : 'save failed');
    }
  };

  // Newest snapshot per source, for the compact per-source status list.
  const latestSnapshotBySource = new Map<string, ThreatIntelSnapshot>();
  for (const snap of tiSnapshots.data ?? []) {
    if (!latestSnapshotBySource.has(snap.source_id)) latestSnapshotBySource.set(snap.source_id, snap);
  }

  const verify = async () => {
    setToken(token.trim());
    setApiBase(apiBase.trim());
    setStatus('checking');
    try {
      const who = await whoami();
      // The team is named first: on a shared engine it is the fact that decides whether the
      // projects you are about to act on are yours.
      setDetail(`${who.tenant} · ${who.name} · scopes: ${who.scopes}`);
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
          What this window talks to and how patches get generated, then what the installation
          underneath it actually is.
        </p>
      </header>

      {/* Connection spans the width, then every other card flows in a balanced grid beneath it.
          This was a 3-column grid with Connection at col-span-2 and all SIX remaining cards
          stacked in the single narrow right column — so the column grew very tall while the two
          columns under Connection stayed empty, wasting most of a wide window. */}
      <div className="stagger flex flex-col gap-5">
        <h2 className="label-caps mt-1 flex items-center gap-2 text-[color:var(--color-ink-faint)]">
          <SlidersHorizontal className="h-3.5 w-3.5" />
          Configuration
        </h2>
        <div className="glass-card flex flex-col gap-5 p-6">
          <h2 className="flex items-center gap-2">
            <Server className="h-5 w-5 text-[color:var(--color-accent)]" /> Connection
          </h2>

          {/* Two fields side by side: at full width a single stacked input stretches across the
              whole window for a value that is rarely longer than a URL. */}
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
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
                Defaults to{' '}
                <span className="font-mono text-[color:var(--color-accent-soft)]">
                  VITE_API_BASE
                </span>
                . The desktop app starts this engine itself as a child process. Override here to
                point at a remote cluster.
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
                  className="glass-input min-w-0 flex-1 px-4 py-2.5"
                />
                <button onClick={verify} className="hud-btn shrink-0 px-5">
                  {status === 'checking' ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    'Save & verify'
                  )}
                </button>
              </div>
              <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
                Verifying reports the token's scopes and the team it belongs to — on a shared engine
                that is what tells you whose projects you are looking at.
              </p>
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

        {/* Which engine actually generates patches. Ollama (local, no key, no cost) is the
            default and stays fully functional with nothing configured here. Picking External
            opts into an OpenAI-compatible endpoint — a company's own model in production, or one
            of the two free hosted presets below for a machine that can't run a bigger local
            model. Ollama is never removed as an option: an external failure falls back to it
            automatically (see the note under Save & verify). */}
        <div className="glass-card flex flex-col gap-5 p-6" data-testid="llm-provider-card">
          <h2 className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-[color:var(--color-accent)]" /> LLM provider
          </h2>
          <p className="text-xs text-[color:var(--color-ink-faint)]">
            Which engine QUBIT calls to generate migration patches. Local Ollama needs no key and
            costs nothing; an external provider can be a stronger model — your own company's
            deployment in production, or a free hosted tier below. Ollama always stays available
            as an automatic fallback if the external provider is unreachable.
          </p>

          <div className="flex gap-2">
            {(['ollama', 'openai-compatible'] as const).map((p) => (
              <button
                key={p}
                onClick={() => setLlmProvider(p)}
                data-testid={`llm-provider-select-${p}`}
                className="hud-btn px-4"
                style={{
                  color: llmProvider === p ? 'var(--color-accent)' : 'var(--color-ink-faint)',
                  borderColor: llmProvider === p ? 'var(--color-accent)' : undefined,
                }}
              >
                {p === 'ollama' ? 'Local (Ollama)' : 'External (OpenAI-compatible)'}
              </button>
            ))}
          </div>

          {llmProvider === 'openai-compatible' && (
            <>
              <div>
                <span className="metric-label mb-2 block">Preset</span>
                <div className="flex flex-wrap gap-2">
                  {(Object.keys(LLM_PRESETS) as LlmPreset[]).map((key) => (
                    <button
                      key={key}
                      onClick={() => applyLlmPreset(key)}
                      data-testid={`llm-preset-${key}`}
                      className="hud-btn px-4"
                      style={{
                        color: llmPreset === key ? 'var(--color-accent)' : 'var(--color-ink-faint)',
                        borderColor: llmPreset === key ? 'var(--color-accent)' : undefined,
                      }}
                    >
                      {LLM_PRESETS[key].label}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
                  {LLM_PRESETS[llmPreset].why}
                </p>
                {LLM_PRESETS[llmPreset].signupUrl && (
                  <p className="mt-1 text-xs text-[color:var(--color-ink-faint)]">
                    No account yet? Free signup, no card:{' '}
                    <span className="font-mono text-[color:var(--color-accent-soft)]">
                      {LLM_PRESETS[llmPreset].signupUrl}
                    </span>
                  </p>
                )}
              </div>

              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <div>
                  <label htmlFor="llm-base-url" className="metric-label mb-2 block">
                    Base URL
                  </label>
                  <input
                    id="llm-base-url"
                    type="text"
                    value={llmBaseUrl}
                    onChange={(e) => setLlmBaseUrl(e.target.value)}
                    placeholder="https://api.example.com/v1"
                    className="glass-input w-full px-4 py-2.5"
                  />
                </div>
                <div>
                  <label htmlFor="llm-model" className="metric-label mb-2 block">
                    Model
                  </label>
                  {/* A free-text input backed by a datalist, not a bare <select>: the live list
                      is only readable AFTER a key is saved, and a select with nothing in it
                      would lock the user out of the very field they need to fill in first. */}
                  <input
                    id="llm-model"
                    type="text"
                    list="llm-model-options"
                    value={llmModel}
                    onChange={(e) => setLlmModel(e.target.value)}
                    placeholder="model id"
                    className="glass-input w-full px-4 py-2.5"
                    data-testid="llm-model-input"
                  />
                  <datalist id="llm-model-options">
                    {llmModels.map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                  <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
                    {llmModels.length > 0 ? (
                      <>
                        {llmModels.length} models offered by this provider — click the field to
                        pick one.
                        {llmModel && !llmModels.includes(llmModel) && (
                          <span className="text-[color:var(--color-warn)]">
                            {' '}
                            {llmModel} is not in that list; it may have been delisted.
                          </span>
                        )}
                      </>
                    ) : llmModelsError ? (
                      llmModelsError
                    ) : (
                      'Save & verify below to load this provider’s live model list.'
                    )}
                  </p>
                </div>
              </div>

              <div>
                <label htmlFor="llm-api-key" className="metric-label mb-2 block">
                  API key
                </label>
                <input
                  id="llm-api-key"
                  type="password"
                  value={llmApiKey}
                  onChange={(e) => setLlmApiKey(e.target.value)}
                  placeholder={
                    llmConfig.data?.api_key_configured
                      ? `configured — ends in ${llmConfig.data.api_key_last4 ?? '????'} (leave blank to keep it)`
                      : 'paste your API key'
                  }
                  className="glass-input w-full px-4 py-2.5"
                />
              </div>

              {/* A second endpoint, tried before falling back to local Ollama. This is not
                  redundancy for its own sake: a free tier's binding constraint is its per-minute
                  TOKEN allowance, and one large file can exhaust a whole minute — measured, Groq's
                  free tier allows 8,000 tokens/request. A second key on a different provider
                  raises the real ceiling with no new code path. */}
              <div className="rounded-[3px] border border-[color:var(--edge)] p-4">
                <span className="label-caps">Backup provider (optional)</span>
                <p className="mt-1 mb-3 text-xs text-[color:var(--color-ink-faint)]">
                  Tried when the primary refuses a request — free tiers cap tokens per minute and
                  requests per day, and one large file can spend a whole minute&apos;s allowance. A
                  second key on a different provider raises that ceiling. Local Ollama stays
                  underneath both.
                </p>
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <div>
                    <label htmlFor="llm-backup-url" className="metric-label mb-2 block">
                      Backup base URL
                    </label>
                    <input
                      id="llm-backup-url"
                      type="text"
                      value={llmBackupUrl}
                      onChange={(e) => setLlmBackupUrl(e.target.value)}
                      placeholder="https://api.cerebras.ai/v1"
                      className="glass-input w-full px-4 py-2.5"
                    />
                  </div>
                  <div>
                    <label htmlFor="llm-backup-model" className="metric-label mb-2 block">
                      Backup model
                    </label>
                    <input
                      id="llm-backup-model"
                      type="text"
                      value={llmBackupModel}
                      onChange={(e) => setLlmBackupModel(e.target.value)}
                      placeholder="gpt-oss-120b"
                      className="glass-input w-full px-4 py-2.5"
                    />
                  </div>
                </div>
                <div className="mt-4">
                  <label htmlFor="llm-backup-key" className="metric-label mb-2 block">
                    Backup API key
                  </label>
                  <input
                    id="llm-backup-key"
                    type="password"
                    value={llmBackupKey}
                    onChange={(e) => setLlmBackupKey(e.target.value)}
                    placeholder={
                      llmConfig.data?.backup_api_key_configured
                        ? `configured — ends in ${llmConfig.data.backup_api_key_last4 ?? '????'} (leave blank to keep it)`
                        : 'paste a second provider’s API key'
                    }
                    className="glass-input w-full px-4 py-2.5"
                    data-testid="llm-backup-key-input"
                  />
                  {llmConfig.data?.backup_context_tokens ? (
                    <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
                      Backup allowance:{' '}
                      {llmConfig.data.backup_context_tokens.toLocaleString()} tokens/request.
                    </p>
                  ) : null}
                </div>
              </div>
            </>
          )}

          <div>
            <button
              onClick={saveAndVerifyLlmProvider}
              className="hud-btn px-5"
              data-testid="llm-provider-save-verify"
            >
              {llmStatus === 'checking' ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                'Save & verify'
              )}
            </button>
            <p className="mt-2 text-xs text-[color:var(--color-ink-faint)]">
              {llmProvider === 'openai-compatible'
                ? "Verifying makes one cheap call to confirm the endpoint and key work — it never spends a generation. If a real migration's external call fails later (outage, rate limit, bad key), QUBIT automatically retries that attempt on the local Ollama model instead of failing it."
                : 'Local Ollama is active — nothing external is contacted.'}
            </p>
          </div>

          {llmStatus === 'ok' && (
            <div
              className="flex items-center gap-2 rounded-[3px] border border-[color:var(--color-safe)]/40 bg-[color:var(--color-safe)]/8 px-4 py-2.5 font-mono text-sm text-[color:var(--color-safe)]"
              data-testid="llm-provider-status-ok"
            >
              <Check className="h-4 w-4" /> {llmDetail}
            </div>
          )}

          {/* The context window is not trivia: QUBIT routes a finding to written guidance instead
              of a patch when the file cannot fit it, so this number is the difference between a
              large file getting a real rewrite and getting advice. */}
          {llmConfig.data?.context_tokens ? (
            <Row
              icon={<Brain className="h-3.5 w-3.5" />}
              label="Context window"
              value={`${llmConfig.data.context_tokens.toLocaleString()} tokens`}
              valueTestId="llm-context-tokens"
            />
          ) : null}
          {llmStatus === 'fail' && (
            <div
              className="flex items-center gap-2 rounded-[3px] border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 px-4 py-2.5 font-mono text-sm text-[color:var(--color-danger)]"
              data-testid="llm-provider-status-fail"
            >
              <XCircle className="h-4 w-4" /> {llmDetail}
            </div>
          )}
        </div>

        {/* `items-start` so a short card keeps its own height instead of being stretched to match
            the tallest in its row — Threat intelligence is several times the height of Engine. */}
      {/* Grouped with Connection and LLM provider rather than with the read-only status
          cards below: it is the third thing on this page with a control that changes behaviour,
          and it was the odd one out sitting among Engine, Language coverage and Updates. */}
        <div className="glass-card p-6" data-testid="threat-intel-card">
          <h2 className="mb-1 flex items-center gap-2">
            <Radar className="h-5 w-5 text-[color:var(--color-accent)]" /> Threat intelligence
          </h2>
          <p className="mb-3 text-xs text-[color:var(--color-ink-faint)]">
            Off by default. When enabled, checks a fixed, curated set of NIST PQC reference pages
            for changes — nothing about your code or scans is ever sent. A changed source is
            staged below for you to read; it never auto-updates the CRQC timeline or Mosca
            parameters on its own.
          </p>

          <div className="mb-3 flex items-center justify-between gap-3">
            <span className="label-caps">Automatic checks</span>
            <button
              onClick={toggleThreatIntel}
              disabled={tiBusy || tiConfig.isLoading}
              className="hud-btn px-4"
              data-testid="threat-intel-toggle"
              style={{
                color: tiConfig.data?.enabled ? 'var(--color-safe)' : 'var(--color-ink-faint)',
              }}
            >
              {tiConfig.data?.enabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          <Row
            icon={<Clock className="h-3.5 w-3.5" />}
            label="Last checked"
            value={
              tiConfig.data?.last_checked_at
                ? new Date(tiConfig.data.last_checked_at).toLocaleString()
                : 'never'
            }
            valueTestId="threat-intel-last-checked"
          />
          <Row
            icon={<RefreshCw className="h-3.5 w-3.5" />}
            label="Interval"
            value={`every ${tiConfig.data?.check_interval_hours ?? 24}h`}
          />

          <button
            onClick={checkThreatIntelNow}
            disabled={tiBusy}
            className="hud-btn mt-3 w-full justify-center"
            data-testid="threat-intel-check-now"
          >
            {tiBusy ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Radar className="h-3.5 w-3.5" />
            )}
            Check now
          </button>

          <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
            {(tiConfig.data?.sources ?? []).map((source) => {
              const snap = latestSnapshotBySource.get(source.id);
              const needsReview = Boolean(snap?.changed_from_previous && !snap.reviewed);
              return (
                <div
                  key={source.id}
                  data-testid={`threat-intel-source-${source.id}`}
                  className="rounded-[3px] border border-[color:var(--edge)] px-3 py-2 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-[color:var(--color-ink)]">{source.label}</span>
                    {needsReview && (
                      <span className="rounded-[3px] bg-[color:var(--color-warn)]/15 px-1.5 py-0.5 text-[10px] text-[color:var(--color-warn)]">
                        changed
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-[color:var(--color-ink-faint)]">
                    {snap
                      ? snap.fetch_error
                        ? `fetch failed: ${snap.fetch_error}`
                        : `checked ${new Date(snap.fetched_at).toLocaleString()}`
                      : 'not checked yet'}
                  </p>
                  {needsReview && snap && (
                    <button
                      onClick={() => markSnapshotReviewed(snap.id)}
                      data-testid={`threat-intel-review-${source.id}`}
                      className="mt-1.5 text-[color:var(--color-accent-soft)] underline"
                    >
                      Mark reviewed
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <h2 className="label-caps mt-1 flex items-center gap-2 text-[color:var(--color-ink-faint)]">
          <Info className="h-3.5 w-3.5" />
          This installation
        </h2>
        <div className="grid grid-cols-1 items-start gap-5 md:grid-cols-2 xl:grid-cols-3">
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

          {/* 19 grammar chips wrap badly in a third of the width; two columns lets them breathe. */}
          <div className="glass-card p-6 md:col-span-2 xl:col-span-2">
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

          {/* Same component as the Migrations tab (../components/LearningPanel) — the standing
              claim that QUBIT keeps getting better with use belongs beside the offline/local
              guarantees below, not just embedded in an active run's page. */}
          {/* Its five stat tiles sit in one row; a single column squeezes them to two characters. */}
          <div className="md:col-span-2 xl:col-span-2">
            <LearningPanel />
          </div>

          <div className="glass-card p-6">
            <h2 className="mb-3 flex items-center gap-2">
              <WifiOff className="h-5 w-5 text-[color:var(--color-safe)]" /> Local &amp; offline
            </h2>
            <ul className="flex flex-col gap-2 text-sm text-[color:var(--color-ink-dim)]">
              <li>No telemetry, no analytics, no crash reporting.</li>
              <li>Source code and scan results never leave this machine.</li>
              <li>
                {llmConfig.data?.provider === 'openai-compatible' ? (
                  <>
                    Patch generation is currently configured to use an external LLM at{' '}
                    <span className="font-mono text-[color:var(--color-accent-soft)]">
                      {llmConfig.data.base_url}
                    </span>{' '}
                    — a deliberate opt-in exception you configured in the LLM provider card above.
                    Local Ollama remains the automatic fallback if it's unreachable.
                  </>
                ) : (
                  <>
                    Patch generation uses a{' '}
                    <span className="font-mono text-[color:var(--color-accent-soft)]">local</span>{' '}
                    Ollama model; no cloud LLM is contacted.
                  </>
                )}
              </li>
              <li>
                Docker is used only as a throwaway sandbox to validate generated patches.
              </li>
              <li>
                One opt-in exception: Threat intelligence above, off unless you enable it.
              </li>
            </ul>
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
