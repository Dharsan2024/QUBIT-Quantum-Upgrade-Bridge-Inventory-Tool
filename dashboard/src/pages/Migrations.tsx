import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { ProjectGrid } from '../components/ProjectGrid';
import { ProjectScopeBar } from '../components/ProjectScopeBar';
import { useActiveScan } from '../hooks/useActiveScan';
import { useUiStore } from '../stores/ui';
import {
  Terminal,
  RefreshCw,
  Play,
  Check,
  X,
  Loader2,
  ChevronDown,
  ChevronRight,
  Wand2,
  GitFork,
  ShieldCheck,
  ShieldAlert,
  List,
  AlertTriangle,
  FileCode2,
  Clock3,
  Layers,
  Lightbulb,
} from 'lucide-react';
import {
  adviseTask,
  createPlan,
  fetchPlanGraph,
  fetchPlanQueue,
  fetchPlans,
  fetchTaskGovernance,
  fetchTaskPatches,
  generatePatch,
  reviewPatch,
} from '../api/client';
import type { MigrationPlan, MigrationTask } from '../api/types';
import { displayAlgorithm } from '../lib/assetLabels';

function StateChip({ state }: { state: string }) {
  const cls =
    state === 'ready'
      ? 'chip chip-info'
      : state === 'applied' || state === 'done' || state === 'approved'
        ? 'chip chip-safe'
        : state === 'failed'
          ? 'chip chip-danger'
          : 'chip chip-warn';
  return <span className={cls}>{state.replace(/_/g, ' ')}</span>;
}

function shortPath(p: string | null, segments = 2): string {
  if (!p) return '—';
  return p.split(/[\\/]/).slice(-segments).join('/');
}

function TaskRow({ task }: { task: MigrationTask }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [generator, setGenerator] = useState<'auto' | 'llm' | 'template'>('auto');

  const { data: patches } = useQuery({
    queryKey: ['patches', task.id],
    queryFn: () => fetchTaskPatches(task.id),
    enabled: open,
  });

  const { data: governance } = useQuery({
    queryKey: ['governance', task.id],
    queryFn: () => fetchTaskGovernance(task.id),
    enabled: open,
  });

  const gen = useMutation({
    mutationFn: () => generatePatch(task.id, generator),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['patches', task.id] });
      qc.invalidateQueries({ queryKey: ['migrate-queue'] });
      setOpen(true);
    },
  });

  // Guidance for a finding no patch can be produced for. The queue's honest answer for those is
  // "manual change", which names an algorithm and a line and stops — this is the other half.
  const advise = useMutation({
    mutationFn: (force: boolean) => adviseTask(task.id, force),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['migrate-queue'] }),
  });

  const review = useMutation({
    mutationFn: ({ patchId, approve }: { patchId: string; approve: boolean }) =>
      reviewPatch(patchId, approve),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['patches', task.id] });
      qc.invalidateQueries({ queryKey: ['governance', task.id] });
      qc.invalidateQueries({ queryKey: ['migrate-queue'] });
    },
  });

  const latest = patches?.[0];
  const COLS = 8;

  return (
    <>
      <tr className="data-row">
        <td className="px-4 py-3">
          <button
            onClick={() => setOpen(!open)}
            className="text-[color:var(--color-ink-faint)] hover:text-[color:var(--color-accent)]"
            aria-label={open ? 'Collapse task' : 'Expand task'}
          >
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        </td>
        <td className="px-4 py-3">
          <div
            className="text-xs text-[color:var(--color-accent-soft)]"
            title={task.file_path ?? undefined}
          >
            {shortPath(task.file_path)}
            {task.line ? `:${task.line}` : ''}
          </div>
          {/* Provenance and purpose, which the queue previously could not show at all — a config
              finding and a certificate are handled completely differently from a call site. */}
          <div className="metric-label mt-1 flex flex-wrap gap-x-2">
            {task.source_scanner && <span>{task.source_scanner}</span>}
            {task.usage_context && task.usage_context !== 'unknown' && (
              <span>· {task.usage_context}</span>
            )}
            {task.sensitivity && task.sensitivity !== 'unknown' && <span>· {task.sensitivity}</span>}
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="chip chip-danger" title={task.algorithm ?? undefined}>
            {task.algorithm ? displayAlgorithm(task.algorithm) : '?'}
          </span>
          {task.key_size ? <span className="metric-label ml-2">{task.key_size} bit</span> : null}
        </td>
        <td className="px-4 py-3 text-xs">
          {task.rule_id ? (
            <span className="flex flex-col gap-1">
              <span className="font-mono text-[color:var(--color-ink-dim)]">{task.rule_id}</span>
              <span
                className={task.has_codemod ? 'chip chip-safe' : 'chip chip-info'}
                title={
                  task.has_codemod
                    ? 'Deterministic codemod — runs offline and produces the same diff every time.'
                    : 'No codemod for this rule; the patch is written by the local Ollama model and must be reviewed.'
                }
              >
                {task.has_codemod ? 'automatic' : 'LLM-assisted'}
              </span>
            </span>
          ) : (
            <span className="text-[color:var(--color-ink-faint)]">no migration rule</span>
          )}
        </td>
        <td className="px-4 py-3 text-xs tabular-nums text-[color:var(--color-accent)]">
          {task.priority.toFixed(3)}
        </td>
        <td className="px-4 py-3 text-xs tabular-nums text-[color:var(--color-ink-dim)]">
          {task.effort_hours_low != null && task.effort_hours_high != null
            ? `${task.effort_hours_low}–${task.effort_hours_high} h`
            : `${task.effort_points} pt`}
        </td>
        <td className="px-4 py-3">
          <StateChip state={task.state} />
        </td>
        <td className="px-4 py-3 text-right">
          {task.rule_id && task.state === 'ready' && (
            <span className="inline-flex items-center gap-2">
              {/* `template` is only offered when the rule actually has a codemod. Offering it
                  unconditionally meant choosing it on any of the ten LLM-only rules returned
                  422 "has no codemod fallback" — after the click. */}
              <select
                value={generator}
                onChange={(e) => setGenerator(e.target.value as 'auto' | 'llm' | 'template')}
                className="glass-input px-2 py-1.5 text-xs"
                title={
                  task.has_codemod
                    ? 'auto = the deterministic codemod; llm = local Ollama model'
                    : 'This rule has no codemod, so generation goes to the local Ollama model.'
                }
              >
                <option value="auto">auto</option>
                {task.has_codemod && <option value="template">template</option>}
                <option value="llm">llm</option>
              </select>
              <button
                onClick={() => gen.mutate()}
                disabled={gen.isPending}
                className="hud-btn px-3 py-1.5"
              >
                {gen.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Wand2 className="h-3.5 w-3.5" />
                )}
                Generate
              </button>
            </span>
          )}
          {!task.rule_id && (
            <span
              className="text-xs text-[color:var(--color-ink-faint)]"
              title="No migration rule matches this asset's language and algorithm, so QUBIT cannot propose a patch for it. It still counts towards the plan and its effort estimate."
            >
              manual change
            </span>
          )}
        </td>
      </tr>
      {gen.isError && (
        <tr>
          <td colSpan={COLS} className="px-4 pb-2">
            <div className="rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
              {gen.error instanceof Error ? gen.error.message : 'generation failed'}
            </div>
          </td>
        </tr>
      )}
      {open && (
        <tr>
          <td colSpan={COLS} className="bg-black/15 px-6 py-4">
            <div className="mb-3 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/30 p-3">
                <div className="metric-label mb-1">Full path</div>
                <div className="break-all font-mono text-[color:var(--color-accent-soft)]">
                  {task.file_path ?? '—'}
                  {task.line ? `:${task.line}` : ''}
                </div>
              </div>
              <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/30 p-3">
                <div className="metric-label mb-1">Risk / Mosca margin</div>
                <div className="font-mono text-[color:var(--color-accent)]">
                  {task.risk_score != null ? task.risk_score.toFixed(3) : '—'}
                  {task.mosca_margin_years != null && (
                    <span className="ml-2 text-[color:var(--color-ink-dim)]">
                      {task.mosca_margin_years > 0 ? '+' : ''}
                      {task.mosca_margin_years.toFixed(1)} y
                    </span>
                  )}
                </div>
              </div>
              <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/30 p-3">
                <div className="metric-label mb-1">Asset type</div>
                <div className="text-[color:var(--color-ink-dim)]">
                  {task.asset_type ?? '—'}
                  {task.source_scanner ? ` · via ${task.source_scanner} scanner` : ''}
                </div>
              </div>
              <div className="rounded-[3px] border border-[color:var(--edge)] bg-black/30 p-3">
                <div className="metric-label mb-1">Effort drivers</div>
                <div className="text-[color:var(--color-ink-dim)]">
                  {task.effort_drivers.length ? task.effort_drivers.join(', ') : 'baseline'}
                </div>
              </div>
            </div>
            {governance && (
              <div className="mb-3 flex items-center justify-between rounded-lg border border-[color:var(--glass-border)] bg-black/20 px-3 py-2 text-xs">
                <div className="flex items-center gap-2">
                  {governance.gate_status === 'passed' ? (
                    <ShieldCheck className="h-4 w-4 text-[color:var(--color-safe)]" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-amber-400" />
                  )}
                  <span className="font-medium text-[color:var(--color-ink)]">
                    Governance Policy:
                  </span>
                  <span className="text-[color:var(--color-ink-dim)]">
                    {governance.current_approvals} / {governance.required_approvals} approvals (
                    {governance.sensitivity} sensitivity)
                  </span>
                </div>
                <span
                  className={governance.gate_status === 'passed' ? 'chip chip-safe' : 'chip chip-warn'}
                >
                  {governance.gate_status}
                </span>
              </div>
            )}
            {!patches?.length && (
              <div className="text-xs text-[color:var(--color-ink-faint)]">
                {task.rule_id
                  ? 'No patches yet — generate one.'
                  : 'No migration rule matches this asset, so no patch can be generated. Change it by hand, then rescan to confirm it is gone.'}
              </div>
            )}

            {/* Migration guidance. Offered on every task, but it is the answer for the ones that
                cannot be patched: what this code does, why it is a problem, what to change in THIS
                file, what it breaks, and how to prove it is gone. Written by the local model from
                the real source — two findings of the same algorithm in different files get
                different advice. */}
            <div className="mt-3 flex flex-col gap-2 border-t border-[color:var(--edge)] pt-3">
              <div className="flex flex-wrap items-center gap-3">
                <span className="label-caps flex items-center gap-1.5 text-[color:var(--color-accent-2)]">
                  <Lightbulb className="h-3.5 w-3.5" />
                  How to migrate this
                </span>
                <button
                  onClick={() => advise.mutate(Boolean(task.advice_text))}
                  disabled={advise.isPending}
                  className="hud-btn hud-btn-ghost px-3 py-1.5"
                  data-testid="advise-task"
                  title="Asks the local Ollama model to read this file and explain the change. Nothing leaves the machine."
                >
                  {advise.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Lightbulb className="h-3.5 w-3.5" />
                  )}
                  {task.advice_text ? 'Regenerate' : 'Explain'}
                </button>
                {task.advice_model && (
                  <span className="metric-label">written by {task.advice_model}</span>
                )}
              </div>

              {advise.isError && (
                <div className="rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                  {advise.error instanceof Error ? advise.error.message : 'could not generate advice'}
                </div>
              )}

              {task.advice_text ? (
                <div className="whitespace-pre-wrap rounded-[3px] border border-[color:var(--edge)] bg-black/30 p-3 text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                  {task.advice_text}
                </div>
              ) : (
                !advise.isPending && (
                  <p className="text-xs text-[color:var(--color-ink-faint)]">
                    Reads this file with the local model and explains what to change, what it
                    breaks, and how to verify it. Requires Ollama.
                  </p>
                )
              )}
            </div>
            {latest && (
              <div className="flex flex-col gap-3">
                <div className="flex flex-wrap items-center gap-3 text-xs">
                  <StateChip state={latest.status} />
                  <span className="font-mono text-[color:var(--color-ink-faint)]">
                    {latest.generator}
                    {latest.model_name ? ` (${latest.model_name})` : ''} ·{' '}
                    {latest.file_path.split(/[\\/]/).pop()}
                  </span>
                  {latest.validation?.stages &&
                    Object.entries(latest.validation.stages).map(([name, s]) => (
                      <span
                        key={name}
                        title={s.detail}
                        className={
                          s.status === 'pass'
                            ? 'text-[color:var(--color-safe)]'
                            : s.status === 'fail'
                              ? 'text-[color:var(--color-danger)]'
                              : 'text-[color:var(--color-ink-faint)]'
                        }
                      >
                        {name}:{s.status}
                      </span>
                    ))}
                  {latest.status === 'proposed' && (
                    <span className="ml-auto flex gap-2">
                      <button
                        onClick={() => review.mutate({ patchId: latest.id, approve: true })}
                        disabled={review.isPending}
                        className="hud-btn px-3 py-1.5"
                        style={{
                          borderColor: 'var(--color-safe)',
                          color: 'var(--color-safe)',
                          background: 'color-mix(in srgb, var(--color-safe) 12%, transparent)',
                        }}
                      >
                        <Check className="h-3.5 w-3.5" /> Approve
                      </button>
                      <button
                        onClick={() => review.mutate({ patchId: latest.id, approve: false })}
                        disabled={review.isPending}
                        className="hud-btn px-3 py-1.5"
                        style={{
                          borderColor: 'var(--color-danger)',
                          color: 'var(--color-danger)',
                          background: 'color-mix(in srgb, var(--color-danger) 12%, transparent)',
                        }}
                      >
                        <X className="h-3.5 w-3.5" /> Reject
                      </button>
                    </span>
                  )}
                  {latest.status === 'approved' && (
                    <span className="ml-auto font-mono text-[color:var(--color-ink-faint)]">
                      apply via: qubit migrate apply
                    </span>
                  )}
                </div>
                <pre className="max-h-64 overflow-auto rounded-lg border border-[color:var(--glass-border)] bg-black/40 p-3 font-mono text-xs leading-relaxed">
                  {latest.diff_text.split('\n').map((l, i) => (
                    <div
                      key={i}
                      className={
                        l.startsWith('+') && !l.startsWith('+++')
                          ? 'text-emerald-300'
                          : l.startsWith('-') && !l.startsWith('---')
                            ? 'text-rose-300'
                            : 'text-[color:var(--color-ink-dim)]'
                      }
                    >
                      {l}
                    </div>
                  ))}
                </pre>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

/** Tasks grouped by the file they live in.
 *
 *  A flat 127-row queue is a list of findings; the unit of work is a file, because one editor
 *  session fixes every finding in it. This view is what turns the plan into something you can hand
 *  to somebody. */
function ByFileView({ tasks }: { tasks: MigrationTask[] }) {
  const groups = useMemo(() => {
    const map = new Map<string, MigrationTask[]>();
    for (const t of tasks) {
      const key = t.file_path ?? '(no file)';
      const list = map.get(key) ?? [];
      list.push(t);
      map.set(key, list);
    }
    return [...map.entries()]
      .map(([file, list]) => ({
        file,
        tasks: [...list].sort((a, b) => (a.line ?? 0) - (b.line ?? 0)),
        maxPriority: Math.max(...list.map((t) => t.priority)),
        hours: list.reduce((n, t) => n + (t.effort_hours_high ?? 0), 0),
        automatable: list.filter((t) => t.rule_id).length,
      }))
      .sort((a, b) => b.tasks.length - a.tasks.length || b.maxPriority - a.maxPriority);
  }, [tasks]);

  if (!groups.length) {
    return (
      <div className="glass-card p-10 text-center text-sm text-[color:var(--color-ink-faint)]">
        Nothing to group — the queue is empty.
      </div>
    );
  }

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      {groups.map((g) => (
        <div key={g.file} className="glass-card flex flex-col gap-3 p-5">
          <div className="flex items-start justify-between gap-3 border-b border-[color:var(--edge)] pb-2.5">
            <div className="min-w-0">
              <div
                className="truncate font-mono text-sm text-[color:var(--color-accent-soft)]"
                title={g.file}
              >
                {shortPath(g.file, 3)}
              </div>
              <div className="metric-label mt-1">
                {g.tasks.length} finding{g.tasks.length === 1 ? '' : 's'} · {g.automatable} with
                a migration rule · up to {g.hours} h
              </div>
            </div>
            <FileCode2 className="h-4 w-4 flex-none text-[color:var(--color-ink-faint)]" />
          </div>
          <div className="flex flex-col gap-1.5">
            {g.tasks.map((t) => (
              <div
                key={t.id}
                className="flex items-center justify-between gap-3 rounded-[3px] border border-[color:var(--edge)] bg-black/30 px-3 py-2 text-xs"
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span className="w-12 flex-none font-mono text-[color:var(--color-ink-faint)]">
                    {t.line ? `L${t.line}` : '—'}
                  </span>
                  <span className="chip chip-danger">
                    {t.algorithm ? displayAlgorithm(t.algorithm) : '?'}
                  </span>
                  {t.usage_context && t.usage_context !== 'unknown' && (
                    <span className="metric-label truncate">{t.usage_context}</span>
                  )}
                </span>
                <span className="flex flex-none items-center gap-3">
                  <span className="tabular-nums text-[color:var(--color-accent)]">
                    {t.priority.toFixed(3)}
                  </span>
                  {t.rule_id ? (
                    <span className="chip chip-info" title={t.rule_id}>
                      auto
                    </span>
                  ) : (
                    <span className="chip chip-warn">manual</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function DependencyGraphView({ planId }: { planId: string }) {
  const {
    data: graph,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['plan-graph', planId],
    queryFn: () => fetchPlanGraph(planId),
  });

  if (isLoading) {
    return (
      <div className="glass-card flex items-center justify-center gap-3 p-12 text-sm text-[color:var(--color-ink-dim)]">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading dependency graph…
      </div>
    );
  }

  if (isError || !graph) {
    return (
      <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
        {error instanceof Error ? error.message : 'Failed to load graph'}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="glass-card flex flex-wrap items-center justify-between gap-4 px-5 py-4">
        <div className="flex flex-wrap items-center gap-6">
          {[
            { n: graph.nodes.length, l: 'Assets', c: 'var(--color-accent)' },
            { n: graph.edges.length, l: 'Dependencies', c: 'var(--color-accent-2)' },
            { n: graph.units.length, l: 'Execution units', c: 'var(--color-safe)' },
          ].map((s) => (
            <div key={s.l} className="flex items-baseline gap-2">
              <span className="metric text-[1.5rem]" style={{ color: s.c }}>
                {s.n}
              </span>
              <span className="metric-label">{s.l}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-4">
          <span className="chip chip-safe">Sequential</span>
          <span className="chip chip-warn">Cycle / parallel unit</span>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2 2xl:grid-cols-3">
        {graph.units.map((unit, idx) => (
          <div
            key={String(unit.unit_id)}
            className="glass-card flex flex-col gap-3 p-5"
            style={{
              borderLeft: `3px solid ${unit.is_cycle ? 'var(--color-warn)' : 'var(--color-accent)'}`,
            }}
          >
            <div className="flex items-center justify-between border-b border-[color:var(--edge)] pb-2.5">
              <span className="label-caps text-[color:var(--color-accent)]">
                Unit #{idx + 1} · {unit.members.length} member{unit.members.length === 1 ? '' : 's'}
              </span>
              {unit.is_cycle && <span className="chip chip-warn">Cycle condensation</span>}
            </div>
            <div className="flex flex-col gap-2">
              {unit.members.map((memberId) => {
                const node = graph.nodes.find((n) => n.id === memberId || n.asset_id === memberId);
                const edgesFrom = graph.edges.filter((e) => e.source === memberId);
                return (
                  <div
                    key={memberId}
                    className="rounded-[3px] border border-[color:var(--edge)] bg-black/40 p-3 transition-colors hover:border-[color:var(--edge-lume)]"
                  >
                    <div className="flex items-center justify-between gap-3 font-mono text-xs">
                      <span
                        className="truncate text-[color:var(--color-accent-soft)]"
                        title={node?.algorithm}
                      >
                        {node?.algorithm ? displayAlgorithm(node.algorithm) : 'Asset'}
                      </span>
                      <span className="flex-none text-[color:var(--color-ink-faint)]">
                        rank #{node?.order_index ?? idx}
                      </span>
                    </div>
                    {node?.usage_context && (
                      <div className="metric-label mt-1.5">Context · {node.usage_context}</div>
                    )}
                    {edgesFrom.length > 0 && (
                      <div className="mt-2 border-t border-[color:var(--edge)] pt-2 font-mono text-[11px] text-[color:var(--color-accent-2)]">
                        → depends on {edgesFrom.map((e) => e.target.slice(0, 8)).join(', ')} (
                        {edgesFrom[0].kind ?? 'dependency'})
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        {graph.units.length === 0 && (
          <div className="glass-card col-span-full p-10 text-center text-sm text-[color:var(--color-ink-faint)]">
            No graph dependencies detected.
          </div>
        )}
      </div>
    </div>
  );
}

/** The plan's headline numbers — what it covers, how big it is, and how much of it QUBIT can do
 *  for you. The three-way split is the part that changes how the work is planned: a task with
 *  no codemod has to go through the local model, and one with no rule at all has to be changed
 *  by hand whatever the app says. */
function PlanSummary({ plan }: { plan: MigrationPlan }) {
  const s = plan.stats;
  const tasks = s.tasks ?? 0;
  // Three states, not one. The tile here used to read "Codemod available" over a count of tasks
  // that matched ANY rule — but only 5 of the 14 rules carry a deterministic codemod, the rest
  // route to a local LLM. On a real polyglot project that overstated what the app can do offline
  // by more than 2x (110 claimed against 46 actual).
  const withCodemod = s.with_codemod ?? 0;
  const withLlm = s.with_llm_rule ?? 0;
  const manual = s.manual ?? Math.max(0, tasks - (s.automatable ?? 0));
  const tiles = [
    { label: 'Tasks', value: String(tasks), color: 'var(--color-accent)' },
    {
      label: 'Automatic patch',
      value: tasks ? `${withCodemod} / ${tasks}` : '—',
      color: 'var(--color-safe)',
      hint: 'Deterministic codemod — runs offline, same diff every time.',
    },
    {
      label: 'LLM-assisted',
      value: String(withLlm),
      color: 'var(--color-accent-2)',
      hint: 'A rule with a target and constraints, but the patch is written by the local Ollama model and must be reviewed.',
    },
    {
      label: 'Manual',
      value: String(manual),
      color: 'var(--color-warn)',
      hint: 'No migration rule matches this asset — change it by hand, then rescan to confirm it is gone.',
    },
    {
      label: 'Estimated effort',
      value:
        s.effort_hours_low != null && s.effort_hours_high != null
          ? `${s.effort_hours_low}–${s.effort_hours_high} h`
          : '—',
      color: 'var(--color-ink-dim)',
      hint: 'Sum of the per-task additive estimate (doc 03 §6.2): rule kind, language, data-compatibility class and cross-service edges.',
    },
  ];
  const byAlgorithm = Object.entries(s.by_algorithm ?? {});

  return (
    <div className="flex flex-col gap-4">
      <div className="glass-card grid grid-cols-2 gap-5 p-5 lg:grid-cols-5">
        {tiles.map((t) => (
          <div key={t.label} title={t.hint}>
            <div className="metric text-[1.7rem] leading-none" style={{ color: t.color }}>
              {t.value}
            </div>
            <div className="metric-label mt-1.5">{t.label}</div>
          </div>
        ))}
      </div>
      {byAlgorithm.length > 0 && (
        <div className="glass-card flex flex-col gap-3 p-5">
          <div className="label-caps flex items-center gap-2 text-[color:var(--color-accent)]">
            <Layers className="h-3.5 w-3.5" /> What this plan replaces
          </div>
          <div className="flex flex-wrap gap-2">
            {byAlgorithm.map(([algorithm, count]) => (
              <span
                key={algorithm}
                className="flex items-center gap-2 rounded-[3px] border border-[color:var(--edge)] bg-black/40 px-2.5 py-1.5 text-xs"
                title={algorithm}
              >
                <span className="text-[color:var(--color-danger)]">
                  {displayAlgorithm(algorithm)}
                </span>
                <span className="tabular-nums text-[color:var(--color-ink-faint)]">×{count}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** One project's migration state. */
function ProjectMigration({ projectId }: { projectId: string }) {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<'queue' | 'files' | 'graph'>('queue');
  const { activeScan, projectScans } = useActiveScan();

  const plansQ = useQuery({
    queryKey: ['migrate-plans', projectId],
    queryFn: () => fetchPlans(projectId),
  });

  // Newest plan for THIS project. Previously this took the newest plan in the entire installation,
  // which is why a freshly scanned project showed another project's queue — or, if that plan had
  // been built when nothing was vulnerable, the message "no vulnerable assets in scope" over a
  // project full of them.
  const plan = plansQ.data?.[0];
  const latestScan = projectScans[0];
  const planIsStale = Boolean(
    plan && latestScan && new Date(latestScan.created_at) > new Date(plan.created_at),
  );

  const queueQ = useQuery({
    queryKey: ['migrate-queue', plan?.id],
    queryFn: () => fetchPlanQueue(plan!.id),
    enabled: !!plan && plan.status === 'active',
  });

  const build = useMutation({
    mutationFn: (scope: 'scan' | 'project') =>
      createPlan(0, {
        projectId,
        // Default to the displayed scan: nothing dedupes assets across scans, so a project-wide
        // plan over a directory scanned three times carries three copies of every task.
        scanId: scope === 'scan' ? (activeScan?.id ?? undefined) : undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['migrate-plans', projectId] });
      qc.invalidateQueries({ queryKey: ['projects-overview'] });
    },
  });

  const tasks = queueQ.data ?? [];
  const planScanSeq = plan?.scan_id
    ? projectScans.find((s) => s.id === plan.scan_id)?.seq
    : undefined;

  return (
    <>
      <ProjectScopeBar>
        <button
          onClick={() => build.mutate('scan')}
          disabled={build.isPending || !activeScan}
          className="hud-btn"
          data-testid="build-plan"
          title={
            activeScan
              ? `Build a plan from scan #${activeScan.seq}`
              : 'This project has no scan to plan from'
          }
        >
          {build.isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5" />
          )}
          {plan ? 'Rebuild plan' : 'Build plan'}
        </button>
        <button
          onClick={() => build.mutate('project')}
          disabled={build.isPending}
          className="hud-btn hud-btn-ghost"
          title="Plan across every scan in this project. Repeated scans of the same target will appear more than once."
        >
          Whole project
        </button>
      </ProjectScopeBar>

      {(plansQ.isError || build.isError) && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          {(() => {
            const e = build.error ?? plansQ.error;
            return e instanceof Error ? e.message : 'request failed';
          })()}
          <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
        </div>
      )}

      {plansQ.isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading this project&apos;s plan…
        </div>
      )}

      {plansQ.data && !plan && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No migration plan for this project yet. A plan is built automatically when a scan
          finishes — build one now with the button above, or rescan the project.
        </div>
      )}

      {planIsStale && (
        <div
          className="glass-card flex items-start gap-3 border-amber-400/40 bg-amber-500/10 p-4 text-sm text-amber-200"
          data-testid="plan-stale"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <div>
            This plan was built before the project&apos;s most recent scan
            {latestScan ? ` (#${latestScan.seq})` : ''}, so its queue describes a snapshot that no
            longer exists. Rebuild it to plan against what is there now.
          </div>
        </div>
      )}

      {plan && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-[color:var(--color-ink-faint)]">
          <span className="flex items-center gap-1.5">
            <Clock3 className="h-3.5 w-3.5" />
            Plan {plan.id.slice(0, 8)} built {new Date(plan.created_at).toLocaleString()}
          </span>
          <span>
            ·{' '}
            {plan.scan_id
              ? `scoped to scan${planScanSeq ? ` #${planScanSeq}` : ''}`
              : 'scoped to every scan in this project'}
          </span>
        </div>
      )}

      {plan?.status === 'completed' && (
        <div className="glass-card p-6 text-center text-sm text-[color:var(--color-ink-dim)]">
          {plan.stats.message ?? 'Plan completed — no vulnerable assets in scope.'}
        </div>
      )}

      {plan?.status === 'active' && (
        <>
          <PlanSummary plan={plan} />

          <div className="flex gap-1 self-start rounded-[3px] border border-[color:var(--edge)] bg-black/40 p-1">
            {(
              [
                ['queue', 'Queue', List],
                ['files', 'By file', FileCode2],
                ['graph', 'Dependency graph', GitFork],
              ] as const
            ).map(([key, label, Icon]) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                data-testid={`migration-tab-${key}`}
                className={`label-caps flex items-center gap-1.5 rounded-[2px] px-3 py-1.5 transition-all ${
                  activeTab === key
                    ? 'bg-[color:var(--color-accent)]/18 text-[color:var(--color-accent)] shadow-[inset_0_1px_0_rgba(255,255,255,0.15)]'
                    : 'hover:text-[color:var(--color-accent-soft)]'
                }`}
              >
                <Icon className="h-3.5 w-3.5" /> {label}
              </button>
            ))}
          </div>

          {activeTab === 'graph' && <DependencyGraphView planId={plan.id} />}
          {activeTab === 'files' && <ByFileView tasks={tasks} />}
          {activeTab === 'queue' && (
            <div className="glass-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="hud-table w-full">
                  <thead>
                    <tr>
                      <th className="w-8 px-4 py-3" />
                      <th className="px-4 py-3">Asset</th>
                      <th className="px-4 py-3">Algorithm</th>
                      <th className="px-4 py-3">Rule</th>
                      <th className="px-4 py-3">WSJF</th>
                      <th className="px-4 py-3">Effort</th>
                      <th className="px-4 py-3">State</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((t) => (
                      <TaskRow key={t.id} task={t} />
                    ))}
                    {queueQ.isLoading && (
                      <tr>
                        <td colSpan={8} className="px-4 py-8 text-center">
                          <Loader2 className="inline h-4 w-4 animate-spin" /> Loading queue…
                        </td>
                      </tr>
                    )}
                    {!queueQ.isLoading && tasks.length === 0 && (
                      <tr>
                        <td
                          colSpan={8}
                          className="px-4 py-8 text-center text-[color:var(--color-ink-faint)]"
                        >
                          Queue is empty.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}

export function Migrations() {
  const projectId = useUiStore((s) => s.projectId);

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header>
        <h1>Migration Hub</h1>
        <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
          {projectId
            ? 'Ranked work for this project: what to replace, in what order, and which changes QUBIT can write for you.'
            : 'Each project carries its own plan, built from its own scan. Choose one to open its queue.'}
        </p>
      </header>

      {!projectId ? (
        <ProjectGrid
          metric="migration"
          title="Migration by project"
          subtitle="A plan is built automatically when a scan finishes. Projects showing “plan outdated” have been scanned since theirs was built."
        />
      ) : (
        <ProjectMigration projectId={projectId} />
      )}

      <div className="glass-card flex items-start gap-3 border-indigo-400/20 bg-indigo-500/5 p-4 text-xs text-[color:var(--color-ink-faint)]">
        <Terminal className="mt-0.5 h-4 w-4 flex-shrink-0 text-[color:var(--color-accent)]" />
        <div>
          Applying approved patches to a working tree runs via{' '}
          <span className="font-mono text-[color:var(--color-accent)]">qubit migrate apply</span> (or{' '}
          <span className="font-mono text-[color:var(--color-accent)]">
            POST /migrate/patches/&#123;id&#125;/apply
          </span>{' '}
          with a repo root) so git safety checks run against the target checkout.
        </div>
      </div>
    </AnimatedPage>
  );
}
