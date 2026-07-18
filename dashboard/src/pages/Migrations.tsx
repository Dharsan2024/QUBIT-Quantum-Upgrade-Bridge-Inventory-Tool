import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
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
} from 'lucide-react';
import {
  createPlan,
  fetchPlanQueue,
  fetchPlans,
  fetchTaskPatches,
  generatePatch,
  reviewPatch,
} from '../api/client';
import type { MigrationTask } from '../api/types';

function StateChip({ state }: { state: string }) {
  const cls =
    state === 'ready'
      ? 'chip'
      : state === 'applied' || state === 'done' || state === 'approved'
        ? 'chip chip-safe'
        : state === 'failed'
          ? 'chip chip-danger'
          : 'chip chip-warn';
  return <span className={cls}>{state.replace(/_/g, ' ')}</span>;
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

  const gen = useMutation({
    mutationFn: () => generatePatch(task.id, generator),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['patches', task.id] });
      qc.invalidateQueries({ queryKey: ['migrate-queue'] });
      setOpen(true);
    },
  });

  const review = useMutation({
    mutationFn: ({ patchId, approve }: { patchId: string; approve: boolean }) =>
      reviewPatch(patchId, approve),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['patches', task.id] });
      qc.invalidateQueries({ queryKey: ['migrate-queue'] });
    },
  });

  const latest = patches?.[0];

  return (
    <>
      <tr className="transition-colors hover:bg-black/10">
        <td className="px-4 py-3">
          <button
            onClick={() => setOpen(!open)}
            className="text-[color:var(--color-ink-faint)] hover:text-[color:var(--color-ink)]"
          >
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        </td>
        <td className="px-4 py-3 font-mono text-xs text-[color:var(--color-ink)]">
          {task.file_path ? `${task.file_path.split(/[\\/]/).slice(-2).join('/')}${task.line ? `:${task.line}` : ''}` : '—'}
        </td>
        <td className="px-4 py-3">
          <span className="inline-flex rounded border border-rose-500/20 bg-rose-500/10 px-2 py-1 text-xs text-[color:var(--color-danger)]">
            {task.algorithm ?? '?'}
          </span>
        </td>
        <td className="px-4 py-3 font-mono text-xs">{task.rule_id ?? '—'}</td>
        <td className="px-4 py-3 text-xs tabular-nums">{task.priority.toFixed(3)}</td>
        <td className="px-4 py-3">
          <StateChip state={task.state} />
        </td>
        <td className="px-4 py-3 text-right">
          {task.rule_id && task.state === 'ready' && (
            <span className="inline-flex items-center gap-2">
              <select
                value={generator}
                onChange={(e) => setGenerator(e.target.value as 'auto' | 'llm' | 'template')}
                className="glass-input px-2 py-1.5 text-xs"
                title="auto = codemod when available; llm = local Ollama model"
              >
                <option value="auto">auto</option>
                <option value="template">template</option>
                <option value="llm">llm</option>
              </select>
              <button
                onClick={() => gen.mutate()}
                disabled={gen.isPending}
                className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-400/40 bg-indigo-500/10 px-3 py-1.5 text-xs font-medium text-indigo-300 transition-colors hover:bg-indigo-500/20 disabled:opacity-50"
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
            <span className="text-xs text-[color:var(--color-ink-faint)]">no codemod rule</span>
          )}
        </td>
      </tr>
      {gen.isError && (
        <tr>
          <td colSpan={7} className="px-4 pb-2">
            <div className="rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
              {gen.error instanceof Error ? gen.error.message : 'generation failed'}
            </div>
          </td>
        </tr>
      )}
      {open && (
        <tr>
          <td colSpan={7} className="bg-black/15 px-6 py-4">
            {!patches?.length && (
              <div className="text-xs text-[color:var(--color-ink-faint)]">
                No patches yet — generate one.
              </div>
            )}
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
                        className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 font-medium text-[color:var(--color-safe)] hover:bg-emerald-500/20"
                      >
                        <Check className="h-3.5 w-3.5" /> Approve
                      </button>
                      <button
                        onClick={() => review.mutate({ patchId: latest.id, approve: false })}
                        disabled={review.isPending}
                        className="inline-flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 font-medium text-rose-300 hover:bg-rose-500/20"
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

export function Migrations() {
  const qc = useQueryClient();

  const plansQ = useQuery({ queryKey: ['migrate-plans'], queryFn: fetchPlans });
  const activePlan = plansQ.data?.find((p) => p.status === 'active') ?? plansQ.data?.[0];

  const queueQ = useQuery({
    queryKey: ['migrate-queue', activePlan?.id],
    queryFn: () => fetchPlanQueue(activePlan!.id),
    enabled: !!activePlan && activePlan.status === 'active',
  });

  const build = useMutation({
    mutationFn: () => createPlan(0),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['migrate-plans'] }),
  });

  const tasks = queueQ.data ?? [];

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Migration Queue</h1>
          <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
            {activePlan
              ? `Plan ${activePlan.id.slice(0, 8)} · ${activePlan.stats.tasks ?? 0} tasks / ${activePlan.stats.units ?? 0} units`
              : 'Build a plan from risk-annotated assets, then generate and review patches.'}
          </p>
        </div>
        <button
          onClick={() => build.mutate()}
          disabled={build.isPending}
          className="glass-input flex items-center gap-2 border-indigo-400/40 text-sm font-medium hover:border-indigo-400/70 disabled:opacity-50"
        >
          {build.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Play className="h-4 w-4" />
          )}
          Build Plan
        </button>
      </header>

      {(plansQ.isError || build.isError) && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          {(() => {
            const e = build.error ?? plansQ.error;
            return e instanceof Error ? e.message : 'request failed';
          })()}
          <span className="text-[color:var(--color-ink-faint)]"> Is the API running on :8787?</span>
        </div>
      )}

      {activePlan?.status === 'completed' && (
        <div className="glass-card p-6 text-center text-sm text-[color:var(--color-ink-dim)]">
          {activePlan.stats.message ?? 'Plan completed — no vulnerable assets in scope.'}
        </div>
      )}

      {plansQ.isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading plans…
        </div>
      )}

      {activePlan?.status === 'active' && (
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-[color:var(--color-ink-dim)]">
              <thead className="border-b border-[color:var(--glass-border)] bg-black/10 text-xs uppercase tracking-wide">
                <tr>
                  <th className="w-8 px-4 py-3" />
                  <th className="px-4 py-3 font-medium text-[color:var(--color-ink)]">Asset</th>
                  <th className="px-4 py-3 font-medium text-[color:var(--color-ink)]">Algorithm</th>
                  <th className="px-4 py-3 font-medium text-[color:var(--color-ink)]">Rule</th>
                  <th className="px-4 py-3 font-medium text-[color:var(--color-ink)]">WSJF</th>
                  <th className="px-4 py-3 font-medium text-[color:var(--color-ink)]">State</th>
                  <th className="px-4 py-3 text-right font-medium text-[color:var(--color-ink)]">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[color:var(--glass-border)]">
                {tasks.map((t) => (
                  <TaskRow key={t.id} task={t} />
                ))}
                {queueQ.isLoading && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center">
                      <Loader2 className="inline h-4 w-4 animate-spin" /> Loading queue…
                    </td>
                  </tr>
                )}
                {!queueQ.isLoading && tasks.length === 0 && (
                  <tr>
                    <td
                      colSpan={7}
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

      {!activePlan && plansQ.data && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No migration plans yet. Run a scan first, then Build Plan.
        </div>
      )}

      <div className="glass-card flex items-start gap-3 border-indigo-400/20 bg-indigo-500/5 p-4 text-xs text-[color:var(--color-ink-faint)]">
        <Terminal className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-300" />
        <div>
          Applying approved patches to a working tree runs via{' '}
          <span className="font-mono text-indigo-300">qubit migrate apply</span> (or{' '}
          <span className="font-mono text-indigo-300">POST /migrate/patches/&#123;id&#125;/apply</span>{' '}
          with a repo root) so git safety checks run against the target checkout.
        </div>
      </div>
    </AnimatedPage>
  );
}
