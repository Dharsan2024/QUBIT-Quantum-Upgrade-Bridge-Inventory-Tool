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
  GitFork,
  ShieldCheck,
  ShieldAlert,
  List,
} from 'lucide-react';
import {
  createPlan,
  fetchPlanGraph,
  fetchPlanQueue,
  fetchPlans,
  fetchTaskGovernance,
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
            {governance && (
              <div className="mb-3 flex items-center justify-between rounded-lg border border-[color:var(--glass-border)] bg-black/20 px-3 py-2 text-xs">
                <div className="flex items-center gap-2">
                  {governance.gate_status === 'passed' ? (
                    <ShieldCheck className="h-4 w-4 text-[color:var(--color-safe)]" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-amber-400" />
                  )}
                  <span className="font-medium text-[color:var(--color-ink)]">Governance Policy:</span>
                  <span className="text-[color:var(--color-ink-dim)]">
                    {governance.current_approvals} / {governance.required_approvals} approvals ({governance.sensitivity} sensitivity)
                  </span>
                </div>
                <span
                  className={
                    governance.gate_status === 'passed'
                      ? 'chip chip-safe'
                      : 'chip chip-warn'
                  }
                >
                  {governance.gate_status}
                </span>
              </div>
            )}
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

function DependencyGraphView({ planId }: { planId: string }) {
  const { data: graph, isLoading, isError, error } = useQuery({
    queryKey: ['plan-graph', planId],
    queryFn: () => fetchPlanGraph(planId),
  });

  if (isLoading) {
    return (
      <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)] text-sm">
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
      <div className="glass-card p-4 flex items-center justify-between text-xs text-[color:var(--color-ink-dim)]">
        <div>
          <span className="font-semibold text-[color:var(--color-ink)]">{graph.nodes.length}</span> Assets ·{' '}
          <span className="font-semibold text-[color:var(--color-ink)]">{graph.edges.length}</span> Dependencies ·{' '}
          <span className="font-semibold text-[color:var(--color-ink)]">{graph.units.length}</span> Execution Units
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-400"></span> Sequential</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-400"></span> Cycle / Parallel Unit</span>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {graph.units.map((unit, idx) => (
          <div key={unit.unit_id} className="glass-card p-4 flex flex-col gap-3 border-l-4 border-l-indigo-400">
            <div className="flex items-center justify-between text-xs border-b border-[color:var(--glass-border)] pb-2">
              <span className="font-mono font-semibold text-indigo-300">Unit #{idx + 1} ({unit.unit_id.slice(0, 8)})</span>
              {unit.is_cycle && <span className="chip chip-warn">Cycle Condensation</span>}
            </div>
            <div className="flex flex-col gap-2">
              {unit.members.map((memberId) => {
                const node = graph.nodes.find((n) => n.id === memberId || n.asset_id === memberId);
                const edgesFrom = graph.edges.filter((e) => e.source === memberId);
                return (
                  <div key={memberId} className="rounded border border-[color:var(--glass-border)] bg-black/20 p-2.5 text-xs">
                    <div className="flex items-center justify-between font-mono">
                      <span className="text-[color:var(--color-ink)]">{node?.algorithm ?? 'Asset'}</span>
                      <span className="text-[color:var(--color-ink-faint)]">rank #{node?.order_index ?? idx}</span>
                    </div>
                    {node?.usage_context && (
                      <div className="mt-1 text-[11px] text-[color:var(--color-ink-faint)]">
                        Context: {node.usage_context}
                      </div>
                    )}
                    {edgesFrom.length > 0 && (
                      <div className="mt-2 border-t border-[color:var(--glass-border)] pt-1 text-[11px] text-indigo-300/80">
                        Depends on: {edgesFrom.map((e) => e.target.slice(0, 8)).join(', ')} ({edgesFrom[0].kind ?? 'dependency'})
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        {graph.units.length === 0 && (
          <div className="glass-card col-span-2 p-8 text-center text-xs text-[color:var(--color-ink-faint)]">
            No graph dependencies detected.
          </div>
        )}
      </div>
    </div>
  );
}

export function Migrations() {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<'queue' | 'graph'>('queue');

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
        <div className="flex items-center gap-3">
          <div className="flex rounded-lg border border-[color:var(--glass-border)] bg-black/20 p-1 text-xs">
            <button
              onClick={() => setActiveTab('queue')}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition-colors ${
                activeTab === 'queue'
                  ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-400/30'
                  : 'text-[color:var(--color-ink-dim)] hover:text-[color:var(--color-ink)]'
              }`}
            >
              <List className="h-3.5 w-3.5" /> Queue
            </button>
            <button
              onClick={() => setActiveTab('graph')}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition-colors ${
                activeTab === 'graph'
                  ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-400/30'
                  : 'text-[color:var(--color-ink-dim)] hover:text-[color:var(--color-ink)]'
              }`}
            >
              <GitFork className="h-3.5 w-3.5" /> Dependency Graph
            </button>
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
        </div>
      </header>

      {(plansQ.isError || build.isError) && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          {(() => {
            const e = build.error ?? plansQ.error;
            return e instanceof Error ? e.message : 'request failed';
          })()}
          <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
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

      {activePlan?.status === 'active' && activeTab === 'graph' && (
        <DependencyGraphView planId={activePlan.id} />
      )}

      {activePlan?.status === 'active' && activeTab === 'queue' && (
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

