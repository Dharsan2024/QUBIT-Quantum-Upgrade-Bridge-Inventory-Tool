import { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import { ProjectGrid } from '../components/ProjectGrid';
import { ProjectScopeBar } from '../components/ProjectScopeBar';
import { GuidancePanel } from '../components/GuidancePanel';
import { LearningPanel } from '../components/LearningPanel';
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
  Rocket,
  PartyPopper,
} from 'lucide-react';
import {
  adviseTask,
  createPlan,
  createScan,
  fetchJob,
  findRunningMigration,
  runPlan,
  fetchPlanGraph,
  fetchPlanQueue,
  fetchPlans,
  fetchProjects,
  fetchProjectsOverview,
  fetchScans,
  fetchTaskGovernance,
  fetchTaskPatches,
  generatePatch,
  reviewPatch,
} from '../api/client';
import { ApiError } from '../api/client';
import type { JobStatus, MigrationRunResult } from '../api/client';
import type { MigrationPlan, MigrationTask, ProjectOverview } from '../api/types';
import { displayAlgorithm } from '../lib/assetLabels';

function StateChip({ state, resolution }: { state: string; resolution?: string | null }) {
  // A task parked because there was nothing left to migrate is finished work, not a warning.
  // `deferred` is reached both ways — the FSM's terminal states all mean "a patch was applied and
  // verified" — so the resolution is the only thing that separates them.
  if (state === 'deferred' && resolution === 'satisfied') {
    return <span className="chip chip-safe">already compliant</span>;
  }
  // A generation attempt that failed is not a dead end — it is retried automatically the next
  // time the plan is rebuilt, and can be retried right now from this row. "deferred" alone read
  // as inert, giving no sign that anything would ever happen to this row again.
  if (state === 'deferred' && resolution === 'unresolved') {
    return (
      <span
        className="chip chip-warn"
        title="The last attempt did not produce a valid patch. It will be retried automatically the next time the plan is rebuilt, grounded in whatever QUBIT has learned since — or retry it now from this row."
      >
        needs retry
      </span>
    );
  }
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

/** Outcomes the API reports with HTTP 422 that are NOT failures: the finding was already
 *  satisfied, usually because an earlier task's patch fixed several occurrences in one file.
 *  Matched on the message because the status code cannot distinguish them from a real rejection —
 *  the same conflation the measurement scripts had to work around. */
const SETTLED_MARKERS = [
  'already meets what',
  'already remediated by an earlier task',
  'nothing left for',
  'no bump needed',
];

function TaskRow({
  task,
  autoOpen = false,
  justPrepared = false,
}: {
  task: MigrationTask;
  /** Open this row without being asked, because its change was just prepared by a bulk build. */
  autoOpen?: boolean;
  /** Mark the row as produced by the run in progress. Separate from `autoOpen`, which is capped at
   *  the newest few — every fresh row is worth flagging, only a few are worth expanding. */
  justPrepared?: boolean;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(autoOpen);
  const [generator, setGenerator] = useState<'auto' | 'llm' | 'template'>('auto');

  // A row whose change has just been prepared opens itself. `useState(autoOpen)` alone cannot do
  // this: the row is already mounted when the patch lands, so its initial value was read long
  // before there was anything to show. Collapsing still sticks — the effect fires on the
  // transition, not on every render.
  useEffect(() => {
    if (autoOpen) setOpen(true);
  }, [autoOpen]);

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
      <tr
        className={`data-row${
          justPrepared
            ? ' bg-[color:var(--color-accent)]/8 shadow-[inset_2px_0_0_var(--color-accent)]'
            : ''
        }`}
        data-testid={justPrepared ? 'task-row-just-prepared' : undefined}
      >
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
                className={
                  task.is_guided
                    ? 'chip chip-warn'
                    : task.has_codemod
                      ? 'chip chip-safe'
                      : 'chip chip-info'
                }
                title={
                  task.is_guided
                    ? 'No edit QUBIT can make is the right answer here — a certificate has to be re-issued, an ecosystem has no provider trustworthy enough to install for you, or the fix lives in configuration outside this file. The steps, commands and sources are in the row below.'
                    : task.has_codemod
                      ? 'Deterministic codemod — runs offline and produces the same diff every time.'
                      : 'No codemod for this rule; the patch is written by the local Ollama model and must be reviewed.'
                }
              >
                {/* Three kinds of row, not two. A `dep-legacy-01` finding was labelled
                    "LLM-assisted" while its only control said GET GUIDANCE — the badge and the
                    button were describing different products. */}
                {task.is_guided ? 'guided' : task.has_codemod ? 'automatic' : 'LLM-assisted'}
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
          <StateChip state={task.state} resolution={task.resolution} />
        </td>
        <td className="px-4 py-3 text-right">
          {/* `is_guided` gates this too. A certificate finding HAS a rule and IS ready, so it
              rendered a Generate button whose only possible answer was "this resolves to a guided
              path" — a round trip to learn something the rule pack already knew.

              A task that FAILED its last attempt (`deferred`/`unresolved`) gets the same control
              rather than nothing. It used to have no way back except rebuilding the whole plan —
              the backend's own FSM refused a direct retry (`generate` is not a legal event from
              `deferred`) and the API surfaced that as "this task already has a generated patch",
              which is simply false for a task that has none. `orch.generate_patch` now resumes a
              failed task before generating, so the same click that starts a fresh migration also
              retries one — grounded in whatever QUBIT has learned since the last attempt, not a
              blind repeat of it. */}
          {task.rule_id &&
            !task.is_guided &&
            (task.state === 'ready' ||
              (task.state === 'deferred' && task.resolution === 'unresolved') ||
              task.state === 'rejected') && (
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
                  // The queue's primary action, and it was the least addressable thing on the page:
                  // every other control here carries a testid, so a browser test had to match the
                  // accessible name — which is "Generate", not the "GENERATE" the CSS renders, and
                  // which changes to "Retry" the moment a task has failed once. Both the id and the
                  // state belong in the DOM rather than in a matcher's guesswork.
                  data-testid={`generate-task-${task.id}`}
                  data-task-state={task.state}
                  title={
                    task.state === 'deferred'
                      ? (task.last_error ?? 'The last attempt did not produce a valid patch.')
                      : task.state === 'rejected'
                        ? 'The previous proposal was rejected. Generate a new diff using the review feedback.'
                        : undefined
                  }
                >
                  {gen.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : task.state === 'deferred' || task.state === 'rejected' ? (
                    <RefreshCw className="h-3.5 w-3.5" />
                  ) : (
                    <Wand2 className="h-3.5 w-3.5" />
                  )}
                  {task.state === 'deferred' || task.state === 'rejected' ? 'Regenerate' : 'Generate'}
                </button>
              </span>
            )}
          {/* Inert grey text here read as a dead end — every other row in this column offers an
              action, so a row that offers none looks like the product giving up. There IS a next
              step for a finding with no codemod: the local model can still explain what to change,
              why, and how to verify it. Surfacing that as a real button turns "nothing we can do"
              into "here is what to do by hand", which is the honest answer these findings already
              had — it was just buried in the expanded panel below. */}
          {/* Offered whenever this task will NOT produce a patch, not just when its RULE is a
              guided one. Measured in the running app: 29 rows had an empty actions cell — 8
              `code-kex-01` tasks that fell back to a written plan after generation failed, and
              9 whose generation failed before that fallback existed. Every one of them had (or
              deserved) a remediation path and offered no way to reach it, which is the dead end
              this work exists to remove, arriving by a different route. */}
          {(task.is_guided ||
            task.advice_text !== null ||
            task.resolution === 'guided' ||
            task.resolution === 'unresolved') && (
            <button
              onClick={() => {
                setOpen(true);
                if (!task.advice_text) advise.mutate(false);
              }}
              disabled={advise.isPending}
              className="hud-btn hud-btn-ghost px-3 py-1.5 text-xs"
              title="This finding is remediated by a procedure rather than an edit — re-issuing a certificate, choosing a provider QUBIT will not install for you, or a configuration change outside this file. QUBIT gives the steps, the commands and the sources behind them."
            >
              {advise.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Lightbulb className="h-3.5 w-3.5" />
              )}
              {task.advice_text ? 'View guidance' : 'Get guidance'}
            </button>
          )}
        </td>
      </tr>
      {gen.isError &&
        (() => {
          // "Nothing left to change" is a SUCCESS, and rendering it in the same red as a real
          // failure made a healthy queue look broken — one patch routinely fixes several findings
          // in the same file, so the later ones legitimately have nothing to do. The API answers
          // 422 for both cases, which react-query surfaces identically, so the wording is the only
          // thing that can tell them apart.
          const message =
            gen.error instanceof Error ? gen.error.message : 'generation failed';
          const settled = SETTLED_MARKERS.some((m) => message.toLowerCase().includes(m));
          return (
            <tr>
              <td colSpan={COLS} className="px-4 pb-2">
                <div
                  data-testid={settled ? 'generate-settled' : 'generate-error'}
                  className={
                    settled
                      ? 'rounded-lg border border-[color:var(--edge)] bg-black/30 px-3 py-2 text-xs text-[color:var(--color-ink-dim)]'
                      : 'rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200'
                  }
                >
                  {settled ? `Nothing to do — ${message}` : message}
                </div>
              </td>
            </tr>
          );
        })()}
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
                  ? task.is_guided
                    ? 'This finding is resolved by a guided path rather than a patch — the remediation is a procedure QUBIT cannot make as an edit. The steps are below.'
                    : 'No patches yet — generate one.'
                  : 'No migration rule covers this finding, so QUBIT builds the remediation path instead of a patch. The steps, commands and sources are below.'}
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
                {task.advice_model === 'qubit-guided' && (
                  <span
                    className="metric-label"
                    title="Assembled from QUBIT's rule pack, migration knowledge base and verified provider playbook. Every version number and adoption figure here was checked against that ecosystem's own registry — none of it is model output."
                  >
                    verified sources
                  </span>
                )}
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
                <GuidancePanel text={task.advice_text} />
              ) : (
                !advise.isPending && (
                  <p className="text-xs text-[color:var(--color-ink-faint)]">
                    Builds the remediation path for this finding — the target, the library that
                    provides it with its verified version floor, what the change breaks, and how
                    to confirm it. Works offline; with Ollama running it also reads this file and
                    explains the change in its own terms.
                  </p>
                )
              )}
            </div>
            {latest && (
              <div className="flex flex-col gap-3">
                {/* The model's reasoning, beside its diff. A diff alone does not tell a reviewer
                    whether the model understood the migration or pattern-matched it, and the
                    most valuable line is usually the one admitting what it could NOT fix in this
                    file — a caller, a column width, a stored key format. */}
                {latest.validation?.security_notes && (
                  <div className="rounded-lg border border-[color:var(--color-accent)]/30 bg-[color:var(--color-accent)]/8 px-3 py-2">
                    <div className="metric-label mb-1 text-[color:var(--color-accent)]">
                      Model's security reasoning
                    </div>
                    <pre className="whitespace-pre-wrap font-sans text-xs text-[color:var(--color-ink-dim)]">
                      {latest.validation.security_notes}
                    </pre>
                  </div>
                )}
                {/* Which checks did NOT run. `partial` was carried by the API and shown nowhere,
                    so a patch validated only by a syntax parse and a rescan looked identical to
                    one that compiled and passed a test suite. Measured on a real accepted patch:
                    an RSA-to-ML-KEM rewrite in Rust parsed, satisfied the rescan, and would not
                    have compiled - it returned a tuple from a function declared to return one
                    value. `compiles` was skipped because the sandbox has no Rust toolchain, and a
                    tree-sitter parse is not a type-check. The reviewer has to be told that. */}
                {latest.validation?.partial && latest.validation?.stages && (
                  <div className="rounded-lg border border-[color:var(--color-warn)]/30 bg-[color:var(--color-warn)]/8 px-3 py-2">
                    <div className="metric-label mb-1 text-[color:var(--color-warn)]">
                      Partly validated — read the diff
                    </div>
                    <p className="text-xs text-[color:var(--color-ink-dim)]">
                      {(() => {
                        const skipped = Object.entries(latest.validation.stages)
                          .filter(([, s]) => s.status === 'skipped')
                          .map(([n]) => n);
                        const ran = Object.entries(latest.validation.stages)
                          .filter(([, s]) => s.status === 'pass')
                          .map(([n]) => n);
                        return `Passed: ${ran.join(', ') || 'nothing'}. Did not run: ${skipped.join(', ')}. A syntax parse is not a type-check and a rescan only asks whether the algorithm changed — neither can tell you this compiles or that the behaviour is preserved.`;
                      })()}
                    </p>
                  </div>
                )}
                {/* What the model says its own patch does NOT do. Shown as warnings rather than
                    used to reject: a patch whose notes admit a gap is more useful than one that
                    stays quiet about the same gap, and rejecting the honest one would train the
                    prompt in exactly the wrong direction.

                    One of these can come from QUBIT rather than from the model: a file too large
                    to send whole is generated from an excerpt, and the reviewer is told so here,
                    because otherwise they would credit the patch with having weighed a whole file
                    the model never read. */}
                {latest.validation?.security_caveats &&
                  latest.validation.security_caveats.length > 0 && (
                    <div className="rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2">
                      <div className="metric-label mb-1 text-amber-200">
                        Not covered by this patch
                      </div>
                      <ul className="list-disc space-y-0.5 pl-4 text-xs text-amber-100/90">
                        {latest.validation.security_caveats.map((c, i) => (
                          <li key={i}>{c.replace(/^[-*]\s*/, '')}</li>
                        ))}
                      </ul>
                    </div>
                  )}
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
            {
              n: graph.edges.length,
              l: 'Dependencies',
              c: 'var(--color-accent-2)',
            },
            {
              n: graph.units.length,
              l: 'Execution units',
              c: 'var(--color-safe)',
            },
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
                Unit #{idx + 1} · {unit.members.length} member
                {unit.members.length === 1 ? '' : 's'}
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
      // Renamed from "Manual", which was the old dead-end state. These findings have a rule, a
      // target and a written remediation path; what they do not have is an edit QUBIT can make.
      label: 'Guided',
      value: String(manual),
      color: 'var(--color-warn)',
      hint: 'The remediation is a procedure rather than an edit — re-issuing a certificate, choosing a provider QUBIT will not install for you, or a configuration change outside this file. QUBIT writes the steps, the commands and the sources.',
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

// What each regime actually requires, for the hover on the plan header.
//
// The disagreement is not the one usually described. CNSA 2.0 does not forbid hybrid — it forbids
// a hybrid whose ML-KEM component is below the 1024 grade, so `X25519MLKEM768` fails it on the
// 768. BSI and ANSSI both REQUIRE hybrid, and differ only in severity.
const REGIME_TITLES: Record<string, string> = {
  'cnsa-2.0': 'NSA CNSA 2.0 — ML-KEM-1024 and ML-DSA-87 only; rejects a sub-1024 hybrid component',
  anssi: 'ANSSI (France) — hybrid required during the transition, raised as an advisory',
  'bsi-tr-02102': 'BSI TR-02102 (Germany) — hybrid REQUIRED; standalone ML-KEM is not sufficient',
  'asd-ism': 'ASD ISM (Australia) — highest parameter sets; classical ceases by 2030',
  'nist-civil': 'NIST IR 8547 (draft) + FIPS 203/204/205 — deprecation dates, no mandated construction',
};

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

  const [runJobId, setRunJobId] = useState<string | null>(null);

  // The queue is polled while a run is in flight, and only then.
  //
  // "Build plan" has always generated a change for every finding; what it never did was show them
  // arriving. The table stayed frozen at whatever it held when the click landed, so a build over
  // three hundred findings put a spinner on screen for twenty minutes and produced its entire
  // result in one jump at the end — with no way to tell work from a hang, and no diff to read
  // until all of it was done. The work was happening. The page had no way to say so.
  const queueQ = useQuery({
    queryKey: ['migrate-queue', plan?.id],
    queryFn: () => fetchPlanQueue(plan!.id),
    enabled: !!plan && plan.status === 'active',
    refetchInterval: runJobId ? 2500 : false,
  });

  // Findings that gained a reviewable change during THIS run, newest first.
  //
  // Pressing Generate on a single row shows the diff the moment it exists. Building the plan did
  // the same work for every asset and showed none of it: each diff landed silently into a row a
  // reader had to know to expand, one at a time, after the run had finished. These ids lift the
  // rows that just changed to the top of the queue and open them, so a bulk build reads the way a
  // single generate does.
  const [freshlyPrepared, setFreshlyPrepared] = useState<string[]>([]);
  //: What was already prepared when the run started. Without this snapshot the first poll would
  //: announce every previously prepared finding as new work.
  const preparedBefore = useRef<Set<string> | null>(null);
  //: Which half is in flight. The two share one job poller because they are the same job kind;
  //: only the wording differs, and a run that is preparing changes must not say it is writing them.
  const [runMode, setRunMode] = useState<'generate' | 'apply'>('apply');
  const [runOutcome, setRunOutcome] = useState<MigrationRunResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  //: Set when "Build plan" answers 409 — every finding is already migrated, parked, or there were
  //: none to begin with. Found on a project with zero vulnerable findings (spring-security, in a
  //: real run): the click produced no job, so `runOutcome` never got set, and nothing else on
  //: this page said anything either — no banner, no toast, nothing. A queue that had rendered
  //: "Queue is empty" further down the page was the only confirmation the click had done
  //: anything, and a reader has no reason to scroll to it after a button click that appeared to
  //: do nothing. The backend already writes a precise, honest reason for a 409; this is what
  //: shows it, rather than discarding it the moment it is caught.
  const [nothingToPrepare, setNothingToPrepare] = useState<string | null>(null);
  //: Raised when a WRITING run finishes, to ask about the rescan. Separate from `runOutcome`, which
  //: also holds the result of a preparing run — that one has changed nothing, so it must not ask.
  const [rescanPrompt, setRescanPrompt] = useState<MigrationRunResult | null>(null);

  // "Build plan" queues the findings AND prepares a patch for every one of them, writing nothing.
  // Planning alone produced a list of problems and no answers: every diff still had to be asked
  // for a row at a time, which meant the operator met the model's work one finding at a time and
  // had nothing to review as a whole. Generating here moves the slow, uncertain half to the front,
  // so by the time "Initiate migration" is offered, every change it would make can already be read.
  const build = useMutation({
    mutationFn: async (scope: 'scan' | 'project') => {
      const created = await createPlan(0, {
        projectId,
        // Default to the displayed scan: nothing dedupes assets across scans, so a project-wide
        // plan over a directory scanned three times carries three copies of every task.
        scanId: scope === 'scan' ? (activeScan?.id ?? undefined) : undefined,
      });
      try {
        const started = await runPlan(created.id, { generate: true, apply: false });
        return { plan: created, jobId: started.job.id as string | null, note: null as string | null };
      } catch (e) {
        // 409 is the engine saying there is nothing ready to prepare — every finding is already
        // migrated or parked. That is a complete answer to "build me a plan", not a failure, and
        // the plan itself was created. Anything else is a real error and must still surface.
        if (e instanceof ApiError && e.status === 409) {
          return { plan: created, jobId: null, note: e.message || null };
        }
        throw e;
      }
    },
    onSuccess: ({ jobId, note }) => {
      qc.invalidateQueries({ queryKey: ['migrate-plans', projectId] });
      qc.invalidateQueries({ queryKey: ['projects-overview'] });
      if (jobId) {
        setRunOutcome(null);
        setRunError(null);
        setNothingToPrepare(null);
        setRunMode('generate');
        // Snapshot before the run rather than on the first poll: by the time a poll comes back the
        // engine may already have prepared two or three findings, and those are exactly the ones
        // worth showing.
        preparedBefore.current = new Set(
          (queueQ.data ?? [])
            .filter((t) => t.state === 'proposed' || t.state === 'approved')
            .map((t) => t.id),
        );
        setFreshlyPrepared([]);
        setRunJobId(jobId);
      } else {
        setNothingToPrepare(note ?? 'Nothing to prepare — every finding here is already handled.');
      }
    },
  });

  // Memoised because two hooks below depend on it: a fresh array each render would re-run the
  // "what just changed" scan on every keystroke elsewhere on the page.
  const tasks = useMemo(() => queueQ.data ?? [], [queueQ.data]);

  // A run already in flight is adopted, not ignored.
  //
  // The job lives on the server; this page only watches it. But the id it watched was component
  // state, so leaving the Migration Hub and coming back showed a project with nothing running --
  // no banner, no live counters, a frozen queue -- and a "Build plan" button offering to start a
  // SECOND run over the same findings. The first was still going the whole time, which is what
  // "the process has been stopped" looked like from the outside.
  //
  // Asked once per plan rather than polled: the answer only changes when a run starts or ends, and
  // both of those are already known here.
  useEffect(() => {
    if (!plan?.id || runJobId) return;
    let cancelled = false;
    findRunningMigration(plan.id)
      .then((found) => {
        if (cancelled || !found) return;
        setRunMode(found.mode);
        setRunJobId(found.id);
        // Nothing is known about what this run has already prepared, so the "just prepared" list
        // starts from what is on screen now. Better than claiming every previously prepared
        // finding is new work of this run's.
        preparedBefore.current = new Set(
          (queueQ.data ?? [])
            .filter((t) => t.state === 'proposed' || t.state === 'approved')
            .map((t) => t.id),
        );
      })
      .catch(() => {
        // A page that cannot ask is no worse off than before this existed.
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [plan?.id]);

  // Notice each change as it is prepared, and put it in front of the reader.
  useEffect(() => {
    const before = preparedBefore.current;
    if (!runJobId || before === null) return;
    const prepared = tasks
      .filter((t) => t.state === 'proposed' || t.state === 'approved')
      .map((t) => t.id);
    setFreshlyPrepared((seen) => {
      const known = new Set(seen);
      const added = prepared.filter((id) => !before.has(id) && !known.has(id));
      if (added.length === 0) return seen;
      // A row opened before its patch existed cached an empty result, and nothing else
      // invalidates it — without this the diff that just arrived stays invisible in an open row.
      for (const id of added) qc.invalidateQueries({ queryKey: ['patches', id] });
      return [...added.reverse(), ...seen];
    });
  }, [tasks, runJobId, qc]);

  // Rows that just changed come first, so the newest diff is at the top of the page instead of
  // wherever its WSJF rank happens to place it among three hundred others. The order survives the
  // run — after it ends, what the run produced is still the first thing on screen.
  const orderedTasks = useMemo(() => {
    if (freshlyPrepared.length === 0) return tasks;
    const rank = new Map(freshlyPrepared.map((id, i) => [id, i]));
    return [...tasks].sort(
      (a, b) =>
        (rank.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.id) ?? Number.MAX_SAFE_INTEGER),
    );
  }, [tasks, freshlyPrepared]);

  const planScanSeq = plan?.scan_id
    ? projectScans.find((s) => s.id === plan.scan_id)?.seq
    : undefined;

  const migrationRequest = useUiStore((s) => s.migrationRequest);
  const openScan = useUiStore((s) => s.openScan);

  // "Initiate migration" writes the prepared patches into the original files. It runs no model and
  // decides nothing: every diff in the set has already been through the validation gate and has
  // been sitting in the queue to be read. Keeping the irreversible half as its own act is the
  // point — approving happens by pressing this, on changes already seen.
  const startRun = useMutation({
    mutationFn: () => runPlan(plan!.id, { generate: false, apply: true }),
    onSuccess: (r) => {
      setRunOutcome(null);
      setRunError(null);
      setNothingToPrepare(null);
      setRunMode('apply');
      setRunJobId(r.job.id);
    },
    onError: (e) => setRunError(e instanceof Error ? e.message : 'could not start the migration'),
  });

  // Poll the job while it runs. The run is dispatched off the request path, so this is how the
  // page learns it finished — and the only place the per-task outcome is available.
  const runJobQ = useQuery({
    queryKey: ['migrate-job', runJobId],
    queryFn: () => fetchJob(runJobId!),
    enabled: !!runJobId,
    refetchInterval: (q) => {
      const s = (q.state.data as JobStatus | undefined)?.status;
      return s && !['queued', 'running'].includes(s) ? false : 1200;
    },
  });

  useEffect(() => {
    const job = runJobQ.data;
    if (!job || ['queued', 'running'].includes(job.status)) return;
    setRunJobId(null);
    if (job.status === 'succeeded' && job.result) {
      setRunOutcome(job.result);
      // Only a run that actually wrote something invalidates the inventory. A preparing run left
      // the tree exactly as it found it, so asking to rescan after it would be asking the operator
      // to redo the scan for no reason.
      if (job.result.mode === 'apply' || job.result.mode === 'full') {
        if ((job.result.applied ?? 0) > 0) setRescanPrompt(job.result);
      }
    } else {
      setRunError(job.error || `migration ${job.status}`);
    }
    qc.invalidateQueries({ queryKey: ['migrate-queue'] });
    qc.invalidateQueries({ queryKey: ['migrate-plans', projectId] });
    qc.invalidateQueries({ queryKey: ['projects-overview'] });
  }, [runJobQ.data, qc, projectId]);

  // The sidebar's "Initiate migration" raises a counter; this is where it lands. Skipped on the
  // first render so merely opening the hub does not start a migration nobody asked for.
  const seenRequest = useRef(migrationRequest);
  useEffect(() => {
    if (migrationRequest === seenRequest.current) return;
    seenRequest.current = migrationRequest;
    if (plan?.status === 'active' && !runJobId && !startRun.isPending) startRun.mutate();
  }, [migrationRequest, plan?.status, runJobId, startRun]);

  // Rescan the same target the plan was built from — offered right after a run, because a
  // migration that changed files has invalidated the inventory it was planned from.
  const rescan = useMutation({
    mutationFn: async () => {
      const scan = projectScans.find((s) => s.id === plan?.scan_id) ?? projectScans[0];
      if (!scan?.targets?.length) throw new Error('no scan target recorded to rescan');
      return createScan(scan.targets);
    },
    onSuccess: (s) => {
      setRunOutcome(null);
      setNothingToPrepare(null);
      setRescanPrompt(null);
      if (s?.project_id && s?.id) openScan(s.project_id, s.id);
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['projects-overview'] });
    },
  });

  // The two halves are told apart everywhere they are shown. A run that is preparing changes must
  // never say it is writing them — that is the one sentence an operator would act on wrongly.
  const preparing = build.isPending || (!!runJobId && runMode === 'generate');
  const writing = startRun.isPending || (!!runJobId && runMode === 'apply');
  const running = preparing || writing;
  // What "Initiate migration" would actually write: patches that exist and have not been rejected.
  // Counting `ready` tasks instead would offer the button over findings with no diff behind them.
  const preparedCount = tasks.filter(
    (t) => t.state === 'proposed' || t.state === 'approved',
  ).length;
  // Findings a previous attempt could not migrate. "Build plan" retries every one of these
  // automatically — resumed and regenerated with whatever QUBIT has learned since — so a failure
  // is a pause, not a dead end. Counted here so the button can say so, instead of leaving the
  // operator to discover it by re-reading the completion banner from the last run.
  const retryableCount = tasks.filter(
    (t) => t.state === 'deferred' && t.resolution === 'unresolved',
  ).length;

  // How far through the plan the run is, counted from the queue rather than parsed out of the job's
  // message. Every finding lands in exactly one of these, so `remaining` reaching zero means the
  // queue is genuinely done rather than merely quiet. `guided` and `settled` are deliberately not
  // counted as failures: one is a written remediation, the other work that was already correct, and
  // folding either into "failed" is what made a healthy run read as a broken one.
  //
  // `refused` (the algorithm belongs to a party outside this repository) folds into the same
  // "guided" count here, not a bucket of its own: both mean "QUBIT decided, wrote why, nothing to
  // click Generate on", which is exactly what this label already says. The backend's own run
  // summary keeps them as separate fields (`refused` vs `needs_guidance`) because an operator
  // reading THAT number cares whether QUBIT was capable and declined or had nothing to offer —
  // this is a per-row live count, not that summary, and merging them here is what stops it from
  // silently undercounting every refused row as this queue re-renders mid-run.
  const liveCounts = {
    prepared: tasks.filter((t) => ['proposed', 'approved', 'applied'].includes(t.state)).length,
    remaining: tasks.filter((t) => ['pending', 'ready', 'generating'].includes(t.state)).length,
    guided: tasks.filter((t) => t.resolution === 'guided' || t.resolution === 'refused').length,
    settled: tasks.filter((t) => t.resolution === 'satisfied').length,
    failed: tasks.filter(
      (t) =>
        ['failed', 'apply_failed', 'rejected'].includes(t.state) ||
        (t.state === 'deferred' && t.resolution === 'unresolved'),
    ).length,
  };

  return (
    <>
      <ProjectScopeBar>
        <button
          onClick={() => startRun.mutate()}
          disabled={running || plan?.status !== 'active' || preparedCount === 0}
          className="hud-btn"
          data-testid="initiate-migration"
          title={
            preparedCount > 0
              ? `Write ${preparedCount} prepared change${preparedCount === 1 ? '' : 's'} into the original files`
              : 'Nothing is prepared yet — build the plan first, which generates the changes'
          }
        >
          {writing ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Rocket className="h-3.5 w-3.5" />
          )}
          {writing
            ? 'Writing changes…'
            : `Initiate migration${preparedCount > 0 ? ` (${preparedCount})` : ''}`}
        </button>
        <button
          onClick={() => build.mutate('scan')}
          disabled={running || !activeScan}
          className="hud-btn"
          data-testid="build-plan"
          title={
            activeScan
              ? `Queue every vulnerable finding in scan #${activeScan.seq} and generate a change for each. Nothing is written to disk.${retryableCount > 0 ? ` Also retries ${retryableCount} finding${retryableCount === 1 ? '' : 's'} that could not be migrated last time, grounded in whatever QUBIT has learned since.` : ''}`
              : 'This project has no scan to plan from'
          }
        >
          {preparing ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5" />
          )}
          {preparing
            ? 'Preparing changes…'
            : `${plan ? 'Rebuild plan' : 'Build plan'}${retryableCount > 0 ? ` (retry ${retryableCount})` : ''}`}
        </button>
        <button
          onClick={() => build.mutate('project')}
          disabled={running}
          className="hud-btn hud-btn-ghost"
          title="Plan across every scan in this project. Repeated scans of the same target will appear more than once."
        >
          Whole project
        </button>
      </ProjectScopeBar>

      {/* Live progress while the run is in flight — a bulk migration takes minutes, and a button
          that only says "Migrating…" gives no way to tell work from a hang. */}
      {running && (
        <div
          className="glass-card flex items-center gap-3 border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent)]/8 p-4 text-sm"
          data-testid="migration-running"
        >
          <Loader2 className="h-4 w-4 flex-shrink-0 animate-spin text-[color:var(--color-accent)]" />
          <div>
            <div className="text-[color:var(--color-ink)]">
              {runJobQ.data?.message ??
                (preparing ? 'Preparing changes…' : 'Starting migration…')}
            </div>
            {/* Live tallies, counted from the queue itself rather than from the job's message.
                A build that takes twenty minutes needs to say how much of the plan is done, not
                only which finding is in flight — without this the only number on screen was a
                spinner, and a run producing changes looked exactly like one failing every
                finding until the moment it ended. */}
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs tabular-nums">
              <span className="text-[color:var(--color-safe)]">{liveCounts.prepared} prepared</span>
              <span className="text-[color:var(--color-ink-faint)]">
                {liveCounts.remaining} to go
              </span>
              {liveCounts.guided > 0 && (
                <span className="text-[color:var(--color-warn)]">{liveCounts.guided} guided</span>
              )}
              {liveCounts.failed > 0 && (
                <span className="text-[color:var(--color-danger)]">{liveCounts.failed} failed</span>
              )}
              {liveCounts.settled > 0 && (
                <span className="text-[color:var(--color-ink-faint)]">
                  {liveCounts.settled} already compliant
                </span>
              )}
            </div>
            <div className="metric-label mt-1">
              {preparing
                ? 'Each finding is being rewritten and put through the validation gate. Nothing is written to disk until you initiate the migration.'
                : 'Each prepared change is being written into its original file.'}
            </div>
          </div>
        </div>
      )}

      {runError && (
        <div
          className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200"
          data-testid="migration-failed"
        >
          Migration did not complete: {runError}
        </div>
      )}

      {/* "Build plan" produced no job — every finding here is already migrated, parked, or there
          were none to begin with. Without this, that click left NOTHING on screen: no banner, no
          job, no confirmation the click had registered at all. The queue table further down does
          render an accurate "Queue is empty" once its own query settles, but a reader who just
          watched a button do nothing has no reason to scroll down looking for it. */}
      {nothingToPrepare && !runOutcome && (
        <div
          className="glass-card flex items-start gap-3 border-[color:var(--color-safe)]/40 bg-[color:var(--color-safe)]/8 p-4 text-sm"
          data-testid="nothing-to-prepare"
        >
          <ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-[color:var(--color-safe)]" />
          <div className="flex-1 text-[color:var(--color-ink)]">{nothingToPrepare}</div>
          <button
            onClick={() => setNothingToPrepare(null)}
            className="hud-btn hud-btn-ghost px-2 py-1 text-xs"
            data-testid="dismiss-nothing-to-prepare"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* The result notification, and the rescan the user is most likely to want next: the files
          just changed, so the inventory this plan was built from now describes the old code. */}
      {runOutcome && (
        <div
          className={`glass-card flex flex-col gap-3 p-5 ${
            runOutcome.failed > 0
              ? 'border-[color:var(--color-warn)]/40 bg-[color:var(--color-warn)]/8'
              : 'border-[color:var(--color-safe)]/40 bg-[color:var(--color-safe)]/8'
          }`}
          data-testid="migration-complete"
        >
          <div className="flex items-start gap-3">
            <PartyPopper
              className={`mt-0.5 h-5 w-5 flex-shrink-0 ${
                runOutcome.failed > 0
                  ? 'text-[color:var(--color-warn)]'
                  : 'text-[color:var(--color-safe)]'
              }`}
            />
            <div className="flex-1">
              <div
                className={`text-sm font-semibold ${
                  runOutcome.failed > 0
                    ? 'text-[color:var(--color-warn)]'
                    : 'text-[color:var(--color-safe)]'
                }`}
              >
                {runOutcome.mode === 'generate'
                  ? `${runOutcome.generated} change${runOutcome.generated === 1 ? '' : 's'} prepared and validated${(runOutcome.needs_guidance ?? 0) > 0 ? `, ${runOutcome.needs_guidance} routed to guided review` : ''}. Nothing has been written yet — read the diffs below, then initiate the migration.`
                  : runOutcome.applied > 0 && runOutcome.failed === 0
                    ? `Migration successful — ${runOutcome.applied + (runOutcome.covered ?? 0)} of ${runOutcome.total} finding${runOutcome.total === 1 ? '' : 's'} migrated and written to disk${(runOutcome.needs_guidance ?? 0) > 0 ? `, ${runOutcome.needs_guidance} routed to guided review` : ''}.`
                    : runOutcome.applied > 0
                      ? `Migration partly applied — ${runOutcome.applied} of ${runOutcome.total} finding${runOutcome.total === 1 ? '' : 's'} written to disk, ${runOutcome.failed} could not be written. Nothing was changed for those; the reasons are below.`
                      : runOutcome.failed > 0
                        ? // Not "refused": that word now names the opposite outcome — a finding
                          // QUBIT deliberately declined to edit. These are the ones it could not
                          // produce a usable change for at all.
                          `Nothing was written — no usable change was produced for ${runOutcome.failed} finding${runOutcome.failed === 1 ? '' : 's'}. The files are unchanged; the reasons are below.`
                        : `Migration finished — ${runOutcome.generated} patch${runOutcome.generated === 1 ? '' : 'es'} generated, none written.`}
              </div>
              <div className="metric-label mt-1 flex flex-wrap gap-x-3">
                {runOutcome.mode === 'apply' ? (
                  <span>{runOutcome.applied} written</span>
                ) : (
                  <>
                    <span>{runOutcome.generated} generated</span>
                    <span>· {runOutcome.applied} applied</span>
                  </>
                )}
                {/* Findings this plan holds no diff for. Naming them is what turns "12 written"
                    from a total into a fraction the operator can act on. */}
                {(runOutcome.no_patch ?? 0) > 0 && (
                  <span title="These findings had no prepared change, so nothing was written for them. Build the plan again to generate them.">
                    · {runOutcome.no_patch} not prepared
                  </span>
                )}
                {(runOutcome.from_cache ?? 0) > 0 && (
                  <span
                    className="text-[color:var(--color-accent)]"
                    title="Answered from an earlier, already-validated fix for this exact finding — no model call needed."
                  >
                    · {runOutcome.from_cache} from learned cache
                  </span>
                )}
                {(runOutcome.covered ?? 0) > 0 && (
                  <span title="Covered by a patch to the same file — a rule rewrites the whole file.">
                    · {runOutcome.covered} already covered
                  </span>
                )}
                {/* Findings with no rule are NOT failures — they were never patch-eligible and
                    the queue offers each a guidance button. Lumping them into "could not be
                    migrated" reported 94 failures where there were 19. */}
                {(runOutcome.needs_guidance ?? 0) > 0 && (
                  <span title="No codemod or LLM rule matches these findings. Each has a guidance button in the queue — QUBIT explains what to change by hand, why, and how to verify it.">
                    · {runOutcome.needs_guidance} need guided review
                  </span>
                )}
                {/* A refusal is a correct decision, not a shortfall, and a rejection is the gate
                    doing its job. Both were inside "could not be migrated" until a run reported 18
                    failures for a set that held 6 ownership refusals, 7 gate rejections and 2 real
                    failures. `covered` is a sub-count of `refused`, so it is shown above and
                    subtracted here rather than counted twice. */}
                {(runOutcome.refused ?? 0) - (runOutcome.covered ?? 0) > 0 && (
                  <span title="The algorithm here belongs to a party outside this repository — a Gravatar URL keyed by MD5, a webhook field the remote names sha1=, an established KDF. Changing it would break the exchange, so QUBIT refused and wrote guidance instead.">
                    · {(runOutcome.refused ?? 0) - (runOutcome.covered ?? 0)} refused (not ours to
                    change)
                  </span>
                )}
                {(runOutcome.rejected ?? 0) > 0 && (
                  <span
                    className="text-[color:var(--color-warn)]"
                    title="A patch was generated and a validation stage — symbols, compiles, behaves, rescan or the project's own test suite — turned it down. The bad patch was caught before anything was written. Each is retried on the next run."
                  >
                    · {runOutcome.rejected} rejected by a validation gate
                  </span>
                )}
                {runOutcome.failed > 0 && (
                  <span
                    className="text-[color:var(--color-danger)]"
                    title="Each one now has a guidance panel built from the specific reason it failed, and each is retried automatically the next time the plan is rebuilt — grounded in whatever QUBIT has learned since. Not a dead end; a pause."
                  >
                    · {runOutcome.failed} could not be migrated (will retry on rebuild)
                  </span>
                )}
                {runOutcome.repo_root && <span>· {runOutcome.repo_root}</span>}
              </div>
              {/* Naming what failed, not just counting it — an unmigratable finding is the thing
                  that still needs a person, so hiding it behind a number wastes the run. */}
              {runOutcome.failures.length > 0 && (
                <ul className="mt-2 flex flex-col gap-1 text-xs text-[color:var(--color-ink-faint)]">
                  {runOutcome.failures.slice(0, 5).map((f) => (
                    <li key={f.task_id}>
                      <span className="font-mono text-[color:var(--color-ink-dim)]">
                        {f.rule_id || 'finding'}
                      </span>{' '}
                      — {f.detail}
                    </li>
                  ))}
                  {runOutcome.failures.length > 5 && (
                    <li>…and {runOutcome.failures.length - 5} more.</li>
                  )}
                </ul>
              )}
            </div>
          </div>

          <div
            className="flex flex-wrap items-center gap-3 border-t border-[color:var(--edge)] pt-3"
            hidden={runOutcome.mode === 'generate'}
          >
            <span className="text-xs text-[color:var(--color-ink-dim)]">
              The code on disk has changed. Rescan this project to see what is left?
            </span>
            <button
              onClick={() => rescan.mutate()}
              disabled={rescan.isPending}
              className="hud-btn"
              data-testid="rescan-after-migration"
            >
              {rescan.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5" />
              )}
              Rescan project
            </button>
            <button
              onClick={() => setRunOutcome(null)}
              className="hud-btn hud-btn-ghost"
              data-testid="dismiss-migration-result"
            >
              Not now
            </button>
            {rescan.isError && (
              <span className="text-xs text-[color:var(--color-danger)]">
                {rescan.error instanceof Error ? rescan.error.message : 'rescan failed'}
              </span>
            )}
          </div>
        </div>
      )}

      {(plansQ.isError || build.isError) && (
        <div className="glass-card border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          {(() => {
            const e = build.error ?? plansQ.error;
            return e instanceof Error ? e.message : 'request failed';
          })()}
          {/* A 5xx means the request reached the engine and it failed there — "is the API
              reachable?" is the wrong question to leave someone with. Distinguished from a real
              network failure, which IS what that hint is for. Building a plan across several
              projects at once can hit real, transient database contention (the engine retries
              this itself now, but retries are bounded); the fix here is the same action, again. */}
          <span className="text-[color:var(--color-ink-faint)]">
            {' '}
            {(build.error ?? plansQ.error) instanceof ApiError &&
            ((build.error ?? plansQ.error) as ApiError).status >= 500
              ? 'The engine hit an error handling this. Try again.'
              : 'Is the API reachable?'}
          </span>
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
          {/*
            The regime the targets were chosen under. Shown always, including when there is none,
            because "no regime" is itself the answer a reviewer needs: it means the targets came
            from the general-purpose defaults and carry no regulator's mandate. Printing the
            default regime's name in that case would attribute a decision nobody made.
          */}
          <span title={REGIME_TITLES[plan.regime ?? ''] ?? undefined}>
            · {plan.regime ? `regime ${plan.regime}` : 'no regime configured'}
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

          {/* What the engine has learned from its own validated migrations. Placed above the queue
              because it is the answer to "does this get better, or does it just run again" — and
              until it existed the evidence was a row count in a table nobody could see. */}
          <LearningPanel />

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
                    {orderedTasks.map((t) => {
                      const fresh = freshlyPrepared.indexOf(t.id);
                      return (
                        <TaskRow
                          key={t.id}
                          task={t}
                          justPrepared={fresh >= 0}
                          // The three most recent open themselves. Opening all of them would put
                          // three hundred diffs on one page and make the newest unfindable;
                          // opening none is what left a bulk build with nothing to read.
                          autoOpen={fresh >= 0 && fresh < 3}
                        />
                      );
                    })}
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

      {/* The rescan question, asked as a dialog rather than a notice further down the page.
          A migration that has just rewritten files leaves every number on screen describing code
          that no longer exists, and rescanning is the only thing that makes them true again — so
          it is put in front of the operator rather than left to be noticed. Dismissing is a real
          answer: the same offer stays in the completion banner underneath. */}
      {rescanPrompt && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-6"
          role="dialog"
          aria-modal="true"
          aria-labelledby="rescan-dialog-title"
          data-testid="rescan-dialog"
        >
          <motion.div
            className="absolute inset-0 bg-black/65 backdrop-blur-sm"
            onClick={() => setRescanPrompt(null)}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.18 }}
          />
          <motion.div
            className="relative z-10 w-full max-w-md rounded-2xl border border-[color:var(--edge-lume)] bg-[#0b0e14]/97 p-6 shadow-[0_24px_60px_rgba(0,0,0,0.65)] backdrop-blur-2xl"
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.22, ease: [0.32, 0.72, 0, 1] }}
          >
            <div className="flex items-start gap-3">
              <RefreshCw className="mt-0.5 h-5 w-5 flex-shrink-0 text-[color:var(--color-accent)]" />
              <div>
                <h2
                  id="rescan-dialog-title"
                  className="text-base font-semibold text-[color:var(--color-ink)]"
                >
                  Rescan to confirm the fix?
                </h2>
                <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
                  {rescanPrompt.applied} change
                  {rescanPrompt.applied === 1 ? ' was' : 's were'} written into your files. Until
                  this project is scanned again, every finding on screen describes the code as it
                  was <em>before</em> the migration.
                </p>
                {(rescanPrompt.no_patch ?? 0) > 0 && (
                  <p className="mt-2 text-sm text-[color:var(--color-ink-faint)]">
                    {rescanPrompt.no_patch} finding
                    {rescanPrompt.no_patch === 1 ? ' had' : 's had'} no prepared change and{' '}
                    {rescanPrompt.no_patch === 1 ? 'was' : 'were'} left alone. Build the plan again
                    to generate {rescanPrompt.no_patch === 1 ? 'it' : 'them'}.
                  </p>
                )}
              </div>
            </div>
            <div className="mt-5 flex flex-wrap items-center justify-end gap-3">
              <button
                onClick={() => setRescanPrompt(null)}
                className="hud-btn hud-btn-ghost"
                data-testid="rescan-dialog-dismiss"
              >
                Not now
              </button>
              <button
                onClick={() => rescan.mutate()}
                disabled={rescan.isPending}
                className="hud-btn"
                data-testid="rescan-dialog-confirm"
                autoFocus
              >
                {rescan.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                Rescan now
              </button>
            </div>
            {rescan.isError && (
              <p className="mt-3 text-right text-xs text-[color:var(--color-danger)]">
                {rescan.error instanceof Error ? rescan.error.message : 'rescan failed'}
              </p>
            )}
          </motion.div>
        </div>
      )}
    </>
  );
}

/** Recent scans, newest first — the entry point the hub opens on.
 *
 *  A migration is always against ONE scan: the plan is built from that scan's findings, and the
 *  patches are written against the tree it recorded. Landing on a project grid asked the reader to
 *  pick a project and then work out which of its scans they meant; landing on the scans themselves
 *  is the same choice with the answer already in it. */
function RecentScans() {
  const openScan = useUiStore((s) => s.openScan);
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
  });
  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: fetchProjects,
  });
  const nameOf = (id: string) => projects?.find((p) => p.id === id)?.name ?? id.slice(0, 8);

  const usable = (scans ?? []).filter((s) => s.status === 'succeeded');

  if (isLoading) {
    return (
      <div className="glass-card flex items-center justify-center gap-3 p-12 text-[color:var(--color-ink-dim)]">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading scans…
      </div>
    );
  }
  if (!usable.length) {
    return (
      <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
        No finished scans yet. Run one from <span className="font-mono">Scans &amp; Jobs</span>, then
        come back here to migrate what it found.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <h2 className="flex items-center gap-2">
        <Layers className="h-5 w-5 text-[color:var(--color-accent)]" />
        Recent scans
      </h2>
      <p className="-mt-1 text-xs text-[color:var(--color-ink-faint)]">
        Open a scan to see everything it found that needs migrating.
      </p>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {usable.slice(0, 12).map((scan) => {
          // The previous scan of the SAME project, so the card can say which way this is going.
          // Without it a reader is left comparing a number to nothing, and the only figure on
          // screen was one a successful migration makes larger.
          const before = usable.find(
            (s) => s.project_id === scan.project_id && s.seq === scan.seq - 1,
          );
          const now = scan.stats?.vulnerable ?? 0;
          const then = before?.stats?.vulnerable;
          const delta = then == null ? null : now - then;
          return (
          <button
            key={scan.id}
            onClick={() => openScan(scan.project_id, scan.id)}
            data-testid={`migration-scan-${scan.id}`}
            className="glass-card flex flex-col gap-2 p-4 text-left transition-colors hover:border-[color:var(--color-accent)]/60"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate font-semibold text-[color:var(--color-accent-soft)]">
                {nameOf(scan.project_id)}
              </span>
              <span className="metric-label flex-shrink-0">#{scan.seq}</span>
            </div>
            <div
              className="truncate font-mono text-[11px] text-[color:var(--color-ink-faint)]"
              title={(scan.targets ?? []).join(', ')}
            >
              {(scan.targets ?? []).join(', ') || 'no target recorded'}
            </div>
            {/* Vulnerable is the headline, and total assets is the aside.
                A total asset count was the only number on this card, and it is the one number a
                migration is not supposed to reduce: replacing ECDSA with ML-DSA-65 does not remove
                a crypto asset, it changes one and usually adds an import, so a working migration
                makes this figure go UP. Measured across three scans of certbot: 490 → 488 → 493
                assets while vulnerable fell 293 → 268 and quantum-safe rose 197 → 225. Reading the
                cards alone, the tool looked like it was making the problem worse. */}
            <div className="mt-1 flex items-end justify-between">
              <span className="text-2xl font-bold tabular-nums text-[color:var(--color-danger)]">
                {scan.stats?.vulnerable ?? 0}
                <span className="metric-label ml-1.5">vulnerable</span>
              </span>
              <span className="metric-label tabular-nums">
                of {scan.stats?.assets ?? 0} assets
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="metric-label">
                {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : ''}
              </span>
              {delta !== null && delta !== 0 && (
                <span
                  className={`metric-label tabular-nums ${
                    delta < 0
                      ? 'text-[color:var(--color-safe)]'
                      : 'text-[color:var(--color-warn)]'
                  }`}
                  title={`Scan #${scan.seq - 1} found ${then} vulnerable; this one found ${now}.`}
                >
                  {delta < 0 ? `↓ ${Math.abs(delta)} fewer` : `↑ ${delta} more`} than #
                  {scan.seq - 1}
                </span>
              )}
            </div>
          </button>
          );
        })}
      </div>
    </div>
  );
}

/** A project whose migration has started but is not finished, or one whose changes have landed.
 *
 *  Split from the plain project grid because "what is still moving" and "what is done" are the two
 *  questions someone opens this hub to answer, and a single grid sorted by asset count answered
 *  neither. The numbers come from the tasks' own FSM states (see `ProjectPlanRef`'s progress
 *  fields), so a card can never disagree with the queue it links to. */
function MigrationCard({
  project,
  onOpen,
}: {
  project: ProjectOverview;
  onOpen: () => void;
}) {
  const plan = project.plan;
  if (!plan) return null;
  // Everything that has reached a resolved outcome, by any route: written to disk, resolved by a
  // guided procedure, or already compliant. Deliberately not just `written` — a certificate that
  // needs re-issuing is genuinely handled, and counting it as unfinished would make a completed
  // migration look stuck forever.
  const settled = plan.written + plan.guided + plan.satisfied;
  const total = settled + plan.outstanding + plan.prepared;
  const pct = total > 0 ? Math.round((settled / total) * 100) : 0;

  return (
    <button
      onClick={onOpen}
      data-testid={`migration-project-${project.slug}`}
      className="glass-card flex flex-col gap-2 p-4 text-left transition-colors hover:border-[color:var(--color-accent)]/60"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold text-[color:var(--color-accent-soft)]">
          {project.name}
        </span>
        <span className="metric-label flex-shrink-0 tabular-nums">{pct}%</span>
      </div>

      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[color:var(--edge)]">
        <div
          className="h-full rounded-full bg-[color:var(--color-safe)] transition-[width] duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="metric-label mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
        {plan.written > 0 && (
          <span className="text-[color:var(--color-safe)]" title="Written into the original files.">
            {plan.written} written
          </span>
        )}
        {plan.verified > 0 && (
          <span
            className="text-[color:var(--color-safe)]"
            title="Written and then proven by a rescan."
          >
            {plan.verified} verified
          </span>
        )}
        {plan.prepared > 0 && (
          <span
            className="text-[color:var(--color-accent)]"
            title="A validated diff exists and is waiting to be written."
          >
            {plan.prepared} prepared
          </span>
        )}
        {plan.outstanding > 0 && (
          <span title="Not yet attempted, or awaiting a retry.">{plan.outstanding} to go</span>
        )}
        {plan.guided > 0 && (
          <span title="Remediated by a written procedure rather than an edit QUBIT can make.">
            {plan.guided} guided
          </span>
        )}
        {plan.satisfied > 0 && (
          <span title="Nothing left to migrate — already covered, or already meeting the PQC floor.">
            {plan.satisfied} already compliant
          </span>
        )}
      </div>
    </button>
  );
}

/** The two progress sections between "Recent scans" and the full project grid. */
function MigrationProgressSections() {
  const setProjectId = useUiStore((s) => s.setProjectId);
  const { data } = useQuery({
    queryKey: ['projects-overview'],
    queryFn: fetchProjectsOverview,
  });

  const withPlans = (data ?? []).filter((p) => p.plan && p.plan.tasks > 0);
  // A migration is ONGOING while anything still has a step left — work not yet attempted, or a
  // prepared diff not yet written. Everything else with a plan that actually resolved something
  // is COMPLETE. Mutually exclusive, so a project appears in exactly one section and the two
  // never double-count the same work.
  const ongoing = withPlans.filter((p) => p.plan!.outstanding + p.plan!.prepared > 0);
  const complete = withPlans.filter(
    (p) =>
      p.plan!.outstanding + p.plan!.prepared === 0 &&
      p.plan!.written + p.plan!.guided + p.plan!.satisfied > 0,
  );

  return (
    <>
      <div className="flex flex-col gap-3" data-testid="ongoing-migrations">
        <h2 className="flex items-center gap-2">
          <Rocket className="h-5 w-5 text-[color:var(--color-accent)]" />
          Ongoing migrations
        </h2>
        <p className="-mt-1 text-xs text-[color:var(--color-ink-faint)]">
          Plans with work still to do — findings waiting to be generated, or diffs prepared and
          waiting to be written.
        </p>
        {ongoing.length === 0 ? (
          <div className="glass-card p-6 text-center text-sm text-[color:var(--color-ink-dim)]">
            Nothing in flight. Open a scan above and press{' '}
            <span className="font-mono">Build plan</span> to start one.
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {ongoing.map((p) => (
              <MigrationCard key={p.id} project={p} onOpen={() => setProjectId(p.id)} />
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-col gap-3" data-testid="successful-migrations">
        <h2 className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-[color:var(--color-safe)]" />
          Successful migrations
        </h2>
        <p className="-mt-1 text-xs text-[color:var(--color-ink-faint)]">
          Plans where every finding has reached an outcome — written to the files, routed to a
          guided procedure, or already compliant.
        </p>
        {complete.length === 0 ? (
          <div className="glass-card p-6 text-center text-sm text-[color:var(--color-ink-dim)]">
            None finished yet. A plan lands here once nothing is left waiting in its queue.
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {complete.map((p) => (
              <MigrationCard key={p.id} project={p} onOpen={() => setProjectId(p.id)} />
            ))}
          </div>
        )}
      </div>
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
        <>
          {/* Ordered as the work actually flows: what was found, what is being migrated, what is
              done. The grid stays last as the catch-all — it lists every project including ones
              with no plan yet, which the two progress sections deliberately exclude. */}
          <RecentScans />
          <MigrationProgressSections />
          <ProjectGrid
            metric="migration"
            title="Or browse by project"
            subtitle="A plan is built automatically when a scan finishes. Projects showing “plan outdated” have been scanned since theirs was built."
          />
        </>
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
