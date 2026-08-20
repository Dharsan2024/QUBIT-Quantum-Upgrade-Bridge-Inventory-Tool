import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import {
  CalendarClock,
  CheckCircle2,
  CircleDashed,
  CircleSlash,
  Landmark,
  RefreshCw,
  Terminal,
  TriangleAlert,
} from 'lucide-react';
import { fetchCnsa2 } from '../api/client';
import { useActiveScan } from '../hooks/useActiveScan';
import { useUiStore } from '../stores/ui';
import { ProjectGrid } from '../components/ProjectGrid';
import { ProjectScopeBar } from '../components/ProjectScopeBar';
import type { Cnsa2Milestone } from '../api/types';

/**
 * CNSA 2.0 compliance posture — the deterministic, regulatory counterpart to the Risk page.
 *
 * The risk engine answers "what should we fix first" probabilistically. This answers a different
 * question with a fixed answer: NSA's CNSA 2.0 milestones carry real dates (2025 → 2035), so a
 * scan either does or does not show the required algorithm classes by each one.
 *
 * IMPORTANT presentation decision. The backend's `overall_score` is *schedule adherence*, not PQC
 * readiness: a milestone that is not yet due scores full marks, because you are not late yet. Today
 * that means a scan with three non-compliant future milestones still scores 100. Showing that number
 * alone under a heading like "compliance" would be actively misleading, so this page always shows
 * readiness (how many milestones are actually satisfied) next to it, and labels each for what it is.
 * The upstream implementation this was ported from had a documented bug from exactly this
 * conflation, and the fix is to keep the two questions visibly separate rather than to pick one.
 */

const STATUS_META: Record<
  Cnsa2Milestone['status'],
  { label: string; cls: string; icon: typeof CheckCircle2 }
> = {
  compliant: {
    label: 'Compliant',
    cls: 'border-[color:var(--color-safe)]/40 bg-[color:var(--color-safe)]/10 text-[color:var(--color-safe)]',
    icon: CheckCircle2,
  },
  partial: {
    label: 'Partial',
    cls: 'border-[color:var(--color-amber-400)]/40 bg-[color:var(--color-amber-400)]/10 text-[color:var(--color-amber-300)]',
    icon: TriangleAlert,
  },
  'in-progress': {
    label: 'In progress',
    cls: 'border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent)]/10 text-[color:var(--color-accent)]',
    icon: CircleDashed,
  },
  'non-compliant': {
    label: 'Non-compliant',
    cls: 'border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 text-[color:var(--color-danger)]',
    icon: CircleSlash,
  },
};

function StatusPill({ status }: { status: Cnsa2Milestone['status'] }) {
  const meta = STATUS_META[status];
  const Icon = meta.icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-[3px] border px-2 py-1 font-mono text-[11px] ${meta.cls}`}
    >
      <Icon className="h-3 w-3" />
      {meta.label}
    </span>
  );
}

export function Compliance() {
  const { activeScanId, activeScan } = useActiveScan();
  const projectId = useUiStore((s) => s.projectId);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['cnsa2', activeScanId],
    queryFn: () => fetchCnsa2(activeScanId as string),
    enabled: !!activeScanId,
  });

  const milestones = data?.milestones ?? [];
  const satisfied = milestones.filter((m) => m.status === 'compliant').length;
  const overdue = milestones.filter((m) => m.is_due && m.status !== 'compliant').length;

  // Placed below every hook on purpose. React requires the same hooks to run in the same order on
  // every render, so an early return above `useQuery` makes the hook count change the moment a
  // project is chosen — which crashed this page with React error #310 (caught by the browser
  // suite, not by tsc, which cannot see hook order).
  if (!projectId) {
    return (
      <AnimatedPage
        className="flex flex-col gap-6 py-5"
        data-testid="compliance-root"
        aria-label="CNSA 2.0 compliance posture"
      >
        <header>
          <h1 className="flex items-center gap-3">
            <Landmark className="h-8 w-8 text-[color:var(--color-accent)]" />
            CNSA 2.0 Posture
          </h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            Posture is evaluated per project against NSA&apos;s mandated milestones (2025 → 2035).
            Open a project to see its milestone verdicts.
          </p>
        </header>

        <ProjectGrid
          metric="vulnerable"
          title="Compliance by project"
          subtitle="Quantum-vulnerable assets are what the CNSA 2.0 milestones are measured against."
        />
      </AnimatedPage>
    );
  }

  return (
    <AnimatedPage
      className="flex flex-col gap-6 py-5"
      data-testid="compliance-root"
      aria-label="CNSA 2.0 compliance posture"
    >
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3">
            <Landmark className="h-8 w-8 text-[color:var(--color-accent)]" />
            CNSA 2.0 Posture
          </h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            {activeScan
              ? `NSA Commercial National Security Algorithm Suite 2.0 · scan #${activeScan.seq} · ${data?.assets_evaluated ?? 0} assets evaluated`
              : 'Your inventory measured against NSA’s mandated migration milestones (2025 → 2035).'}
          </p>
        </div>
        {data && (
          <p className="font-mono text-xs text-[color:var(--color-ink-faint)]">
            evaluated as of {data.as_of}
          </p>
        )}
      </header>

      <ProjectScopeBar />

      {!activeScanId && (
        <div className="glass-card p-8 text-center text-sm text-[color:var(--color-ink-dim)]">
          No scans yet.{' '}
          <Link
            to="/scans"
            className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]"
          >
            Run a scan
          </Link>{' '}
          to evaluate CNSA 2.0 posture.
        </div>
      )}

      {isLoading && activeScanId && (
        <div className="glass-card flex items-center justify-center gap-3 p-14 text-[color:var(--color-ink-dim)]">
          <RefreshCw className="h-4 w-4 animate-spin" /> Evaluating milestones…
        </div>
      )}

      {isError && (
        <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)]">
          Could not evaluate CNSA 2.0 posture:{' '}
          {error instanceof Error ? error.message : 'unknown error'}.
        </div>
      )}

      {data && (
        <>
          {/* Two scores, deliberately side by side. See the note in this file's header: reporting
              schedule adherence alone would read as "you are done" while future milestones fail. */}
          <div className="grid grid-cols-1 gap-5 md:grid-cols-3">
            <div className="glass-card flex flex-col gap-2 p-6">
              <p className="metric-label">On schedule</p>
              <p className="font-mono text-4xl font-bold text-[color:var(--color-accent)]">
                {data.overall_score.toFixed(0)}
                <span className="text-xl text-[color:var(--color-ink-faint)]">%</span>
              </p>
              <p className="text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                Weighted adherence to deadlines that have <em>already passed</em>. A milestone that is
                not yet due counts as met — this measures lateness, not readiness.
              </p>
            </div>

            <div className="glass-card flex flex-col gap-2 p-6">
              <p className="metric-label">PQC readiness</p>
              <p className="font-mono text-4xl font-bold text-[color:var(--color-ink)]">
                {satisfied}
                <span className="text-xl text-[color:var(--color-ink-faint)]">
                  /{milestones.length}
                </span>
              </p>
              <p className="text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                Milestones whose required algorithm classes are actually present in this inventory
                today, regardless of deadline.
              </p>
            </div>

            <div className="glass-card flex flex-col gap-2 p-6">
              <p className="metric-label">Next deadline</p>
              <p className="font-mono text-4xl font-bold text-[color:var(--color-ink)]">
                {data.days_to_next_deadline ?? '—'}
                {data.days_to_next_deadline != null && (
                  <span className="text-xl text-[color:var(--color-ink-faint)]"> days</span>
                )}
              </p>
              <p className="text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                {data.next_deadline
                  ? `${data.next_deadline} · current phase: ${data.current_phase}`
                  : 'All milestone dates have passed.'}
              </p>
            </div>
          </div>

          {overdue > 0 && (
            <div className="glass-card flex items-start gap-3 border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4">
              <TriangleAlert className="mt-0.5 h-4 w-4 flex-none text-[color:var(--color-danger)]" />
              <p className="text-sm text-[color:var(--color-danger)]">
                {overdue} milestone{overdue === 1 ? '' : 's'} past its deadline and not met. This is
                the only figure that represents a missed mandate.
              </p>
            </div>
          )}

          <div className="glass-card flex flex-col gap-3 p-6">
            <h3 className="label-caps flex items-center gap-2 text-[color:var(--color-accent)]/70">
              <CalendarClock className="h-4 w-4" /> Recommended next action
            </h3>
            <p className="text-sm leading-relaxed text-[color:var(--color-ink)]">
              {data.next_action}
            </p>
          </div>

          <div className="glass-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead>
                  <tr className="border-b border-[color:var(--edge)]">
                    <th className="metric-label px-5 py-3">Milestone</th>
                    <th className="metric-label px-5 py-3">Deadline</th>
                    <th className="metric-label px-5 py-3">Status</th>
                    <th className="metric-label px-5 py-3 text-right">Weight</th>
                    <th className="metric-label px-5 py-3">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {milestones.map((m) => (
                    <tr
                      key={m.name}
                      className="border-b border-[color:var(--edge)]/50 last:border-0"
                    >
                      <td className="px-5 py-4 font-medium text-[color:var(--color-ink)]">
                        {m.name}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs whitespace-nowrap">
                        {m.deadline}
                        <span
                          className={
                            m.is_due
                              ? 'ml-2 text-[color:var(--color-danger)]'
                              : 'ml-2 text-[color:var(--color-ink-faint)]'
                          }
                        >
                          {m.is_due ? 'due' : 'upcoming'}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        <StatusPill status={m.status} />
                      </td>
                      <td className="px-5 py-4 text-right font-mono text-xs tabular-nums">
                        {m.weight}
                      </td>
                      <td className="px-5 py-4 text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
                        {m.evidence}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="glass-card flex flex-col gap-4 p-6">
            <h3 className="label-caps flex items-center gap-2 text-[color:var(--color-accent)]/70">
              <Terminal className="h-4 w-4" /> What this measures
            </h3>
            <p className="text-xs leading-relaxed text-[color:var(--color-ink-dim)]">
              A milestone's status answers whether the required algorithm class appears anywhere in
              the inventory — not whether every asset is compliant. Those are different questions and
              answering them as one produces contradictory verdicts for the same scan, so QUBIT
              reports only the milestone question here. Per-asset remediation lives on the{' '}
              <Link
                to="/migrations"
                className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]"
              >
                Migrations
              </Link>{' '}
              page, and the probabilistic view on{' '}
              <Link
                to="/risk"
                className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]"
              >
                Risk Posture
              </Link>
              .
            </p>
          </div>
        </>
      )}
    </AnimatedPage>
  );
}
