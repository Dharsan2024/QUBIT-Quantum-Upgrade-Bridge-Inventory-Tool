import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Trash2, X, Loader2 } from 'lucide-react';
import {
  clearAllMigrationPlans,
  clearAllScans,
  fetchPlans,
  fetchProjects,
  fetchScans,
  resetAllProjects,
} from '../api/client';

/**
 * The three ways to throw work away, in one place, reachable from every page.
 *
 * They were reachable from exactly one panel before, which is the wrong shape for the thing people
 * reach for when a machine is out of disk or a run went wrong. `Layout` renders this in the top
 * rail, so it is present on every route without each page having to carry its own copy.
 *
 * The three are deliberately a ladder, weakest first, because "clear it" almost never means "clear
 * ALL of it" — rebuilding a plan is free, rescanning a corpus is not, and re-creating projects
 * loses the history every trend line is drawn from. Each rung names what it keeps, not only what
 * it destroys, and none of them fire on a single click.
 */

type Rung = {
  id: 'plans' | 'scans' | 'projects';
  label: string;
  count: (n: Counts) => number;
  noun: string;
  destroys: string;
  keeps: string;
  run: () => Promise<{ deleted: number }>;
  tone: string;
};

type Counts = { projects: number; scans: number; plans: number };

const RUNGS: Rung[] = [
  {
    id: 'plans',
    label: 'Clear migrations',
    count: (c) => c.plans,
    noun: 'plan',
    destroys: 'every migration plan, its queue, its patches and its history',
    keeps: 'every scan and every finding — rebuild the plan with one click',
    run: clearAllMigrationPlans,
    tone: 'text-[color:var(--color-accent)]',
  },
  {
    id: 'scans',
    label: 'Clear scans',
    count: (c) => c.scans,
    noun: 'scan',
    destroys: 'every scan, its findings, and the migrations built from them',
    keeps: 'the project shells, so a repeat scan has somewhere to land',
    run: clearAllScans,
    tone: 'text-[color:var(--color-warn)]',
  },
  {
    id: 'projects',
    label: 'Reset everything',
    count: (c) => c.projects,
    noun: 'project',
    destroys: 'every project, scan, finding, migration and applied-patch record',
    keeps: 'nothing but your settings — trend history cannot be rebuilt',
    run: resetAllProjects,
    tone: 'text-[color:var(--color-danger)]',
  },
];

export function CleanupMenu() {
  const [open, setOpen] = useState(false);
  const [armed, setArmed] = useState<Rung['id'] | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const panel = useRef<HTMLDivElement>(null);
  const qc = useQueryClient();

  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: fetchProjects });
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });
  // Plans across every project: the menu is global, so the count has to be too.
  const { data: plans } = useQuery({ queryKey: ['plans', 'all'], queryFn: () => fetchPlans() });
  const counts: Counts = {
    projects: projects?.length ?? 0,
    scans: scans?.length ?? 0,
    plans: plans?.length ?? 0,
  };

  const mutation = useMutation({
    mutationFn: (rung: Rung) => rung.run(),
    onSuccess: (res, rung) => {
      setDone(`Removed ${res.deleted} ${rung.noun}${res.deleted === 1 ? '' : 's'}.`);
      setArmed(null);
      // Everything downstream of a delete is now wrong, and the pages that show it are mounted.
      qc.invalidateQueries();
    },
  });

  // Close on Escape and on an outside click, and always disarm — an armed destructive button left
  // behind a closed panel is a click waiting to happen to the wrong person.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    const onClick = (e: MouseEvent) => {
      if (panel.current && !panel.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onClick);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onClick);
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      setArmed(null);
      setDone(null);
    }
  }, [open]);

  return (
    <div className="relative" ref={panel}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="hud-btn py-2"
        data-testid="cleanup-open"
        title="Remove previous migrations, scans or projects"
      >
        <Trash2 className="h-3.5 w-3.5" />
        Clean up
      </button>

      {open && (
        <div
          className="glass absolute right-0 top-11 z-50 w-[27rem] rounded-[4px] p-4 shadow-2xl"
          data-testid="cleanup-panel"
        >
          <div className="mb-3 flex items-center justify-between">
            <div className="label-caps text-[color:var(--color-accent)]">Remove previous work</div>
            <button
              onClick={() => setOpen(false)}
              className="text-[color:var(--color-ink-faint)] hover:text-[color:var(--color-ink)]"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-2">
            {RUNGS.map((rung) => {
              const n = rung.count(counts);
              const isArmed = armed === rung.id;
              const busy = mutation.isPending && mutation.variables?.id === rung.id;
              return (
                <div
                  key={rung.id}
                  className="rounded-[3px] border border-[color:var(--edge)] p-3"
                  data-testid={`cleanup-row-${rung.id}`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className={`text-sm font-semibold ${rung.tone}`}>{rung.label}</div>
                    <div className="font-mono text-[11px] text-[color:var(--color-ink-faint)]">
                      {n} {rung.noun}
                      {n === 1 ? '' : 's'}
                    </div>
                  </div>
                  <div className="mt-1 text-[11px] leading-relaxed text-[color:var(--color-ink-dim)]">
                    <div>
                      <span className="text-[color:var(--color-ink-faint)]">Removes</span>{' '}
                      {rung.destroys}.
                    </div>
                    <div>
                      <span className="text-[color:var(--color-ink-faint)]">Keeps</span> {rung.keeps}.
                    </div>
                  </div>

                  {/* Two steps, never one. The second button says the number out loud, because
                      "Clear scans" and "delete 41 scans" are read very differently. */}
                  {isArmed ? (
                    <div className="mt-2 flex items-center gap-2">
                      <button
                        onClick={() => mutation.mutate(rung)}
                        disabled={busy}
                        className="hud-btn hud-btn-danger py-1.5 text-[11px]"
                        data-testid={`cleanup-confirm-${rung.id}`}
                      >
                        {busy && <Loader2 className="h-3 w-3 animate-spin" />}
                        Yes, delete {n} {rung.noun}
                        {n === 1 ? '' : 's'}
                      </button>
                      <button
                        onClick={() => setArmed(null)}
                        className="text-[11px] text-[color:var(--color-ink-faint)] hover:text-[color:var(--color-ink)]"
                        data-testid={`cleanup-cancel-${rung.id}`}
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => {
                        setDone(null);
                        setArmed(rung.id);
                      }}
                      disabled={n === 0 || mutation.isPending}
                      className="hud-btn mt-2 py-1.5 text-[11px] disabled:opacity-40"
                      data-testid={`cleanup-arm-${rung.id}`}
                    >
                      {n === 0 ? 'Nothing to remove' : rung.label}
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {/* The one thing that survives all three, said plainly — it is the only part of a wipe
              that would be expensive to get back, so people should not have to guess. */}
          <div className="mt-3 rounded-[3px] border border-[color:var(--color-safe)]/25 bg-[color:var(--color-safe)]/8 px-3 py-2 text-[11px] text-[color:var(--color-ink-dim)]">
            <span className="text-[color:var(--color-safe)]">Kept either way:</span> what QUBIT has
            learned — its validated fixes and per-engine reliability record. Those carry no scan or
            project id, so nothing here reaches them.
          </div>

          {done && (
            <div
              className="mt-2 text-[11px] text-[color:var(--color-safe)]"
              data-testid="cleanup-result"
            >
              {done}
            </div>
          )}
          {mutation.isError && (
            <div className="mt-2 text-[11px] text-[color:var(--color-danger)]">
              {(mutation.error as Error).message}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
