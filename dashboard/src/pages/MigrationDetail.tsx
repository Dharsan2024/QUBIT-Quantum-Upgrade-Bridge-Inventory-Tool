import { AnimatedPage } from '../components/AnimatedPage';
import { ArrowLeft, Terminal } from 'lucide-react';
import { Link } from 'react-router';

// Patch generation/approval is a qubit-migrate CLI workflow in M1; the API + interactive
// diff review land in M2. This page documents the real CLI flow rather than showing a
// fabricated diff.
const STEPS: { cmd: string; note: string }[] = [
  { cmd: 'qubit migrate plan <path>', note: 'Rank vulnerable assets and propose replacements.' },
  { cmd: 'qubit migrate generate <path> --branch pqc-migration', note: 'Generate codemod patches on a branch.' },
  { cmd: 'qubit migrate diff <path>', note: 'Review the generated unified diff.' },
  { cmd: 'qubit migrate apply <path>', note: 'Apply approved patches to disk.' },
];

export function MigrationDetail() {
  return (
    <AnimatedPage className="mx-auto flex max-w-4xl flex-col gap-5 py-4">
      <div className="mb-2 flex items-center gap-4 text-sm text-[color:var(--color-ink-faint)]">
        <Link
          to="/migrations"
          className="flex items-center gap-1 transition-colors hover:text-[color:var(--color-accent)]"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Queue
        </Link>
      </div>

      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Migration via the CLI</h1>
        <p className="mt-1 text-sm text-[color:var(--color-ink-dim)]">
          Plan, generate, and review run interactively on the{' '}
          <Link to="/migrations" className="text-indigo-300 hover:text-indigo-200">
            Migration Queue
          </Link>{' '}
          page. The equivalent <span className="font-mono">qubit migrate</span> CLI flow below also
          covers <span className="font-mono">apply</span>, which runs against a git checkout so the
          safety checks (clean tree, file-hash guard, branch/commit) execute where the code lives.
        </p>
      </header>

      <div className="glass-card flex flex-col divide-y divide-[color:var(--glass-border)]">
        {STEPS.map((s, i) => (
          <div key={s.cmd} className="flex items-start gap-4 p-5">
            <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full border border-indigo-400/30 bg-indigo-500/10 text-sm font-semibold text-indigo-300">
              {i + 1}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 overflow-x-auto rounded-lg border border-[color:var(--glass-border)] bg-black/40 px-3 py-2 font-mono text-sm text-indigo-300">
                <Terminal className="h-4 w-4 flex-shrink-0" />
                {s.cmd}
              </div>
              <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">{s.note}</p>
            </div>
          </div>
        ))}
      </div>
    </AnimatedPage>
  );
}
