/**
 * What QUBIT has learned from its own migrations.
 *
 * A tool that claims to get better with use has to be able to show it, and until this existed the
 * evidence was a row count in a table nobody could see. The two stores are reported separately
 * because they do different jobs and one of them was doing almost none of the work:
 *
 * - the **line cache** replays an exact line with no model call at all;
 * - the **experience base** grounds a fresh call on structurally similar work already validated,
 *   including the multi-line rewrites the cache refuses to hold.
 *
 * Failures are shown beside successes on purpose. A rejection this project has already paid for
 * is worth as much as a success — it is what stops the next attempt walking into the same wall —
 * and hiding it would make the panel a scoreboard rather than a record.
 */
import { useQuery } from '@tanstack/react-query';
import { Brain } from 'lucide-react';

import { fetchLearning } from '../api/client';

function Stat({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="flex flex-col gap-0.5" title={hint}>
      <span className="font-[family-name:var(--font-display)] text-lg text-[color:var(--color-ink)]">
        {value.toLocaleString()}
      </span>
      <span className="metric-label">{label}</span>
    </div>
  );
}

export function LearningPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ['migrate-learning'],
    queryFn: fetchLearning,
    // Written by the validation gate during a run, so it changes while the user is watching.
    refetchInterval: 15_000,
  });

  if (isLoading || !data) return null;
  const nothingYet =
    data.cached_lines === 0 && data.proven_rewrites === 0 && data.retained_failures === 0;

  return (
    <div className="glass-card p-4" data-testid="learning-panel">
      <div className="mb-3 flex items-center gap-2">
        <Brain className="h-4 w-4 text-[color:var(--color-accent-2)]" />
        <span className="label-caps text-[color:var(--color-accent-2)]">What QUBIT has learned</span>
        <span
          className="metric-label ml-auto"
          title="Written by the validation gate, not by the model: a rewrite is only retained after it passed, and a rejection only after the gate refused it. Nothing here leaves this machine."
        >
          local · gate-verified
        </span>
      </div>

      {nothingYet ? (
        <p className="text-xs text-[color:var(--color-ink-faint)]">
          Nothing yet. Every migration that passes validation is retained here — the rewrite, the
          reasoning behind it, and the rejections worth not repeating — so later findings of the
          same shape start from work already proven rather than from nothing.
        </p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <Stat
              label="Proven rewrites"
              value={data.proven_rewrites}
              hint="Validated rewrites retained with the reasoning that went with them, including multi-line ones. These ground a fresh call on structurally similar work."
            />
            <Stat
              label="Cached lines"
              value={data.cached_lines}
              hint="Exact line replacements that can be replayed with no model call at all. Still validated before they are proposed."
            />
            <Stat
              label="Answered from cache"
              value={data.cache_hits}
              hint="Findings answered by replaying a stored line instead of calling the model."
            />
            <Stat
              label="Grounding replays"
              value={data.grounding_uses}
              hint="How often stored experience has been put into a prompt to condition a fresh generation."
            />
            <Stat
              label="Rejections kept"
              value={data.retained_failures}
              hint="Dead ends this project has already paid for. Replayed to the model as warnings so the same attempt is not made twice."
            />
          </div>

          {data.by_rule.length > 0 && (
            <div className="mt-4 border-t border-[color:var(--edge)] pt-3">
              <div className="metric-label mb-2">By rule and language</div>
              <div className="flex flex-col gap-1">
                {data.by_rule.slice(0, 8).map((row) => (
                  <div
                    key={`${row.rule_id}:${row.language}`}
                    className="flex items-center gap-3 text-xs"
                  >
                    <span className="font-mono text-[color:var(--color-ink-dim)]">
                      {row.rule_id}
                    </span>
                    <span className="text-[color:var(--color-ink-faint)]">{row.language}</span>
                    <span className="ml-auto flex gap-3">
                      <span className="text-[color:var(--color-safe)]" title="verified rewrites">
                        {row.proven} proven
                      </span>
                      <span className="text-[color:var(--color-warn)]" title="rejections retained">
                        {row.warnings} to avoid
                      </span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
