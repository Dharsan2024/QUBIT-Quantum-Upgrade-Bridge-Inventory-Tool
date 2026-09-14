import type { ReactNode } from 'react';
import { Suspense } from 'react';
import { Loader2 } from 'lucide-react';

function PageFallback() {
  return (
    <div className="glass-card flex items-center justify-center gap-3 p-14 text-[color:var(--color-ink-dim)]">
      <Loader2 className="h-4 w-4 animate-spin" /> Loading…
    </div>
  );
}

/** Suspense boundary for every code-split route (see `pages/lazy.ts` for which pages and why).
 *
 *  Was `LazyChartPage`, wrapping only the two Plotly-backed pages; the fallback said "Loading
 *  charts…", which became wrong the moment Migrations and Scans were split too. */
export function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<PageFallback />}>{children}</Suspense>;
}
