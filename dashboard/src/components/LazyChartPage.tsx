import type { ReactNode } from 'react';
import { Suspense } from 'react';
import { Loader2 } from 'lucide-react';

function ChartPageFallback() {
  return (
    <div className="glass-card flex items-center justify-center gap-3 p-14 text-[color:var(--color-ink-dim)]">
      <Loader2 className="h-4 w-4 animate-spin" /> Loading charts…
    </div>
  );
}

/** Suspense boundary for the Plotly-backed pages (Risk, Timeline), which are lazy-loaded so the
 *  rest of the app doesn't pay for a ~4.7MB charting library it never uses. */
export function LazyChartPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<ChartPageFallback />}>{children}</Suspense>;
}
