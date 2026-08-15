import { lazy } from 'react';

// Risk and Timeline pull in Plotly (~4.7MB unminified, the single largest dependency in the
// app) purely for their charts. Every other page is lightweight, so only these two are
// code-split — lazy-loading the rest would add Suspense overhead for no real size win.
// Isolated in this file (rather than declared in router.tsx) so router.tsx stays a pure route
// table with no component-shaped local bindings, which is what oxlint's react-refresh rule wants.
export const Risk = lazy(() => import('./Risk').then((m) => ({ default: m.Risk })));
export const Timeline = lazy(() => import('./Timeline').then((m) => ({ default: m.Timeline })));
