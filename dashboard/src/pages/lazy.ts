import { lazy } from 'react';

// Every route-level page except Login and Projects is code-split.
//
// Risk and Timeline came first, because they pull in Plotly (~4.7MB unminified, the single
// largest dependency in the app) purely for their charts. The rest followed once the initial
// chunk was measured at 4.66MB: nine pages were bundled eagerly, so opening Projects downloaded
// Migrations (1783 lines), Scans, Report, Compliance, Cbom and Inventory too, none of which that
// view can reach without a navigation.
//
// Login and Projects stay eager on purpose. They are the first two views of every session — the
// pre-auth entry and the landing grid — so splitting them only trades bytes for a loading
// spinner on the exact path that has nothing else to do.
//
// Isolated in this file (rather than declared in router.tsx) so router.tsx stays a pure route
// table with no component-shaped local bindings, which is what oxlint's react-refresh rule wants.
export const Risk = lazy(() => import('./Risk').then((m) => ({ default: m.Risk })));
export const Timeline = lazy(() => import('./Timeline').then((m) => ({ default: m.Timeline })));
export const Migrations = lazy(() =>
  import('./Migrations').then((m) => ({ default: m.Migrations })),
);
export const Scans = lazy(() => import('./Scans').then((m) => ({ default: m.Scans })));
export const Report = lazy(() => import('./Report').then((m) => ({ default: m.Report })));
export const Compliance = lazy(() =>
  import('./Compliance').then((m) => ({ default: m.Compliance })),
);
export const Inventory = lazy(() => import('./Inventory').then((m) => ({ default: m.Inventory })));
export const Cbom = lazy(() => import('./Cbom').then((m) => ({ default: m.Cbom })));
export const Settings = lazy(() => import('./Settings').then((m) => ({ default: m.Settings })));
