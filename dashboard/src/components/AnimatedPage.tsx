import { motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';

interface AnimatedPageProps {
  children: ReactNode;
  className?: string;
  /** Any remaining DOM attributes (`data-testid`, `aria-label`, `id`, …) are forwarded to the
   *  wrapper. Without this they were silently DROPPED: a page could set `data-testid` and it would
   *  never reach the DOM, so anything trying to address that page's content had to fall back to
   *  matching on visible text — which collides with the sidebar's nav labels. */
  [key: `data-${string}`]: unknown;
  'aria-label'?: string;
  id?: string;
  role?: string;
}

/**
 * Page entrance: content rises and fades in, then behaves like ordinary layout.
 *
 * **This deliberately does NOT use a 3D transform, and that is a correctness requirement rather than
 * a style preference.** It previously animated `perspective(1200px) translate3d(...)` with
 * `transformStyle: preserve-3d`, which left a live 3D rendering context on the wrapper at rest —
 * every page in the app is wrapped here, so that applied everywhere. Inside such a context the
 * projected geometry shifts whenever the page's layout changes, Chromium's compositor hit-testing
 * and `getBoundingClientRect()` stop agreeing, and a real mouse click at the visible centre of a
 * control lands on nothing.
 *
 * How it presented and how it was pinned down:
 *   - On the Scans page, the first click on a source tab worked and every click after it silently
 *     did nothing — no error, no console output, correct-looking DOM.
 *   - `page.mouse.click` at the element's real coordinates failed exactly as a human's click did,
 *     while a synthetic `dispatchEvent('click')` still worked. That separated "the handler and React
 *     state are broken" (they were not) from "the event never arrives" (it did not).
 *   - Re-running with `reducedMotion: 'reduce'`, which skipped the transform, made every click work.
 *   - Tab widths differed at rest depending on which panel was open (237px vs 241px) — the
 *     projection drifting as layout changed.
 *
 * Animating to an *identity* 3D transform does not fix it (the context still exists), and animating
 * to `transform: none` does not either, because framer-motion will not interpolate a `matrix3d` to
 * `none` — the perspective simply stays applied. So the entrance is now a plain 2D `y` offset, which
 * resolves to an identity `matrix(1, 0, 0, 1, 0, 0)` at rest and cannot project anything. The visual
 * result is nearly identical: content still rises into place as the page loads.
 */
export function AnimatedPage({ children, className = '', ...rest }: AnimatedPageProps) {
  const reduce = useReducedMotion();

  const anim = reduce
    ? { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }
    : {
        initial: { opacity: 0, y: 18 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -12 },
      };

  return (
    <motion.div
      {...anim}
      {...rest}
      transition={{ duration: 0.42, ease: [0.23, 1, 0.32, 1] }}
      className={`w-full ${className}`}
    >
      {children}
    </motion.div>
  );
}
