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
 * Page transition with 3D depth: content arrives from slightly behind the screen plane and settles
 * forward, so navigating feels like moving through layers rather than swapping flat images.
 * Uses full transform strings (GPU-accelerated) and collapses to a plain fade under reduced-motion.
 */
export function AnimatedPage({ children, className = '', ...rest }: AnimatedPageProps) {
  const reduce = useReducedMotion();

  const anim = reduce
    ? { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }
    : {
        initial: { opacity: 0, transform: 'perspective(1200px) translate3d(0, 18px, -60px)' },
        animate: { opacity: 1, transform: 'perspective(1200px) translate3d(0, 0px, 0px)' },
        exit: { opacity: 0, transform: 'perspective(1200px) translate3d(0, -12px, -30px)' },
      };

  return (
    <motion.div
      {...anim}
      {...rest}
      transition={{ duration: 0.42, ease: [0.23, 1, 0.32, 1] }}
      className={`w-full ${className}`}
      style={{ transformStyle: 'preserve-3d' }}
    >
      {children}
    </motion.div>
  );
}
