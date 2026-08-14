import { motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';

interface AnimatedPageProps {
  children: ReactNode;
  className?: string;
}

/**
 * Page transition with 3D depth: content arrives from slightly behind the screen plane and settles
 * forward, so navigating feels like moving through layers rather than swapping flat images.
 * Uses full transform strings (GPU-accelerated) and collapses to a plain fade under reduced-motion.
 */
export function AnimatedPage({ children, className = '' }: AnimatedPageProps) {
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
      transition={{ duration: 0.42, ease: [0.23, 1, 0.32, 1] }}
      className={`w-full ${className}`}
      style={{ transformStyle: 'preserve-3d' }}
    >
      {children}
    </motion.div>
  );
}
