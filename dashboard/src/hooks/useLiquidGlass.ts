import { useRef } from 'react';

declare global {
  interface Window {
    // legacy SVG-refraction hook; no longer provided (glass is pure CSS). Optional so `?.` is a no-op.
    liquidGlass?: (el: Element, opts?: Record<string, unknown>) => {
      supported: boolean;
      refresh: () => void;
      destroy: () => void;
    };
  }
}

/**
 * No-op shim. The old SVG-refraction hack (window.liquidGlass) is gone — glassmorphism is now pure CSS
 * (see index.css: .glass / .glass-card / .liquid-panel + the .aurora field). Kept so existing imports
 * keep working; returns a ref you can attach or ignore.
 */
export function useLiquidGlass(_options?: {
  scale?: number;
  chroma?: number;
  border?: number;
  mapBlur?: number;
  blur?: number;
  saturate?: number;
  radius?: number;
  fallbackBlur?: number;
}) {
  return useRef<HTMLDivElement>(null);
}
