import type { ReactNode } from 'react';

/**
 * Shared HUD readout tile — label on top, oversized figure bottom-left, ghosted glyph
 * bottom-right. The panel hairline is tinted to the tile's semantic colour.
 * Used on: Inventory, Risk, any future page that needs a top-row KPI strip.
 */
export function Kpi({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  color: string;
}) {
  return (
    <div
      className="glass-card flex h-32 flex-col justify-between p-5"
      style={{ borderColor: `color-mix(in srgb, ${color} 32%, transparent)` }}
    >
      <span className="metric-label" style={{ color }}>
        {label}
      </span>
      <div className="flex items-end justify-between gap-3">
        <span className="metric" style={{ color }}>
          {value}
        </span>
        <span className="opacity-25" style={{ color }}>
          {icon}
        </span>
      </div>
    </div>
  );
}
