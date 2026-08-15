---
name: Quantum Command
colors:
  surface: '#111319'
  surface-dim: '#111319'
  surface-bright: '#37393f'
  surface-container-lowest: '#0c0e14'
  surface-container-low: '#191c21'
  surface-container: '#1d2025'
  surface-container-high: '#272a30'
  surface-container-highest: '#32353b'
  on-surface: '#e1e2ea'
  on-surface-variant: '#bbc9cd'
  inverse-surface: '#e1e2ea'
  inverse-on-surface: '#2e3037'
  outline: '#859397'
  outline-variant: '#3c494c'
  surface-tint: '#29d9f7'
  primary: '#c1f2ff'
  on-primary: '#00363f'
  primary-container: '#38e0ff'
  on-primary-container: '#00606f'
  inverse-primary: '#006878'
  secondary: '#cabeff'
  on-secondary: '#31009a'
  secondary-container: '#4816cb'
  on-secondary-container: '#b9aaff'
  tertiary: '#87ffe1'
  on-tertiary: '#00382d'
  tertiary-container: '#56e4c5'
  on-tertiary-container: '#006352'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#a7edff'
  primary-fixed-dim: '#29d9f7'
  on-primary-fixed: '#001f25'
  on-primary-fixed-variant: '#004e5b'
  secondary-fixed: '#e6deff'
  secondary-fixed-dim: '#cabeff'
  on-secondary-fixed: '#1c0062'
  on-secondary-fixed-variant: '#4816cb'
  tertiary-fixed: '#6ef9d9'
  tertiary-fixed-dim: '#4ddcbd'
  on-tertiary-fixed: '#002019'
  on-tertiary-fixed-variant: '#005143'
  background: '#111319'
  on-background: '#e1e2ea'
  surface-variant: '#32353b'
typography:
  display-lg:
    fontFamily: Space Grotesk
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Space Grotesk
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: 0.05em
  headline-sm:
    fontFamily: Space Grotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: 0.05em
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: 0.02em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.1em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 24px
  margin: 40px
  panel-padding: 24px
---

## Brand & Style

This design system establishes a high-fidelity, HUD-inspired interface for cybersecurity professionals managing quantum transitions. The personality is hyper-technical, vigilant, and futuristic. 

The aesthetic leverages **Glassmorphism** and **Tactile HUD** elements to create a sense of depth and data density. It prioritizes "Information at a Glance" through a layered architecture where surfaces appear as translucent holographic glass floating over a deep-space structural grid. Visual interest is driven by luminous hairline strokes, neon accents, and subtle bloom effects that simulate a light-emitting display.

## Colors

The palette is rooted in a deep-space obsidian (#05070C) to maximize the contrast of luminous elements. 

- **Primary (Holographic Cyan):** Used for interactive states, primary focus areas, and critical HUD accents.
- **Secondary (Plasma Violet):** Used for secondary data visualizations, decorative accents, and tertiary navigation.
- **Backgrounds:** Use a 1px blueprint grid overlaying the neutral base. The grid cells should be 40px with sub-divisions at 10px, rendered in #38E0FF at 5% opacity.
- **Overlays:** Surfaces utilize a high-opacity blur (30px+) with a base fill of #0B0E14 at 60% transparency.

## Typography

Typography functions as a functional readout. **Space Grotesk** provides a technical, geometric feel for headings, while **Inter** ensures long-form legibility for documentation and reports. 

All technical strings—including hashes, IP addresses, algorithms (e.g., Kyber, Dilithium), and console logs—must use **JetBrains Mono**. To enhance the HUD effect, all "label-caps" should be rendered in uppercase. Text colors should primarily be off-white (#E0E6ED) for body text and Luminous Cyan for technical headers to signify interactivity.

## Layout & Spacing

This design system utilizes a **Fluid Grid** model designed for ultra-wide displays. Layouts should span the full width of the viewport, avoiding constrained center columns.

- **Breakpoints:** Desktop (1440px+), Tablet (1024px), Mobile (600px).
- **Structure:** Content is organized into "Modules" or "Panels." Each panel is separated by a 24px gutter.
- **HUD Accents:** Every major container should feature "Corner Ticks"—4px L-shaped brackets in the corners of the panel to reinforce the technical interface aesthetic.
- **Information Density:** High density is encouraged. Use Flexbox and CSS Grid to stack data visualization components horizontally.

## Elevation & Depth

Depth is conveyed through **Light Emittance** and **Transparency** rather than traditional shadows.

1.  **Level 0 (Floor):** The blueprint grid background.
2.  **Level 1 (Panels):** Translucent glass surfaces. 1px solid stroke (#38E0FF at 20% opacity). 40px Backdrop Blur.
3.  **Level 2 (Modals/Popovers):** Elevated glass. 1px solid stroke (#38E0FF at 50% opacity). Outer Glow: 0px 0px 15px rgba(56, 224, 255, 0.15).
4.  **Interactive States:** On hover, elements should increase their "Bloom" (outer glow) and shift their stroke opacity to 100%.

Use a subtle `0.5deg` 3D tilt effect on primary dashboard panels that reacts to the user's cursor position.

## Shapes

The shape language is architectural and precise. While most elements use a "Soft" 4px radius (`roundedness: 1`), certain UI elements like progress bars and technical chips should feature "Clipped" or "Chamfered" corners (45-degree cuts) to reinforce the military-grade/technical theme. 

Buttons and input fields maintain the 4px radius for consistent interaction mapping.

## Components

- **Glass Buttons:** Primary buttons feature a semi-transparent cyan fill (20%) with a 100% cyan border and a subtle "inner-top" white highlight. Text is always uppercase JetBrains Mono.
- **Technical Chips:** Used for tags (e.g., "AES-256"). These should have no fill, a 1px border, and a small dot icon preceding the text.
- **Risk Bars:** Segmented progress bars. Instead of a smooth fill, use vertical blocks to indicate progress. Colors transition from Cyan (Safe) to Violet (Transitioning) to Red (Vulnerable).
- **Data Tables:** Row-based with no vertical borders. Hovering a row triggers a full-width cyan tint (5% opacity) and highlights the row's edge with a vertical cyan line.
- **Inputs:** Dark backgrounds (#000) with a bottom-only 1px cyan border that glows when focused.
- **Charts:** Line charts must use "Neon" paths with a gradient fill below the line that fades to transparent. Animate lines using a `stroke-dashoffset` draw-in effect on load.
- **HUD Widgets:** Include "scanning" animations—a horizontal light bar that moves vertically across a panel periodically to simulate an active system check.