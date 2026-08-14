# QUBIT — Stitch Design Prompt Kit ("JARVIS Holographic" theme)

**How to use.** Google Stitch generates **one screen per prompt**. So:
1. Paste **§1 (Global Design System)** at the top of *every* screen prompt — it's the style contract.
2. Then paste **one screen block from §2** underneath it.
3. Repeat for each of the 11 screens. Ask Stitch for **dark mode, desktop 1600×1000** every time.

Tip: generate `Inventory` first — it's the densest screen and sets the visual language for the rest.

---

## §1 — GLOBAL DESIGN SYSTEM (prepend to every prompt)

```
You are designing a desktop application UI called QUBIT — a post-quantum cryptography security
analysis tool. The aesthetic is a FUTURISTIC HOLOGRAPHIC COMMAND CENTER, directly inspired by Tony
Stark's JARVIS interface from Iron Man: glowing translucent panels floating in dark space, thin
luminous cyan circuitry, volumetric depth, and precise technical readouts. It must feel like a
high-end sci-fi instrument — powerful, alive, and expensive — but still be a REAL, usable desktop
app, not a movie prop: every label readable, every control obvious.

PLATFORM: Desktop app window, 1600x1000, dark mode only. Not a website — no marketing hero, no
footer, no "sign up" CTA.

COLOR SYSTEM (use exactly):
- Canvas: near-black deep space #05070C, with a subtle radial glow from the top-center.
- Primary accent / holographic cyan: #38E0FF (glowing edges, active states, data lines).
- Secondary accent / plasma violet: #7C5CFF (gradients paired with cyan).
- Tertiary glow: #64F0D0 (soft mint for "safe/verified" states).
- Danger / critical: #FF4D5E (with an outer glow).
- Warning: #FFB020.
- Safe / success: #35E0A1.
- Text primary: #EAF4FF. Text secondary: #9FB2CC. Text tertiary/dim: #5F718C.
- Never use pure white #FFFFFF for body text, and never a light background.

MATERIALS & DEPTH (this is the core of the look):
- Panels are TRANSLUCENT HOLOGRAPHIC GLASS: ~8% white fill, heavy background blur, a 1px luminous
  cyan hairline border, and an inner top highlight so the edge catches light.
- Every panel floats: soft dark drop shadow beneath + a faint cyan outer glow (bloom) around edges.
- Layered Z-depth: background grid < ambient glow < panels < active/hovered panel < modals. Hovered
  panels lift toward the viewer and their cyan border brightens.
- Background: a faint blueprint/engineering grid (44px squares, ~2% opacity white lines), fading out
  toward the screen edges with a radial mask. Optional: extremely subtle scanline and drifting
  hex/circuit filigree in the far background at <4% opacity.
- Corner accents: on major panels, draw thin cyan "bracket" corner ticks (like a HUD targeting frame)
  instead of heavy borders.

TYPOGRAPHY:
- Headings: a geometric/technical sans (Space Grotesk, Chakra Petch, or Rajdhani), large, tight
  letter-spacing, near-white.
- Body/UI: Inter or SF Pro, 16px base, 1.6 line-height — generous and easy to read.
- ALL numbers, IDs, file paths, algorithm names, hashes and code: MONOSPACE (JetBrains Mono),
  cyan-tinted. Big metrics are large monospace with a soft cyan glow.
- Small caps + wide letter-spacing for tiny section labels ("QUANTUM-VULNERABLE").

COMPONENT LANGUAGE:
- Buttons: translucent glass pill/rounded-10px, 1px cyan border, cyan text; on hover the border
  glows brighter and a faint cyan fill appears. Primary action button has a cyan→violet gradient.
- Chips/badges: small monospace uppercase pills with a colored translucent fill + matching glowing
  1px border (green = safe, red = critical, amber = warning, cyan = informational).
- Tables: no heavy grid lines — use thin 1px row dividers at 6% white, an uppercase letter-spaced
  header row, generous 14px vertical row padding, and a cyan left-edge indicator + subtle cyan glow
  on the hovered row.
- Inputs: dark translucent field, 1px border that ignites cyan on focus with a soft outer ring.
- Charts: dark transparent plot area, cyan primary data line with a glowing gradient fill beneath it,
  violet secondary series, dashed cyan reference/marker lines, faint grid.
- Progress/risk bars: thin rounded track with a glowing gradient fill (green→amber→red by severity).
- Sidebar: a tall translucent holographic rail; the ACTIVE item has a cyan→violet gradient fill, a
  glowing left edge bar, and a white icon+label.
- Empty states: a softly glowing outlined icon, one clear sentence, and one action button — never a
  blank area.
- Loading: thin cyan indeterminate sweep bars and pulsing skeleton blocks (never plain spinners).

LAYOUT RULES (important — the current app wastes space):
- Fill the entire window width; do NOT center a narrow column with big empty margins.
- Use the full canvas: multi-column grids, side-by-side panels, and a right-hand detail/inspector
  panel where it helps. No large dead zones.
- Comfortable 32-40px outer gutters, 20-24px gaps between panels, 24px internal panel padding.
- Text must never look cramped or squeezed into a narrow strip.

MOTION (describe as annotations in the design):
- Panels/cards materialize with a fade + rise + slight 3D tilt (as if projecting into space).
- Grid children stagger in sequence, ~60ms apart.
- Hover = lift toward viewer + brighter cyan edge glow.
- Numbers count up on first render. Chart lines draw from left to right.
- Everything is fast and restrained (200-400ms); nothing bounces or wobbles.
```

---

## §2 — SCREEN-BY-SCREEN PROMPTS (11 screens)

### SCREEN 1 — App shell / navigation frame
```
Design the persistent application shell.
LEFT SIDEBAR (240px, full height, holographic glass rail):
- Top: a glowing hexagonal/shield app icon with a cyan→violet gradient, the wordmark "QUBIT" in
  large technical type with a cyan gradient, and a tiny wide-tracked subtitle "PQC MIGRATION".
- Nav list, each row = icon + label, 44px tall, rounded 10px:
  Projects, Inventory, Risk Posture, CRQC Timeline, Migrations, Scans & Jobs, Settings.
  Show "Inventory" as the ACTIVE item: cyan→violet gradient fill, glowing left edge, white text.
- Bottom: a small status card — a pulsing green dot, "Offline · local", and the line
  "No telemetry. Your code never leaves the machine."
TOP HEADER BAR (64px, glass, spans the remaining width):
- Left: current screen title + the subtitle "Quantum Upgrade Bridge & Inventory Tool".
- Right: a green glowing chip reading "CycloneDX 1.7", and a "New scan" glass button.
MAIN AREA: an empty content region showing the faint blueprint grid + ambient glow.
```

### SCREEN 2 — Boot / splash (engine starting)
```
Design a full-screen startup splash for the desktop app.
Centered: a large glowing hexagonal QUBIT emblem (cyan→violet) with concentric rotating HUD rings
and soft bloom. Below it the wordmark "QUBIT" in large wide-tracked technical type, then the
subtitle "Quantum Upgrade Bridge & Inventory Tool".
Beneath that a status line in monospace cyan with a thin animated sweep bar: "Initializing quantum
risk engine…". Under it a subtle ghost button "Retry connection".
Bottom: a tiny wide-tracked uppercase line "OFFLINE · LOCAL · NO TELEMETRY".
Background: deep space, faint grid, slow drifting circuit filigree. Feels like a system booting up.
```

### SCREEN 3 — Projects
```
Design the "Projects" screen: a grid of scanned codebases filling the full window width.
Header: large title "Projects", subtitle "Manage your scanned codebases and configurations", and a
primary gradient button "+ New Scan" on the right.
Below: a 3-column responsive grid of project cards (show 6). Each holographic card contains:
- a small glowing folder/cube icon + the project name in technical type + a monospace short ID below
- two inline stat blocks with large monospace numbers: "ASSETS 412" and "SCANS 3"
- a thin sparkline showing risk trend across scans (cyan glowing line)
- a footer row: last-scanned date (dim) and a cyan "View Details →" link
- HUD bracket corner ticks; on hover the card lifts and its border ignites
Also show one EMPTY-state card variant reading "never scanned" with a dimmed look.
```

### SCREEN 4 — Inventory (the flagship screen — most important)
```
Design the "Cryptographic Inventory" screen. Full window width, no wasted space.
Header: large title "Cryptographic Inventory", subtitle "Scan #3 · X:\projects\billing-service",
and a glass "Refresh" button with a circular-arrow icon.
KPI ROW — 4 wide holographic tiles across the full width, each with a glowing icon in a tinted
rounded square, a very large monospace glowing number, and a small wide-tracked uppercase label
(keep each label on ONE line):
  "412 TOTAL ASSETS" (cyan) · "138 QUANTUM-VULNERABLE" (red glow) · "74 SHOR-BREAKABLE" (amber) ·
  "274 QUANTUM-SAFE" (green)
FILTER BAR: a search input with a magnifier ("Filter by algorithm, file, rule…"), plus dropdown
chips: Algorithm, Asset type, Severity, and a "Vulnerable only" toggle switch.
MAIN TABLE (the centerpiece) — columns:
  ALGORITHM (monospace, cyan) | TYPE | CONTEXT | QUANTUM | HNDL RISK | LOCATION | RANK
Show 8 rows mixing crypto AND non-crypto security findings:
  RSA-2048 / algorithm-use / kex / red chip "VULN · SHOR" / risk bar 0.91 / keygen.py:44 / 1
  SHA-1 / algorithm-use / hash / amber chip "VULN · GROVER" / 0.15 / utils.py:12 / 7
  AES-128 / algorithm-use / at-rest / amber chip "GROVER" / 0.38 / store.py:88 / 5
  ML-KEM-768 / algorithm-use / kex / green chip "PQC SAFE" / 0.00 / kem.py:20 / —
  AWS Access Key ID / secret / credentials / red chip "EXPOSED" / 0.74 / config.py:7 / 2
  JSON Web Token / secret / token / red chip "EXPOSED" / 0.66 / auth.py:31 / 3
  PII: email address / sensitive-data / pii / amber chip "HNDL TARGET" / 0.42 / users.py:19 / 6
  Private key material / secret / credentials / red chip "CRITICAL" / 0.88 / server.pem:1 / 1
The RISK column is a thin glowing gradient bar plus a monospace score. Hovered row shows a cyan
left-edge indicator and faint glow. Row click opens the inspector (next screen).
```

### SCREEN 5 — Asset inspector drawer (slides in over Inventory)
```
Design a right-side inspector panel (460px) sliding over the Inventory screen, which is dimmed and
blurred behind it.
Top: the algorithm name in large monospace cyan ("RSA-2048"), a row of chips
("ALGORITHM-USE", "KEX", "VULN · SHOR"), and a close X.
Then a monospace file path with line number: "src/auth/keygen.py:44".
SECTION "EVIDENCE": a dark code block with syntax highlighting showing 3 lines of Python, the
offending line marked with a glowing cyan left bar.
SECTION "HNDL EXPOSURE" (a glowing bordered callout with a small radar icon): a short paragraph
explaining how an attacker harvests this today and decrypts it after a quantum computer exists.
SECTION "RISK BREAKDOWN": a large monospace score "0.91" with a confidence-interval bracket
"[0.86 – 0.94]", the line "Mosca margin: −3.2 years" in red, and a small horizontal bar chart of the
top contributing factors (feature attributions).
SECTION "PQC RECOMMENDATION" (highlighted panel): a big arrow row "RSA-2048 → ML-KEM-768 (hybrid)",
a library requirement row "cryptography ≥ 49", a chip "source: rule", "confidence 1.00", and a short
rationale paragraph.
Footer: two buttons — primary gradient "Generate patch" and ghost "Export finding".
```

### SCREEN 6 — Risk Posture
```
Design the "Risk Posture" analytics screen, using the full width in a 2-column layout.
Header: title "Risk Posture", subtitle "HNDL risk assessment · scan #3".
KPI ROW (4 tiles): "412 TOTAL ASSETS", "33% QUANTUM VULNERABLE", "0.41 MEDIAN RISK SCORE",
"18 NEGATIVE MOSCA MARGIN" (this last one red and glowing).
LEFT PANEL "RISK SCORE DISTRIBUTION": a histogram, 20 bins, bars with a cyan→violet vertical
gradient and glowing tops, dark transparent plot area, faint grid.
RIGHT PANEL "EXPOSURE SURFACE": a donut or treemap breaking findings into
Weak crypto / Hardcoded secrets / Sensitive data (PII) / Quantum-safe — each segment glowing in its
own accent color, with a legend showing counts.
FULL-WIDTH PANEL BELOW "HIGHEST-RISK ASSETS": a ranked list of 6 rows, each with a rank number in a
glowing circle, the monospace algorithm name, a glowing risk bar, the score, and a "›" expander.
```

### SCREEN 7 — CRQC Timeline (the science showcase)
```
Design the "CRQC Timeline" screen — the app's most visually impressive, scientific screen.
Header: title "CRQC Timeline", subtitle "Monte-Carlo simulation of Cryptographically Relevant
Quantum Computer arrival (surface-code resource model)". Top-right: an algorithm dropdown showing
"RSA-2048" and a toggle switch labelled "Blend expert survey".
KPI ROW (4 tiles, large monospace glowing numbers): "2041 MEDIAN (P50)", "2036 EARLIEST (P05)",
"2055 LATEST (P95)", "10,000 TRIALS".
MAIN CHART PANEL (large, fills the rest of the screen): a cumulative-probability S-curve
"P(CRQC ≤ year)" from 2026 to 2060 — a bright glowing cyan line with a luminous gradient fill
beneath it, a shaded violet 5–95% confidence band, and three vertical dashed cyan marker lines
labelled P05 / P50 / P95 at the top. Y axis in percent, X axis in years, faint grid, dark plot area.
Overlay a "MOSCA OVERLAY" legend box: a small horizontal bracket diagram showing
"migration time + data shelf life" versus the CRQC arrival, with the overlap region glowing red and
annotated "exposure window".
```

### SCREEN 8 — Scans & Jobs
```
Design the "Scans & Jobs" screen in a 1/3 + 2/3 two-column layout.
Header: title "Scans & Jobs", subtitle "Scan a local folder or a git repository URL". Top-right: a
wide input with a folder icon showing the placeholder "X:\projects\my-app  or  https://github.com/org/repo.git"
and a primary gradient button "+ New Scan".
LEFT COLUMN "LIVE JOBS": stacked job cards, each with the job name ("Scan #4"), a monospace target,
a thin glowing cyan indeterminate progress bar, a percentage, and the current stage
("scanning · code · 312/1310 files"). Show one active card and one queued (dimmed) card.
RIGHT COLUMN "SCAN HISTORY": a table with columns SCAN | TARGET | DATE | ASSETS | STATUS | ACTIONS.
Show 5 rows with status chips: green "SUCCEEDED" (x3), cyan pulsing "RUNNING", red "FAILED".
Actions column has a cyan "Open" link and a red trash icon.
Include one row whose target is a github.com URL to show git scanning.
```

### SCREEN 9 — Migrations (queue + dependency graph)
```
Design the "Migrations" screen with a segmented control at the top-right switching between
"Queue" and "Dependency Graph" — show the DEPENDENCY GRAPH view as active, and put a primary
gradient button "Build Plan" beside it.
Header: title "Migration Queue", subtitle "Risk-ranked, dependency-safe migration plan".
MAIN AREA — a holographic node graph filling the canvas: glowing circular nodes connected by thin
curved cyan edges with small arrowheads. Node color = risk (red/amber/green), node label =
monospace algorithm name. Group nodes into 3 labelled translucent "execution unit" containers
("UNIT 1", "UNIT 2", "UNIT 3") drawn as dashed cyan boundaries; one unit is marked with a chip
"CYCLE CONDENSATION". Edges are labelled with tiny text like "keygen-before-use", "shared-cert".
RIGHT SIDE PANEL (320px) "TASK DETAIL": the selected node's algorithm, rule id
(monospace "py-rsa-kex-01"), effort estimate, a governance strip showing
"1 of 2 approvals · blocked" with a shield icon, and buttons "Generate patch" / "Approve".
```

### SCREEN 10 — Migration detail / patch review (diff)
```
Design a patch-review screen.
Header: monospace file path "demo-lab/vulnapp-python/app.py", chips
"LLM · qwen2.5-coder:7b", "GENERATED IN 41.2s", and a status chip "PROPOSED".
VALIDATION STRIP: five pill steps connected by a thin line, each with an icon and state —
"APPLIES ✓", "PARSES ✓", "COMPILES ✓", "TESTS —", "RE-SCAN ✓"; passed ones glow green, skipped is dim.
MAIN AREA: a side-by-side diff viewer on dark glass — left pane "BEFORE" with removed lines tinted
red and a red left bar, right pane "AFTER" with added lines tinted green and a green left bar,
monospace code with syntax highlighting and line numbers.
BELOW: a panel "RATIONALE" containing an explanation paragraph of why RSA was replaced with
ML-KEM-768, in readable body text.
FOOTER action bar: primary gradient "Approve & Apply", ghost "Reject", ghost "Regenerate", and a
red-outlined "Discard". Include a small warning note with a shield icon:
"Patches are applied on a git branch; a failed validation can never be merged."
```

### SCREEN 11 — CBOM export + Settings (two screens, same prompt block)
```
SCREEN 11A — "CBOM": Design a Cryptographic Bill of Materials export screen.
Header: title "CBOM Export", subtitle "CycloneDX 1.7 · scan #3", chips "SPEC 1.7" and "SCHEMA-VALID"
(green, glowing). Buttons: primary gradient "Download JSON", ghost "Validate", ghost "Copy curl".
Left: a summary panel with component counts by asset type as small stat rows (algorithm, certificate,
key, secret, sensitive-data), plus a monospace serialNumber line.
Right (wider): a collapsible JSON tree viewer on dark glass — monospace, cyan keys, amber strings,
expand/collapse chevrons, with a couple of nodes expanded.

SCREEN 11B — "Settings": Design a settings screen with 3 stacked glass panels:
1) "CONNECTION": read-only monospace field "http://127.0.0.1:8787/api/v1", a password-style API token
   field with a "Save & Verify" button, and a green "Connected · scopes: rw" status line.
2) "ENVIRONMENT": two status rows with icons — "Docker  RUNNING" (green dot) and
   "Ollama  qwen2.5-coder:7b  RUNNING" (green dot), each with a "Recheck" ghost button. Show a
   variant where Ollama is amber "NOT DETECTED" with the hint "run: ollama serve".
3) "ABOUT": version rows in monospace (qubit-api, qubit-core, qubit-scanner) and a small note
   "Offline · local · MIT licensed".
```

---

## §3 — After Stitch returns HTML

Stitch gives you an HTML file + screenshot per screen. To bring it into QUBIT:
1. **Don't paste raw HTML into React.** Extract the *design decisions*: exact hex values, border/glow
   values, radii, font sizes, spacing, and the panel/table/chip treatments.
2. Put colors + effects into `dashboard/src/index.css` under `@theme` / `:root` and the existing
   `@layer components` classes — `glass-card`, `glass-input`, `chip`, `nav-pill-active`, `metric`.
   Because every page already uses those class names, **the whole app re-skins at once.**
3. Keep the working React logic and data wiring exactly as-is; only styling changes.
4. Motion notes go into the existing Framer Motion components (`AnimatedPage`, the inspector drawer)
   and the `.stagger` utility.

Send me the Stitch HTML/screenshots and I'll do this integration step.
