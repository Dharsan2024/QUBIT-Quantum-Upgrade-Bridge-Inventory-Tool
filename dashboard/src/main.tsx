import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// Fonts are bundled, not fetched: this ships as an offline Windows desktop app, so a
// Google-Fonts <link> would silently fall back to system faces and lose the HUD look.  Import the
// Latin subsets used by the interface rather than every Unicode subset each family publishes;
// project/file content outside Latin still renders through the platform fallback font.
import '@fontsource/space-grotesk/latin-400.css'
import '@fontsource/space-grotesk/latin-500.css'
import '@fontsource/space-grotesk/latin-600.css'
import '@fontsource/space-grotesk/latin-700.css'
import '@fontsource/inter/latin-400.css'
import '@fontsource/inter/latin-500.css'
import '@fontsource/inter/latin-600.css'
import '@fontsource/inter/latin-700.css'
import '@fontsource/jetbrains-mono/latin-400.css'
import '@fontsource/jetbrains-mono/latin-500.css'
import '@fontsource/jetbrains-mono/latin-700.css'
import './index.css'
import App from './App.tsx'

// This ships as a native Windows app, but the shell is WebView2 — which serves its own browser
// context menu on right-click ("Back", "Refresh", "Save as", "Print", "Send tab to your devices").
// None of those make sense here and they break the native feel, so suppress it in production
// builds. Dev keeps it, since Inspect is useful while working on the UI.
if (import.meta.env.PROD) {
  window.addEventListener('contextmenu', (e) => e.preventDefault())
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
