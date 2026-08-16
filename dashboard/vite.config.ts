import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // `host: true` binds every interface, which matters because Vite's default binds only the
  // `localhost` HOSTNAME. On a machine where `localhost` resolves to `::1`, a client that connects to
  // the `127.0.0.1` LITERAL gets nothing — the server is up and answering on the name while appearing
  // completely dead on the IPv4 address. That cost a Playwright run a full 120s webServer timeout
  // waiting for a server that had already started, and it would bite the same way for anything else
  // pointed at 127.0.0.1 (a container health check, curl in a script, a Tauri dev shell).
  //
  // Binding both means callers can use either literal or the hostname and get the same answer.
  server: { host: true },
  preview: { host: true },
})
