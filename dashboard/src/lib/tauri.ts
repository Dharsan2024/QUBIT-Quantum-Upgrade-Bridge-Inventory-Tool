/**
 * Detects whether the app is running inside the Tauri desktop shell vs. a plain browser (the
 * dev server, or a stray tab someone opens the dashboard URL in directly). Native-only features —
 * the file-system save dialog, the folder picker — must degrade gracefully instead of throwing in
 * the browser case, since `@tauri-apps/plugin-*` calls only work behind the injected bridge.
 */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/**
 * Save text to disk. Inside the desktop app this is a real native save dialog (the WebView2
 * blob + `<a download>` trick this replaced was unverified and, per manual testing, does not
 * reliably prompt a save location in WebView2 — see PROJECT_PHASE_MEMORY 2026-08-15). Outside
 * Tauri (the plain browser dev server) it falls back to the blob approach so `npm run dev` still
 * works standalone.
 *
 * Returns true if the file was written, false if the user cancelled the dialog.
 */
export async function saveTextFile(
  suggestedName: string,
  content: string,
  mime = "application/octet-stream",
): Promise<boolean> {
  if (isTauri()) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const { writeTextFile } = await import("@tauri-apps/plugin-fs");
    const ext = suggestedName.includes(".") ? suggestedName.split(".").pop() : undefined;
    const path = await save({
      defaultPath: suggestedName,
      filters: ext ? [{ name: ext.toUpperCase(), extensions: [ext] }] : undefined,
    });
    if (!path) return false; // user cancelled
    await writeTextFile(path, content);
    return true;
  }

  // Browser fallback (dev server outside the desktop shell).
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = suggestedName;
  a.click();
  URL.revokeObjectURL(url);
  return true;
}
