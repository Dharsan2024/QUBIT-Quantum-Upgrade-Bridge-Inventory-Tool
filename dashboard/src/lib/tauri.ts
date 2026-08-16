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

  // Browser fallback (dev server, or the dashboard served by nginx outside the desktop shell).
  //
  // Two details here are load-bearing, and both were wrong: the anchor has to be IN the document
  // for `click()` to start a download in Firefox, and the object URL must NOT be revoked
  // synchronously after `click()`. Revoking immediately can invalidate the blob before the browser
  // has finished reading it, which silently produces no file at all — the failure mode is an export
  // button that looks like it worked and saved nothing. Revoking on a later task lets the download
  // latch onto the blob first.
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = suggestedName;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    a.remove();
    URL.revokeObjectURL(url);
  }, 0);
  return true;
}
