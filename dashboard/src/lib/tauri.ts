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

/**
 * Save BINARY content to disk — the PDF report path.
 *
 * `saveTextFile` cannot carry a PDF: it writes through Tauri's `writeTextFile`, which encodes as
 * UTF-8, and passing raw PDF bytes through a JS string corrupts every byte above 0x7F. The document
 * still opens in some readers and fails in others, which is the worst kind of bug to ship on a
 * compliance artifact. So this takes bytes end to end.
 *
 * Returns true if the file was written, false if the user cancelled the dialog.
 */
export async function saveBinaryFile(
  suggestedName: string,
  bytes: Uint8Array,
  mime = "application/octet-stream",
): Promise<boolean> {
  if (isTauri()) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const { writeFile } = await import("@tauri-apps/plugin-fs");
    const ext = suggestedName.includes(".") ? suggestedName.split(".").pop() : undefined;
    const path = await save({
      defaultPath: suggestedName,
      filters: ext ? [{ name: ext.toUpperCase(), extensions: [ext] }] : undefined,
    });
    if (!path) return false; // user cancelled
    await writeFile(path, bytes);
    return true;
  }

  // Browser fallback — same two load-bearing details as saveTextFile: the anchor must be in the
  // document, and the object URL must not be revoked synchronously after click().
  const blob = new Blob([bytes as unknown as BlobPart], { type: mime });
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

/**
 * Ask the desktop shell which port it actually started the API on, and store it as the API base.
 *
 * Necessary because the Tauri window loads the BUNDLED dashboard from `tauri.localhost`, not from
 * the API — so it cannot pick up the base URL the API injects into pages it serves itself, and a
 * relative `/api/v1` would resolve against `tauri.localhost` and never reach the engine.
 *
 * The port is not a constant. It used to be 8787 in three places (this bundle's default, the Rust
 * launcher, and `qubit-desktop.bat`), and 8787 is not always bindable: Windows reserves port blocks
 * for Hyper-V/WSL/Docker, and where 8695-8794 is reserved, binding it fails with WinError 10013
 * while nothing is listening. The API never came up and the window sat on "Starting the engine…"
 * until it gave up — with the misleading implication that the engine was broken rather than that
 * nobody could agree on a port.
 *
 * Safe outside Tauri and safe on failure: returns false and leaves whatever base is configured, so
 * the browser and `qubit serve` paths are untouched.
 */
export async function adoptDesktopApiBase(): Promise<boolean> {
  if (!isTauri()) return false;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const base = await invoke<string>("api_base");
    if (typeof base === "string" && base.startsWith("http")) {
      const { setApiBase } = await import("../api/client");
      setApiBase(base);
      return true;
    }
  } catch {
    // An older shell without the command, or the bridge not ready — fall through to the configured
    // default rather than blocking boot on it.
  }
  return false;
}
