import { create } from 'zustand';

/**
 * Which project (and which scan inside it) the data tabs are showing.
 *
 * `projectId` used to default to the string `"default"` — a project id that has never existed in
 * any database this app talks to — and nothing read it. Every tab resolved its own scan from the
 * global scan list instead, so "the newest scan anywhere" decided what Inventory, Risk, CNSA 2.0
 * and the CBOM export all displayed, regardless of which project you had opened. That is why the
 * tabs showed one undifferentiated pile.
 *
 * Now it is the app's actual scope: undefined means "no project chosen yet", which is what makes a
 * tab open on its project grid rather than on somebody's data.
 *
 * Both values persist. Reopening the app inside the project you were working in is the behaviour
 * people expect from a desktop tool, and it also keeps a page refresh from silently changing which
 * project's numbers you are reading.
 */
const PROJECT_KEY = 'qubit_project_id';
const SCAN_KEY = 'qubit_scan_id';

function load(key: string): string | undefined {
  if (typeof window === 'undefined') return undefined;
  return localStorage.getItem(key) ?? undefined;
}

function save(key: string, value: string | undefined) {
  if (typeof window === 'undefined') return;
  if (value) localStorage.setItem(key, value);
  else localStorage.removeItem(key);
}

interface UiState {
  projectId: string | undefined;
  scanId: string | undefined;
  /** Enter a project. Clears the scan selection, because a scan id from the project you just left
   *  would otherwise stay active and every tab would show the wrong project's assets. */
  setProjectId: (id: string | undefined) => void;
  setScanId: (id: string | undefined) => void;
  /** Enter a project at a specific scan — used when opening a scan from Scans & Jobs. */
  openScan: (projectId: string, scanId: string) => void;
  /** Leave the current project and go back to the project grid. */
  clearProject: () => void;
}

export const useUiStore = create<UiState>((set, get) => ({
  projectId: load(PROJECT_KEY),
  scanId: load(SCAN_KEY),
  setProjectId: (id) => {
    if (get().projectId === id) return;
    save(PROJECT_KEY, id);
    save(SCAN_KEY, undefined);
    set({ projectId: id, scanId: undefined });
  },
  setScanId: (id) => {
    save(SCAN_KEY, id);
    set({ scanId: id });
  },
  openScan: (projectId, scanId) => {
    save(PROJECT_KEY, projectId);
    save(SCAN_KEY, scanId);
    set({ projectId, scanId });
  },
  clearProject: () => {
    save(PROJECT_KEY, undefined);
    save(SCAN_KEY, undefined);
    set({ projectId: undefined, scanId: undefined });
  },
}));
