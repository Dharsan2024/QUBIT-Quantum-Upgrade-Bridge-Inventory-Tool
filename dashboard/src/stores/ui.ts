import { create } from 'zustand';

interface UiState {
  projectId: string;
  scanId: string | undefined;
  setProjectId: (id: string) => void;
  setScanId: (id: string | undefined) => void;
}

export const useUiStore = create<UiState>((set) => ({
  projectId: "default", // default project from doc 05
  scanId: undefined,
  setProjectId: (id) => set({ projectId: id }),
  setScanId: (id) => set({ scanId: id }),
}));
