import { Component } from 'react';
import type { ReactNode, ErrorInfo } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Page-level error boundary. Wraps the <Outlet> in Layout so a runtime error in one
 * page (e.g. unexpected null from a malformed API response) doesn't crash the whole app.
 * The sidebar and HUD stay usable so the user can navigate away.
 */
export class PageErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // In production you'd send to a local log file; we intentionally avoid remote telemetry.
    console.error('[QUBIT] Page error boundary caught:', error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="flex flex-col items-center justify-center gap-6 py-20 px-8 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-[3px] border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10">
          <AlertOctagon className="h-8 w-8 text-[color:var(--color-danger)]" />
        </div>
        <div>
          <h2 className="text-[color:var(--color-danger)]">Something went wrong</h2>
          <p className="mt-2 max-w-md text-sm text-[color:var(--color-ink-dim)]">
            This page hit an unexpected error. The sidebar is still usable — navigate to
            another section or reload.
          </p>
        </div>
        <div className="glass-card max-w-2xl w-full overflow-x-auto p-4">
          <pre className="font-mono text-xs text-[color:var(--color-danger)]/80 text-left whitespace-pre-wrap">
            {this.state.error.message}
          </pre>
        </div>
        <button onClick={this.reset} className="hud-btn">
          <RefreshCw className="h-3.5 w-3.5" />
          Try again
        </button>
      </div>
    );
  }
}
