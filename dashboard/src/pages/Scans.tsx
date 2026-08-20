import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { AnimatedPage } from '../components/AnimatedPage';
import {
  Activity,
  CheckCircle2,
  XCircle,
  History,
  Plus,
  Loader2,
  Trash2,
  GitBranch,
  FolderOpen,
  AlertTriangle,
  Ban,
  Radio,
  KeyRound,
} from 'lucide-react';
import {
  createNetworkScan,
  createScan,
  createVaultScan,
  deleteScan,
  fetchScans,
} from '../api/client';
import { useUiStore } from '../stores/ui';
import { isTauri } from '../lib/tauri';
import type { ScanSummary } from '../api/types';

function StatusBadge({ status }: { status: string }) {
  if (status === 'succeeded')
    return (
      <span className="flex items-center gap-1.5 text-[color:var(--color-safe)]">
        <CheckCircle2 className="h-4 w-4" /> Succeeded
      </span>
    );
  if (status === 'failed')
    return (
      <span className="flex items-center gap-1.5 text-[color:var(--color-danger)]">
        <XCircle className="h-4 w-4" /> Failed
      </span>
    );
  return (
    <span className="flex items-center gap-1.5 text-[color:var(--color-accent)]">
      <Loader2 className="h-4 w-4 animate-spin" /> {status}
    </span>
  );
}

function timeAgo(iso: string | null): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  const mins = Math.round((Date.now() - then) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

/** Everything a finished (or deleted) scan invalidates.
 *
 *  A scan no longer only adds rows to the scan list: it creates or reuses the project named after
 *  its target, and the API now builds that project's migration plan as the scan completes. Leaving
 *  `projects` and `projects-overview` cached meant the project grid on every other tab kept showing
 *  the pre-scan counts — and a brand-new project did not appear at all until a manual reload. */
function invalidateAfterScan(qc: QueryClient) {
  qc.invalidateQueries({ queryKey: ['scans'] });
  qc.invalidateQueries({ queryKey: ['projects'] });
  qc.invalidateQueries({ queryKey: ['projects-overview'] });
  qc.invalidateQueries({ queryKey: ['migrate-plans'] });
}

const isGitUrl = (t: string) =>
  /^(https?:\/\/|git@|ssh:\/\/|git:\/\/)/.test(t.trim()) || t.trim().endsWith('.git');

export function Scans() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const openScan = useUiStore((s) => s.openScan);
  // Default to the bundled sample apps; accepts either a local path or a git remote URL.
  const [target, setTarget] = useState('/samples');

  // Source selector. The architecture claims six discovery inputs; four of them (code, config,
  // certs, manifests) arrive through a filesystem path, but live TLS/SSH and Vault are separate
  // entry points with their own arguments, and neither had any way in from the app.
  const [source, setSource] = useState<'files' | 'network' | 'vault'>('files');
  const [netHost, setNetHost] = useState('127.0.0.1');
  const [netPort, setNetPort] = useState('8443');
  const [probePqc, setProbePqc] = useState(true);
  const [authorized, setAuthorized] = useState(false);
  const [vaultAddr, setVaultAddr] = useState('http://127.0.0.1:8200');
  const [vaultToken, setVaultToken] = useState('');

  const browseForFolder = async () => {
    if (!isTauri()) return; // no native picker outside the desktop shell
    const { open } = await import('@tauri-apps/plugin-dialog');
    const picked = await open({ directory: true, multiple: false, title: 'Select a folder to scan' });
    if (typeof picked === 'string') setTarget(picked);
  };

  const {
    data: scans,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    // Poll while any scan is still running so the table updates live.
    refetchInterval: (q) =>
      (q.state.data as ScanSummary[] | undefined)?.some(
        (s) => s.status === 'running' || s.status === 'queued',
      )
        ? 2000
        : false,
  });

  const netScan = useMutation({
    mutationFn: () =>
      createNetworkScan(
        netHost
          .split(',')
          .map((h) => h.trim())
          .filter(Boolean),
        {
          ports: netPort
            .split(',')
            .map((p) => Number(p.trim()))
            .filter((p) => Number.isFinite(p) && p > 0),
          probePqc,
          authorized,
        },
      ),
    onSuccess: () => invalidateAfterScan(qc),
  });

  const vaultScan = useMutation({
    mutationFn: () => createVaultScan(vaultAddr.trim(), vaultToken),
    onSuccess: () => {
      // Drop the token from component state the moment it is no longer needed. It is never written
      // to localStorage and never stored server-side, so this keeps it out of a React DevTools
      // inspection of a page someone leaves open during a demo.
      setVaultToken('');
      invalidateAfterScan(qc);
    },
  });

  const newScan = useMutation({
    mutationFn: (paths: string[]) => createScan(paths),
    onSuccess: () => invalidateAfterScan(qc),
  });

  const removeScan = useMutation({
    mutationFn: (id: string) => deleteScan(id),
    onSuccess: () => invalidateAfterScan(qc),
  });

  /** Track which scan ID is in the "pending confirm" state (first-click shows confirm chip). */
  const [confirmId, setConfirmId] = useState<string | null>(null);

  const handleDeleteClick = (scan: ScanSummary) => {
    if (confirmId === scan.id) {
      // Second click — confirmed, proceed with deletion
      setConfirmId(null);
      removeScan.mutate(scan.id);
    } else {
      // First click — enter confirm state
      setConfirmId(scan.id);
    }
  };

  const cancelConfirm = () => setConfirmId(null);

  // Enter the scan's project AND select that scan, in one store write. Setting them separately
  // meant `setProjectId` cleared the scan selection it had just been given, so "Open" landed on
  // the project's default scan rather than the row that was clicked.
  const handleOpenScan = (scan: ScanSummary) => {
    openScan(scan.project_id, scan.id);
    navigate('/inventory');
  };

  const running = (scans ?? []).filter((s) => s.status === 'running' || s.status === 'queued');

  return (
    <AnimatedPage className="flex flex-col gap-6 py-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1>Scans &amp; Jobs</h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            Point QUBIT at a codebase, a live TLS endpoint, or a Vault server. Assets, HNDL exposures
            and risk are computed and stored in the registry.
          </p>
        </div>
      </header>

      {/* Source selector. Four of QUBIT's six discovery inputs (code, config, certs, dependency
          manifests) come in through a filesystem path, so they share one tab; live TLS/SSH and Vault
          take different arguments and get their own. */}
      <div className="glass-card flex flex-col gap-4 p-5">
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Scan source">
          {(
            [
              ['files', 'Code / configs / certs', FolderOpen],
              ['network', 'Live TLS / SSH', Radio],
              ['vault', 'Vault / KMS', KeyRound],
            ] as const
          ).map(([key, label, Icon]) => (
            <button
              key={key}
              role="tab"
              aria-selected={source === key}
              data-testid={`source-tab-${key}`}
              onClick={() => setSource(key)}
              className={
                source === key ? 'hud-btn' : 'hud-btn hud-btn-ghost opacity-70 hover:opacity-100'
              }
              type="button"
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>

        {source === 'files' && (
          <div className="flex flex-wrap items-center gap-4">
            <span className="metric-label flex items-center gap-2 text-[color:var(--color-accent)]/70">
              {isGitUrl(target) ? (
                <GitBranch className="h-3.5 w-3.5" />
              ) : (
                <FolderOpen className="h-3.5 w-3.5" />
              )}
              {isGitUrl(target) ? 'Git remote' : 'Local path'}
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="C:\path\to\repo  or  https://github.com/org/repo.git"
              className="glass-input min-w-0 flex-1 text-sm"
              spellCheck={false}
            />
            {isTauri() && (
              <button onClick={browseForFolder} className="hud-btn hud-btn-ghost" type="button">
                <FolderOpen className="h-3.5 w-3.5" />
                Browse
              </button>
            )}
            <button
              onClick={() => newScan.mutate([target])}
              disabled={newScan.isPending || !target.trim()}
              className="hud-btn"
              data-testid="run-file-scan"
            >
              {newScan.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Plus className="h-3.5 w-3.5" />
              )}
              New scan
            </button>
          </div>
        )}

        {source === 'network' && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-4">
              <span className="metric-label flex items-center gap-2 text-[color:var(--color-accent)]/70">
                <Radio className="h-3.5 w-3.5" />
                Hosts
              </span>
              <input
                value={netHost}
                onChange={(e) => setNetHost(e.target.value)}
                placeholder="127.0.0.1, 10.0.0.5"
                className="glass-input min-w-0 flex-1 text-sm"
                spellCheck={false}
                aria-label="Hosts to probe"
              />
              <span className="metric-label text-[color:var(--color-accent)]/70">Ports</span>
              <input
                value={netPort}
                onChange={(e) => setNetPort(e.target.value)}
                placeholder="443"
                className="glass-input w-28 text-sm"
                spellCheck={false}
                aria-label="Ports to probe"
              />
              <button
                onClick={() => netScan.mutate()}
                disabled={netScan.isPending || !netHost.trim()}
                className="hud-btn"
                data-testid="run-network-scan"
              >
                {netScan.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Radio className="h-3.5 w-3.5" />
                )}
                Probe endpoints
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-5 text-xs text-[color:var(--color-ink-dim)]">
              <label className="flex cursor-pointer items-center gap-2">
                <input
                  type="checkbox"
                  checked={probePqc}
                  onChange={(e) => setProbePqc(e.target.checked)}
                />
                Probe hybrid PQC groups (X25519MLKEM768 + the two ML-KEM P-curve hybrids)
              </label>
              <label className="flex cursor-pointer items-center gap-2">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                />
                I am authorized to scan public hosts
              </label>
            </div>
            <p className="text-xs leading-relaxed text-[color:var(--color-ink-faint)]">
              Loopback and private (RFC1918) addresses are always allowed. A public host additionally
              requires the checkbox above <em>and</em> an entry in the server&apos;s scan allowlist —
              every attempt is written to the scan audit log whether it is permitted or refused.
            </p>
          </div>
        )}

        {source === 'vault' && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-4">
              <span className="metric-label flex items-center gap-2 text-[color:var(--color-accent)]/70">
                <KeyRound className="h-3.5 w-3.5" />
                Vault
              </span>
              <input
                value={vaultAddr}
                onChange={(e) => setVaultAddr(e.target.value)}
                placeholder="http://127.0.0.1:8200"
                className="glass-input min-w-0 flex-1 text-sm"
                spellCheck={false}
                aria-label="Vault address"
              />
              <input
                value={vaultToken}
                onChange={(e) => setVaultToken(e.target.value)}
                placeholder="token"
                type="password"
                className="glass-input w-56 text-sm"
                spellCheck={false}
                autoComplete="off"
                aria-label="Vault token"
              />
              <button
                onClick={() => vaultScan.mutate()}
                disabled={vaultScan.isPending || !vaultAddr.trim() || !vaultToken}
                className="hud-btn"
                data-testid="run-vault-scan"
              >
                {vaultScan.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <KeyRound className="h-3.5 w-3.5" />
                )}
                Scan Vault
              </button>
            </div>
            <p className="text-xs leading-relaxed text-[color:var(--color-ink-faint)]">
              Reads the <code>transit</code> key list and <code>pki</code> certificates. The token is
              used for this scan only — it is never written to the database, the job record, or this
              browser&apos;s storage, and is cleared from the field once the scan starts.
            </p>
          </div>
        )}
      </div>

      {[newScan, netScan, vaultScan].some((m) => m.isError) && (
        <div
          className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-3 text-sm text-[color:var(--color-danger)]"
          data-testid="scan-error"
        >
          Scan failed:{' '}
          {[newScan, netScan, vaultScan]
            .map((m) => (m.error instanceof Error ? m.error.message : null))
            .find(Boolean) ?? 'unknown error'}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[minmax(0,1fr)_minmax(0,2.2fr)]">
        <section className="flex flex-col gap-3">
          <h2 className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-[color:var(--color-accent)]" />
            Live jobs
          </h2>
          {running.length === 0 && (
            <div className="glass-card p-10 text-center font-mono text-sm text-[color:var(--color-ink-faint)]">
              No jobs running at this time.
            </div>
          )}
          {running.map((job) => (
            <div
              key={job.id}
              className="glass-card scan-panel p-5"
              style={{ ['--scan-h' as string]: '100%' }}
            >
              <div className="mb-2 flex items-center justify-between">
                <span className="font-mono text-sm text-[color:var(--color-accent-soft)]">
                  Scan #{job.seq}
                </span>
                <Loader2 className="h-4 w-4 animate-spin text-[color:var(--color-accent)]" />
              </div>
              <div className="truncate font-mono text-xs text-[color:var(--color-ink-faint)]">
                {job.targets.join(', ')}
              </div>
            </div>
          ))}
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="flex items-center gap-2">
            <History className="h-5 w-5 text-[color:var(--color-accent)]" />
            Scan history
          </h2>

          {isError && (
            <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)]">
              Could not load scans: {error instanceof Error ? error.message : 'unknown error'}.
              <span className="text-[color:var(--color-ink-faint)]"> Is the API reachable?</span>
            </div>
          )}

          <div className="glass-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="hud-table min-w-full">
                <thead>
                  <tr>
                    <th className="px-5 py-3">Scan</th>
                    <th className="px-5 py-3">Target</th>
                    <th className="px-5 py-3">Date</th>
                    <th className="px-5 py-3">Assets</th>
                    <th className="px-5 py-3">Status</th>
                    <th className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(scans ?? []).map((scan) => (
                    <tr key={scan.id} className="data-row">
                      <td className="px-5 py-3.5">
                        <span className="text-[color:var(--color-accent-soft)]">#{scan.seq}</span>{' '}
                        <span className="text-[color:var(--color-ink-faint)]">
                          {scan.id.slice(0, 8)}
                        </span>
                      </td>
                      <td className="max-w-[22rem] truncate px-5 py-3.5 text-xs text-[color:var(--color-ink-dim)]">
                        {scan.targets.join(', ')}
                      </td>
                      <td className="px-5 py-3.5 text-xs text-[color:var(--color-ink-faint)]">
                        {timeAgo(scan.created_at)}
                      </td>
                      <td className="px-5 py-3.5 text-[color:var(--color-accent)]">
                        {scan.stats?.assets ?? '—'}
                      </td>
                      <td className="px-5 py-3.5 text-xs">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="whitespace-nowrap px-5 py-3.5 text-right">
                        <button
                          onClick={() => handleOpenScan(scan)}
                          disabled={scan.status !== 'succeeded'}
                          className="label-caps mr-4 text-[color:var(--color-accent)] transition-colors hover:text-[color:var(--color-accent-soft)] disabled:opacity-40"
                        >
                          Open
                        </button>
                        {scan.status === 'succeeded' && (
                          <Link
                            to={`/report/${scan.id}`}
                            className="label-caps mr-4 text-[color:var(--color-accent-2)] transition-colors hover:text-[color:var(--color-accent)]"
                          >
                            Report
                          </Link>
                        )}

                        {/* Two-step delete: first click shows confirm, second click deletes */}
                        {confirmId === scan.id ? (
                          <span className="inline-flex items-center gap-2">
                            <button
                              onClick={() => handleDeleteClick(scan)}
                              disabled={removeScan.isPending}
                              className="label-caps flex items-center gap-1 text-[color:var(--color-danger)] transition-colors hover:text-[color:var(--color-danger)]/80"
                              title="Confirm deletion"
                            >
                              <AlertTriangle className="inline h-3.5 w-3.5" />
                              Confirm
                            </button>
                            <button
                              onClick={cancelConfirm}
                              className="text-[color:var(--color-ink-faint)] transition-colors hover:text-[color:var(--color-ink)]"
                              title="Cancel"
                              aria-label="Cancel delete"
                            >
                              <Ban className="inline h-4 w-4" />
                            </button>
                          </span>
                        ) : (
                          <button
                            onClick={() => handleDeleteClick(scan)}
                            disabled={
                              removeScan.isPending ||
                              scan.status === 'running' ||
                              scan.status === 'queued'
                            }
                            className="text-[color:var(--color-danger)]/70 transition-colors hover:text-[color:var(--color-danger)] disabled:opacity-30 disabled:cursor-not-allowed"
                            title={
                              scan.status === 'running' || scan.status === 'queued'
                                ? 'Cannot delete a running scan'
                                : 'Delete scan'
                            }
                            aria-label={`Delete scan #${scan.seq}`}
                          >
                            <Trash2 className="inline h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {isLoading && (
                    <tr>
                      <td colSpan={6} className="px-5 py-12 text-center">
                        <Loader2 className="inline h-4 w-4 animate-spin" /> Loading scans…
                      </td>
                    </tr>
                  )}
                  {!isLoading && (scans ?? []).length === 0 && (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-5 py-12 text-center text-[color:var(--color-ink-faint)]"
                      >
                        No scans yet. Point QUBIT at a path or repo above.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </div>
    </AnimatedPage>
  );
}
