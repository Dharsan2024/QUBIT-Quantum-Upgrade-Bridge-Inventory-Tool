import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import {
  FileText,
  Download,
  Printer,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Boxes,
  RefreshCw,
  FileDown,
  Bug,
} from 'lucide-react';
import { AnimatedPage } from '../components/AnimatedPage';
import {
  fetchScan,
  fetchScanAssets,
  fetchRiskSummary,
  fetchTimeline,
  fetchPlans,
  fetchPlanQueue,
  fetchReportPdf,
  fetchSarif,
} from '../api/client';
import { saveBinaryFile, saveTextFile } from '../lib/tauri';
import { displayAlgorithm } from '../lib/assetLabels';
import type { CryptoAsset } from '../api/types';

function isHndl(a: CryptoAsset): boolean {
  return a.asset_type === 'secret' || a.asset_type === 'sensitive-data';
}

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/** Standalone HTML export: same content, no app chrome, a print stylesheet baked in so the
 *  file is readable both on screen and printed/exported to PDF from any browser. */
function buildStandaloneHtml(title: string, bodyHtml: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Inter, sans-serif; margin: 0; padding: 2.5rem;
    max-width: 900px; margin-inline: auto; color: #12161f; background: #fff; line-height: 1.5; }
  h1 { font-size: 1.8rem; margin-bottom: 0.2rem; }
  h2 { font-size: 1.15rem; margin-top: 2.2rem; border-bottom: 2px solid #12161f; padding-bottom: 0.35rem; }
  .meta { color: #5a6472; font-size: 0.9rem; margin-bottom: 1.5rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.88rem; }
  th, td { text-align: left; padding: 0.5rem 0.7rem; border-bottom: 1px solid #dde1e7; }
  th { background: #f3f5f8; font-weight: 600; }
  .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.9rem; margin-top: 1rem; }
  .kpi { border: 1px solid #dde1e7; border-radius: 8px; padding: 0.9rem 1rem; }
  .kpi .label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: #5a6472; }
  .kpi .value { font-size: 1.6rem; font-weight: 700; margin-top: 0.2rem; }
  .danger { color: #b3261e; } .warn { color: #935e00; } .safe { color: #0f7b4f; } .info { color: #0a5fb0; }
  .mono { font-family: "SF Mono", "JetBrains Mono", Consolas, monospace; font-size: 0.85em; }
  .note { color: #5a6472; font-size: 0.8rem; margin-top: 2.5rem; border-top: 1px solid #dde1e7; padding-top: 0.8rem; }
</style>
</head><body>${bodyHtml}</body></html>`;
}

export function Report() {
  const { scanId } = useParams<{ scanId: string }>();

  const scanQ = useQuery({
    queryKey: ['report-scan', scanId],
    queryFn: () => fetchScan(scanId as string),
    enabled: !!scanId,
  });
  const assetsQ = useQuery({
    queryKey: ['report-assets', scanId],
    queryFn: () => fetchScanAssets(scanId as string, 0, 200),
    enabled: !!scanId,
  });
  const riskQ = useQuery({
    queryKey: ['report-risk', scanId],
    queryFn: () => fetchRiskSummary(scanId as string),
    enabled: !!scanId,
  });
  // The plan for THIS scan's project. This used to fetch every plan in the installation and take
  // the newest active one, so a report for scan #4 of one project could embed the migration queue
  // of a completely different project — with a task count and file list that had nothing to do
  // with the assets listed above it in the same document.
  const reportProjectId = scanQ.data?.project_id;
  const plansQ = useQuery({
    queryKey: ['report-plans', reportProjectId],
    queryFn: () => fetchPlans(reportProjectId as string),
    enabled: !!reportProjectId,
  });
  // Prefer a plan built from this exact scan; fall back to the project's newest.
  const activePlan =
    plansQ.data?.find((p) => p.scan_id === scanId && p.status === 'active') ??
    plansQ.data?.find((p) => p.status === 'active' || p.status === 'completed');
  const queueQ = useQuery({
    queryKey: ['report-queue', activePlan?.id],
    queryFn: () => fetchPlanQueue(activePlan!.id),
    enabled: !!activePlan,
  });

  // Memoised so downstream useMemo (dominantVulnAlgo) sees a stable reference — assetsQ.data?.items
  // ?? [] would allocate a new array every render otherwise.
  const items: CryptoAsset[] = useMemo(() => assetsQ.data?.items ?? [], [assetsQ.data]);
  // The report fetches a single page of up to 200 assets (the server's hard cap). For the
  // overwhelming majority of scans that's everything; for a scan bigger than that, the KPIs and
  // asset table below would silently describe only the first 200 unless flagged as partial.
  const totalAssets = assetsQ.data?.total ?? items.length;
  const truncated = items.length < totalAssets;
  // Only Shor-broken public-key algorithms have a modeled CRQC arrival curve — Grover-weakened
  // symmetric/hash algorithms (e.g. SHA-1, AES-128) degrade continuously rather than breaking at
  // a threshold, so /risk/timeline has nothing to return for them (404s). Restricting the pick to
  // "shor" avoids that 404 and shows a timeline that's actually meaningful for this scan.
  const dominantVulnAlgo = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of items) {
      if (a.quantum_vulnerable.vulnerable && a.quantum_vulnerable.attack === 'shor') {
        counts.set(a.algorithm, (counts.get(a.algorithm) ?? 0) + 1);
      }
    }
    let best: string | null = null;
    let bestN = 0;
    for (const [algo, n] of counts) {
      if (n > bestN) {
        best = algo;
        bestN = n;
      }
    }
    return best;
  }, [items]);

  const timelineQ = useQuery({
    queryKey: ['report-timeline', dominantVulnAlgo],
    queryFn: () => fetchTimeline(dominantVulnAlgo as string),
    enabled: !!dominantVulnAlgo,
    staleTime: 5 * 60 * 1000,
  });

  const isLoading = scanQ.isLoading || assetsQ.isLoading || riskQ.isLoading;
  const scan = scanQ.data;
  const risk = riskQ.data;

  const vulnerable = items.filter((a) => a.quantum_vulnerable.vulnerable);
  const hndl = items.filter(isHndl);
  const safe = items.length - vulnerable.length - hndl.length;
  const med = risk ? median(risk.risk_scores) : 0;

  const queueByState = useMemo(() => {
    const m = new Map<string, number>();
    for (const t of queueQ.data ?? []) m.set(t.state, (m.get(t.state) ?? 0) + 1);
    return m;
  }, [queueQ.data]);

  const generatedAt = new Date().toLocaleString();

  function reportBodyHtml(): string {
    const escape = (s: string) =>
      s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const rows = [...items]
      .sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0))
      .slice(0, 25)
      .map((a) => {
        const loc = a.location.file_path
          ? `${a.location.file_path}${a.location.line ? `:${a.location.line}` : ''}`
          : (a.location.host ?? '—');
        const status = isHndl(a)
          ? 'HNDL exposure'
          : a.quantum_vulnerable.vulnerable
            ? `Vulnerable · ${a.quantum_vulnerable.attack}`
            : 'Quantum-safe';
        return `<tr><td class="mono">${escape(displayAlgorithm(a.algorithm))}</td><td>${escape(a.usage_context)}</td><td>${escape(status)}</td><td class="mono">${a.risk ? a.risk.score.toFixed(2) : '—'}</td><td class="mono">${escape(loc)}</td></tr>`;
      })
      .join('');

    const migrationRows =
      queueByState.size > 0
        ? [...queueByState.entries()]
            .map(([state, n]) => `<tr><td>${escape(state)}</td><td class="mono">${n}</td></tr>`)
            .join('')
        : '<tr><td colspan="2">No migration plan has been built for this registry yet.</td></tr>';

    return `
      <h1>QUBIT Risk &amp; Migration Report</h1>
      <div class="meta">
        ${scan ? `Scan #${scan.seq} · ${escape(scan.targets.join(', '))} · ${escape(scan.status)}` : ''}
        <br>Generated ${escape(generatedAt)} · offline, no telemetry
      </div>

      <h2>Executive summary</h2>
      <div class="kpis">
        <div class="kpi"><div class="label">Total assets</div><div class="value info">${totalAssets}</div></div>
        <div class="kpi"><div class="label">Quantum-vulnerable${truncated ? '*' : ''}</div><div class="value danger">${vulnerable.length}</div></div>
        <div class="kpi"><div class="label">HNDL exposures${truncated ? '*' : ''}</div><div class="value warn">${hndl.length}</div></div>
        <div class="kpi"><div class="label">Quantum-safe${truncated ? '*' : ''}</div><div class="value safe">${safe}</div></div>
      </div>
      <p>Median HNDL risk score: <b>${med.toFixed(2)}</b> across ${risk?.risk_scores.length ?? 0} scored assets.</p>
      ${truncated ? `<p style="color:#935e00"><b>*</b> This scan has ${totalAssets} assets; the breakdown above reflects only the first ${items.length} (the report's per-scan limit).</p>` : ''}

      ${
        timelineQ.data
          ? `<h2>CRQC timeline — ${escape(timelineQ.data.algorithm)}</h2>
             <p>Based on ${timelineQ.data.n_trials.toLocaleString()} Monte-Carlo trials of the surface-code
             resource model, the dominant vulnerable algorithm in this scan
             (<span class="mono">${escape(timelineQ.data.algorithm)}</span>) is projected to become
             breakable between <b>${timelineQ.data.p05_year}</b> (P05) and
             <b>${timelineQ.data.p95_year}</b> (P95), with a median estimate of
             <b>${timelineQ.data.median_year}</b>. Under harvest-now-decrypt-later, any traffic or data
             protected by this algorithm today is already exposed to an adversary who is recording it now.</p>`
          : ''
      }

      <h2>Highest-risk assets (top ${Math.min(25, items.length)} of ${totalAssets})</h2>
      <table><thead><tr><th>Algorithm / finding</th><th>Context</th><th>Status</th><th>Risk score</th><th>Location</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5">No assets in this scan.</td></tr>'}</tbody></table>

      <h2>Migration status</h2>
      <table><thead><tr><th>State</th><th>Tasks</th></tr></thead><tbody>${migrationRows}</tbody></table>

      <p class="note">Generated locally by QUBIT — Quantum Upgrade Bridge &amp; Inventory Tool.
      No data leaves this machine.</p>
    `;
  }

  const exportHtml = async () => {
    const title = `QUBIT Report — Scan #${scan?.seq ?? scanId}`;
    const html = buildStandaloneHtml(title, reportBodyHtml());
    await saveTextFile(`qubit-report-scan-${scan?.seq ?? scanId}.html`, html, 'text/html');
  };

  const printReport = () => window.print();

  // The real reports, generated server-side. `window.print()` above is a browser rendering of THIS
  // page; these two are the artifacts qubit_core.report composes — the paginated PDF a compliance
  // submission attaches, and the SARIF an analyst uploads to code scanning. Until now both existed
  // only behind `qubit report` on the CLI and were unreachable from the app.
  const [busy, setBusy] = useState<null | 'pdf' | 'sarif'>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const downloadPdf = async () => {
    if (!scanId) return;
    setDownloadError(null);
    setBusy('pdf');
    try {
      const bytes = await fetchReportPdf(scanId);
      await saveBinaryFile(
        `qubit-report-scan-${scan?.seq ?? scanId}.pdf`,
        bytes,
        'application/pdf',
      );
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : 'Could not generate the PDF report');
    } finally {
      setBusy(null);
    }
  };

  const downloadSarif = async () => {
    if (!scanId) return;
    setDownloadError(null);
    setBusy('sarif');
    try {
      const doc = await fetchSarif(scanId);
      await saveTextFile(
        `qubit-scan-${scan?.seq ?? scanId}.sarif`,
        JSON.stringify(doc, null, 2),
        'application/json',
      );
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : 'Could not generate the SARIF log');
    } finally {
      setBusy(null);
    }
  };

  // The on-screen HUD view below is print:hidden — dark glass panels with glow effects don't
  // print legibly. This is the actual printable content: the same light, plain document used
  // for the HTML export, shown only when printing (hidden on screen, print:block on paper).
  const printableHtml = scan
    ? `<style>
        .qubit-print { color-scheme: light; font-family: -apple-system, "Segoe UI", Inter, sans-serif; color: #12161f; }
        /* Explicit color + text-shadow:none on every heading: index.css's global h1/h2 rules
           (HUD cyan glow) still cascade into this block since it's rendered in the live app DOM,
           not a separate document — the standalone HTML export doesn't have this problem since
           it never includes index.css at all. */
        .qubit-print h1 { font-size: 1.8rem; margin-bottom: 0.2rem; color: #12161f; text-shadow: none; }
        .qubit-print h2 { font-size: 1.15rem; margin-top: 2.2rem; border-bottom: 2px solid #12161f; padding-bottom: 0.35rem; color: #12161f; text-shadow: none; }
        .qubit-print .meta { color: #5a6472; font-size: 0.9rem; margin-bottom: 1.5rem; }
        .qubit-print table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.88rem; }
        .qubit-print th, .qubit-print td { text-align: left; padding: 0.5rem 0.7rem; border-bottom: 1px solid #dde1e7; }
        .qubit-print th { background: #f3f5f8; font-weight: 600; }
        .qubit-print .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.9rem; margin-top: 1rem; }
        .qubit-print .kpi { border: 1px solid #dde1e7; border-radius: 8px; padding: 0.9rem 1rem; }
        .qubit-print .kpi .label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: #5a6472; }
        .qubit-print .kpi .value { font-size: 1.6rem; font-weight: 700; margin-top: 0.2rem; }
        .qubit-print .danger { color: #b3261e; } .qubit-print .warn { color: #935e00; }
        .qubit-print .safe { color: #0f7b4f; } .qubit-print .info { color: #0a5fb0; }
        .qubit-print .mono { font-family: "SF Mono", "JetBrains Mono", Consolas, monospace; font-size: 0.85em; }
        .qubit-print .note { color: #5a6472; font-size: 0.8rem; margin-top: 2.5rem; border-top: 1px solid #dde1e7; padding-top: 0.8rem; }
      </style>${reportBodyHtml()}`
    : '';

  return (
    // `data-testid` + an accessible region name so the report CONTENT is addressable on its own.
    // Several of this page's headings are also sidebar nav labels ("CRQC Timeline", "Migrations"), so
    // anything matching on page text alone — a browser test, a screen-reader rotor, Ctrl-F — can land
    // on the navigation instead of the report and appear to succeed before any data has loaded.
    <AnimatedPage
      className="flex flex-col gap-6 py-5 print:py-0"
      data-testid="report-root"
      aria-label="Detailed report"
    >
      <header className="flex flex-wrap items-end justify-between gap-4 print:hidden">
        <div>
          <h1 className="flex items-center gap-3">
            <FileText className="h-8 w-8 text-[color:var(--color-accent)]" />
            Detailed Report
          </h1>
          <p className="mt-2 text-sm text-[color:var(--color-ink-dim)]">
            {scan
              ? `Scan #${scan.seq} · ${scan.targets.join(', ')}`
              : 'A single exportable document covering inventory, risk, timeline and migration status.'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={printReport} disabled={!scan} className="hud-btn hud-btn-ghost">
            <Printer className="h-3.5 w-3.5" />
            Print page
          </button>
          <button onClick={exportHtml} disabled={!scan} className="hud-btn hud-btn-ghost">
            <Download className="h-3.5 w-3.5" />
            Export HTML
          </button>
          <button
            onClick={downloadSarif}
            disabled={!scan || busy !== null}
            className="hud-btn hud-btn-ghost"
            title="SARIF 2.1.0 — upload to GitHub code scanning"
          >
            {busy === 'sarif' ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Bug className="h-3.5 w-3.5" />
            )}
            SARIF
          </button>
          <button onClick={downloadPdf} disabled={!scan || busy !== null} className="hud-btn">
            {busy === 'pdf' ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileDown className="h-3.5 w-3.5" />
            )}
            {busy === 'pdf' ? 'Generating…' : 'Download PDF report'}
          </button>
        </div>
      </header>

      {downloadError && (
        <div className="glass-card border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/8 p-4 text-sm text-[color:var(--color-danger)] print:hidden">
          {downloadError}
        </div>
      )}

      {!scanId && (
        <div className="glass-card p-10 text-center text-sm text-[color:var(--color-ink-dim)] print:hidden">
          Open this report from a specific scan.{' '}
          <Link to="/scans" className="text-[color:var(--color-accent)] hover:text-[color:var(--color-accent-2)]">
            Go to Scans &amp; Jobs
          </Link>
          .
        </div>
      )}

      {isLoading && (
        <div className="glass-card flex items-center justify-center gap-3 p-14 text-[color:var(--color-ink-dim)] print:hidden">
          <RefreshCw className="h-4 w-4 animate-spin" /> Assembling report…
        </div>
      )}

      {scan && (
        <>
          <div className="stagger grid grid-cols-2 gap-5 lg:grid-cols-4 print:hidden">
            <div className="glass-card flex h-28 flex-col justify-between p-5">
              <span className="metric-label text-[color:var(--color-accent)]">Total assets</span>
              <div className="flex items-end justify-between">
                <span className="metric text-[color:var(--color-accent)]">{totalAssets}</span>
                <Boxes className="h-8 w-8 opacity-25 text-[color:var(--color-accent)]" />
              </div>
            </div>
            <div className="glass-card flex h-28 flex-col justify-between p-5">
              <span className="metric-label text-[color:var(--color-danger)]">
                {truncated ? 'Quantum-vulnerable*' : 'Quantum-vulnerable'}
              </span>
              <div className="flex items-end justify-between">
                <span className="metric text-[color:var(--color-danger)]">{vulnerable.length}</span>
                <ShieldAlert className="h-8 w-8 opacity-25 text-[color:var(--color-danger)]" />
              </div>
            </div>
            <div className="glass-card flex h-28 flex-col justify-between p-5">
              <span className="metric-label text-[color:var(--color-accent-2)]">
                {truncated ? 'HNDL exposures*' : 'HNDL exposures'}
              </span>
              <div className="flex items-end justify-between">
                <span className="metric text-[color:var(--color-accent-2)]">{hndl.length}</span>
                <KeyRound className="h-8 w-8 opacity-25 text-[color:var(--color-accent-2)]" />
              </div>
            </div>
            <div className="glass-card flex h-28 flex-col justify-between p-5">
              <span className="metric-label text-[color:var(--color-safe)]">
                {truncated ? 'Quantum-safe*' : 'Quantum-safe'}
              </span>
              <div className="flex items-end justify-between">
                <span className="metric text-[color:var(--color-safe)]">{safe}</span>
                <ShieldCheck className="h-8 w-8 opacity-25 text-[color:var(--color-safe)]" />
              </div>
            </div>
          </div>
          {truncated && (
            <p className="metric-label -mt-2 normal-case tracking-normal text-[color:var(--color-warn)] print:hidden">
              * This scan has {totalAssets} assets; the breakdown above reflects only the first{' '}
              {items.length} (the report's per-scan limit).
            </p>
          )}

          {timelineQ.data && (
            <div className="glass-card p-6 print:hidden">
              <h2 className="mb-2">CRQC timeline — {timelineQ.data.algorithm}</h2>
              <p className="text-sm leading-relaxed text-[color:var(--color-ink-dim)]">
                Based on {timelineQ.data.n_trials.toLocaleString()} Monte-Carlo trials, the dominant
                vulnerable algorithm in this scan is projected to become breakable between{' '}
                <span className="font-mono text-[color:var(--color-accent-2)]">{timelineQ.data.p05_year}</span>{' '}
                and{' '}
                <span className="font-mono text-[color:var(--color-accent-2)]">{timelineQ.data.p95_year}</span>,
                median{' '}
                <span className="font-mono text-[color:var(--color-accent)]">{timelineQ.data.median_year}</span>.
                Under HNDL, harvested traffic is exposed from today, not from that date.
              </p>
            </div>
          )}

          <div className="glass-card overflow-hidden print:hidden">
            <div className="label-caps border-b border-[color:var(--edge)] px-5 py-3">
              Highest-risk assets (top {Math.min(25, items.length)} of {totalAssets})
            </div>
            <div className="overflow-x-auto">
              <table className="hud-table min-w-full">
                <thead>
                  <tr>
                    <th className="px-5 py-3">Algorithm / finding</th>
                    <th className="px-5 py-3">Context</th>
                    <th className="px-5 py-3">Status</th>
                    <th className="px-5 py-3">Risk</th>
                    <th className="px-5 py-3">Location</th>
                  </tr>
                </thead>
                <tbody>
                  {[...items]
                    .sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0))
                    .slice(0, 25)
                    .map((a) => {
                      const loc = a.location.file_path
                        ? `${a.location.file_path}${a.location.line ? `:${a.location.line}` : ''}`
                        : (a.location.host ?? '—');
                      const status = isHndl(a)
                        ? 'HNDL exposure'
                        : a.quantum_vulnerable.vulnerable
                          ? `Vulnerable · ${a.quantum_vulnerable.attack}`
                          : 'Quantum-safe';
                      return (
                        <tr key={a.id} className="data-row">
                          <td className="px-5 py-3 text-[color:var(--color-accent-soft)]">
                            {displayAlgorithm(a.algorithm)}
                          </td>
                          <td className="px-5 py-3">{a.usage_context}</td>
                          <td className="px-5 py-3">{status}</td>
                          <td className="px-5 py-3 tabular-nums">{a.risk ? a.risk.score.toFixed(2) : '—'}</td>
                          <td className="max-w-[20rem] truncate px-5 py-3 text-xs text-[color:var(--color-ink-dim)]">
                            {loc}
                          </td>
                        </tr>
                      );
                    })}
                  {items.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-5 py-10 text-center text-[color:var(--color-ink-faint)]">
                        No assets in this scan.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="glass-card p-6 print:hidden">
            <h2 className="mb-3">Migration status</h2>
            {queueByState.size === 0 ? (
              <p className="text-sm text-[color:var(--color-ink-dim)]">
                No migration plan has been built for this registry yet.
              </p>
            ) : (
              <div className="flex flex-wrap gap-3">
                {[...queueByState.entries()].map(([state, n]) => (
                  <span key={state} className="chip chip-info">
                    {state}: {n}
                  </span>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* Printable view: hidden on screen, shown only for window.print() / Ctrl+P. Light theme —
          the HUD glass panels above don't print legibly (dark backgrounds, glow effects). */}
      {scan && (
        <div className="hidden qubit-print print:block" dangerouslySetInnerHTML={{ __html: printableHtml }} />
      )}
    </AnimatedPage>
  );
}
