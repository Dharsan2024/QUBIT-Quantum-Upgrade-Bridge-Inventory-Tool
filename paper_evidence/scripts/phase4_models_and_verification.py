"""Phase 4: the learned tiers, and the verification the system is held to.

Two things the pack could not previously show a reader.

**The ML tiers.** QUBIT's risk score has three tiers -- a closed-form heuristic, a fine-tuned
DistilBERT sensitivity classifier, and an XGBoost regressor with conformal intervals -- and the pack
described only the first. The regressor ships with its own held-out metrics (`models/risk-xgboost/
metrics.json`) and a conformal calibration record; both are read here rather than restated, so a
number in the PDF is the number the artifact carries.

**The verification.** "1851 tests pass" is not evidence on its own: what matters is what KIND of
checking runs, and what each kind is capable of catching. This enumerates the suites, including the
security probes and the WCAG 2.2 accessibility regression added after the app was pen-tested.

    uv run python paper_evidence/scripts/phase4_models_and_verification.py

Covers T06 (hyperparameters, learned tiers), A10 (test inventory by kind), and the security posture
a reviewer will ask about before trusting a tool that rewrites source code.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, ROOT


def _xgboost_card() -> list[str]:
    """The regressor's own metrics file. Absent is reported, never invented."""
    metrics_path = ROOT / "models" / "risk-xgboost" / "metrics.json"
    conformal_path = ROOT / "models" / "risk-xgboost" / "conformal.json"
    if not metrics_path.exists():
        return ["**XGBoost risk regressor** — not trained in this checkout (`models/risk-xgboost` "
                "absent), so no metrics are reported."]  # fmt: skip

    m = json.loads(metrics_path.read_text(encoding="utf-8"))
    features = []
    if conformal_path.exists():
        features = json.loads(conformal_path.read_text(encoding="utf-8")).get("feature_names", [])

    lines = [
        "### XGBoost risk regressor (distilled scoring tier)",
        "",
        "Distils the closed-form risk score so the app can return a score plus a calibrated "
        "interval without re-running the Monte-Carlo timeline per asset. Loaded only when "
        "`QUBIT_RISK_XGB_DIR` points at a trained directory; otherwise the pipeline falls back to "
        "the closed form, which is why the tier is optional rather than required.",
        "",
        "| property | value |",
        "|---|---|",
        f"| training population | {m.get('n_assets', 0):,} synthetic assets, "
        f"{m.get('k_draws', 0)} timeline draws each |",
        f"| split | {m.get('n_train', 0):,} train / {m.get('n_cal', 0):,} calibration / "
        f"{m.get('n_test', 0):,} test |",
        f"| test MAE | {m.get('test_mae', float('nan')):.4f} (risk score is on 0-1) |",
        f"| conformal target coverage | {m.get('target_coverage', 0):.0%} |",
        f"| empirical test coverage | **{m.get('empirical_test_coverage', 0):.2%}** |",
        f"| mean interval width | {m.get('mean_interval_width', float('nan')):.4f} |",
        f"| q̂ (conformal quantile) | {m.get('q_hat', float('nan')):.4f} |",
        f"| input features | {len(features)} |",
        "",
        "The coverage line is the one that matters: split-conformal prediction gives a "
        "distribution-free guarantee that the interval contains the true value at the target rate, "
        "and the measured "
        f"{m.get('empirical_test_coverage', 0):.2%} against a {m.get('target_coverage', 0):.0%} "
        "target is the check that the guarantee held on data the model never saw. An interval "
        f"{m.get('mean_interval_width', 0):.4f} wide on a 0-1 score is narrow enough to be useful "
        "rather than vacuously correct.",
        "",
        "**Trained on synthetic data, and that is a limitation, not a footnote.** The "
        "population is "
        "generated from the same priors the closed-form score uses, so the regressor is distilling "
        "a model rather than learning from observed breaches — it inherits every assumption in "
        "`qubit_risk` and can be no better calibrated than they are.",
    ]
    if features:
        lines += [
            "",
            "Feature groups: algorithm family (10 one-hot), key size, quantum-attack ordinal, "
            "CRQC arrival probabilities at 2030/2035/2040, median break year, data-sensitivity "
            "class (7 one-hot), shelf-life mean and P90, exposure class, usage ordinal, and four "
            "posture flags (pre-TLS-1.3, expired certificate, deprecated library, HNDL "
            "probability).",
        ]
    return lines


def _distilbert_card() -> list[str]:
    trained = (ROOT / "models" / "sensitivity-distilbert").is_dir()
    dataset = ROOT / "datasets" / "sensitivity" / "synth.jsonl"
    rows = 0
    if dataset.exists():
        rows = sum(1 for line in dataset.open(encoding="utf-8") if line.strip())
    return [
        "### DistilBERT data-sensitivity classifier",
        "",
        "Decides what KIND of data a finding protects — PHI, PII, financial, credentials, "
        "intellectual property, ephemeral, public — which is the input that sets shelf-life, and "
        "therefore the Mosca margin. The shipped default is the deterministic rule tier in "
        "`qubit_risk.sensitivity`; this is the optional learned replacement.",
        "",
        "| property | value |",
        "|---|---|",
        "| base checkpoint | `distilbert-base-uncased` |",
        "| task | 7-class single-label classification |",
        f"| synthetic training corpus | {rows:,} labelled examples "
        f"(`datasets/sensitivity/synth.jsonl`) |",
        f"| trained artifact present in this checkout | {'yes' if trained else '**no**'} |",
        "",
        "Not trained in this checkout, so **no accuracy is reported for it** — the pack does not "
        "carry a number for a model it cannot point at. `qubit_risk.ml.weaklabel` exists to score "
        "it honestly when it is trained: it measures agreement against a weak-consensus label on "
        "REAL code, not against the synthetic set it was fitted to, because the second number "
        "would only measure memorisation."
        if not trained
        else "Trained artifact present; see `qubit_risk.ml.weaklabel` for the transfer check.",
    ]


def _llm_card() -> list[str]:
    return [
        "### Local code-rewriting model (migration tier)",
        "",
        "The patch generator for rules with no deterministic codemod. Runs entirely on the machine "
        "through Ollama — no code leaves the host, which is a hard requirement for a tool pointed "
        "at private source.",
        "",
        "| property | value |",
        "|---|---|",
        "| model | `qwen2.5-coder:7b-instruct-q4_K_M` |",
        "| fallback | `qwen2.5-coder:1.5b-instruct-q4_K_M` |",
        "| decoding | greedy (`temperature=0.0`), seed pinned at `llm.GENERATION_SEED` |",
        "| repair loop | up to 3 attempts, each re-validated |",
        "| provenance | blob digest and server version in `env/model_provenance.txt` |",
        "",
        "Every generated patch passes the same five-stage gate a template patch does (applies, "
        "parses, compiles, tests, rescan) and is never applied without an explicit human approval "
        "step. Measured acceptance over the 26-repository corpus is in §10.",
    ]


def _test_inventory() -> list[str]:
    """Test suites by KIND, counted from the files themselves."""
    kinds: dict[str, dict[str, int]] = {}

    def add(kind: str, pattern: str, root: Path) -> None:
        files = sorted(root.glob(pattern))
        count = 0
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            count += sum(
                1
                for line in text.splitlines()
                if line.strip().startswith(("def test_", "it(", "test("))
            )
        if files:
            kinds[kind] = {"files": len(files), "cases": count}

    add("Python unit + integration", "packages/*/tests/test_*.py", ROOT)
    add("Benchmark / oracle", "benchmarks/**/test_*.py", ROOT)
    add("Browser end-to-end (Playwright)", "dashboard/e2e/*.spec.ts", ROOT)

    lines = [
        "| suite | files | cases | what it can catch |",
        "|---|---|---|---|",
    ]
    catch = {
        "Python unit + integration": "logic, schema, FSM transitions, API contract, scanner rules, "
        "codemod output, and every regression pinned after a real defect",
        "Benchmark / oracle": "changes to detector agreement, the screening classifier, and the "
        "capture-recapture estimator",
        "Browser end-to-end (Playwright)": "rendering, real API wiring, and WCAG 2.2 AA "
        "conformance — things no unit test can observe",
    }
    for kind, counts in kinds.items():
        lines.append(f"| {kind} | {counts['files']} | {counts['cases']} | {catch.get(kind, '')} |")
    return lines


def _security_section() -> list[str]:
    return [
        "The system rewrites source code and reads whole repositories, so its own attack "
        "surface is "
        "part of the claim. The API was probed live rather than reviewed on paper; both findings "
        "below were fixed and pinned by a regression test.",
        "",
        "| probe | result |",
        "|---|---|",
        "| Unauthenticated access, bad token, empty token | rejected (401) |",
        "| Path traversal in scan targets (`../../`, UNC, `/etc/passwd`) | rejected - target "
        "must exist "
        "and stay inside the configured roots |",
        "| Command injection via git-URL targets (`;`, `&&`, backticks, `--upload-pack`) | "
        "not exploitable - the clone "
        "is `subprocess` with an argument list, never a shell |",
        "| SQL injection on query parameters | rejected at the type boundary (UUID/int parsing) "
        "before any query is built |",
        "| Stack traces or internals in 4xx bodies | none |",
        "| TRACE / TRACK | 405 |",
        "| **SSRF to cloud instance metadata (169.254.169.254)** | **was allowed — FIXED** |",
        "| **Baseline security headers** | **were absent — FIXED** |",
        "",
        "**SSRF to the metadata service.** Python's `ipaddress.is_private` returns true for "
        "link-local (169.254.0.0/16), so the network scanner's \"local targets need no "
        'authorization" rule auto-allowed `169.254.169.254` — the AWS/Azure/GCP instance-metadata '
        "endpoint, and the standard pivot for stealing instance credentials. Measured against the "
        "running app: the scan was accepted and reported `succeeded`, while `8.8.8.8` and "
        "`example.com` were correctly refused. Link-local is now excluded from the auto-allow and "
        "needs the same explicit allowlist entry plus `authorized` flag as any other off-network "
        "target (`test_network_auth.py::TestLinkLocalIsNotTreatedAsSafeLocal`).",
        "",
        "**Response headers.** No `X-Content-Type-Options`, `X-Frame-Options`, "
        "`Content-Security-Policy` or `Referrer-Policy` on any response — and the API serves the "
        "dashboard itself in desktop mode, so those land on HTML a real browser engine "
        "renders. All "
        "four are now set, with a CSP that forbids framing, objects, base-URI rewriting and "
        "`unsafe-eval` (`test_hardening.py::TestSecurityHeaders`).",
    ]


def _accessibility_section() -> list[str]:
    return [
        "EN 301 549 — the technical standard the European Accessibility Act has enforced since "
        "28 June 2025 — is anchored to WCAG Level AA, so an accessibility defect in a shipped tool "
        "is a compliance defect. The dashboard was audited with axe-core in a real browser across "
        "all eight pages, plus checks for the WCAG 2.2 criteria automation cannot fully cover.",
        "",
        "| check | before | after |",
        "|---|---|---|",
        "| axe-core violations (WCAG 2.0/2.1/2.2 A + AA) | 3 critical | **0** |",
        "| SC 2.5.8 Target Size — targets below 24x24 CSS px | 21 | **0** |",
        "| SC 2.4.7 Focus Visible — controls with no focus indicator | 0 | 0 |",
        "| SC 2.4.11 Focus Not Obscured — focused controls hidden by other content | 0 | 0 |",
        "| `prefers-reduced-motion` honoured | yes | yes |",
        "",
        "The three axe violations were real Level A failures: two Settings inputs carried a label "
        "positioned above them but never associated with `htmlFor`/`id`, so a screen reader "
        "announced them as unlabelled; and the CRQC Timeline algorithm picker had no accessible "
        "name at all. The target-size failures were genuine usability defects independent of "
        "assistive technology — the scan-row delete control was 16x21 px and the dependency "
        "recheck 14x14.",
        "",
        "All of it is pinned by `dashboard/e2e/accessibility.spec.ts`, which runs the same axe "
        "sweep, the target-size measurement and a 25-stop keyboard traversal against the built "
        "app, so a regression fails a test rather than reaching a user.",
    ]


def main() -> int:
    body: list[str] = ["# Learned tiers and model cards", ""]
    body += [
        "Three learned or generative components sit inside QUBIT. Each is optional, each degrades "
        "to a deterministic path when absent, and none of them decides anything on its own — the "
        "scanner's findings and the validation gate are rule-based throughout.",
        "",
    ]
    body += [*_xgboost_card(), "", "", *_distilbert_card(), "", "", *_llm_card()]
    (OUT / "MODELS.md").write_text("\n".join(body) + "\n", encoding="utf-8")

    verification = ["# Verification", ""]
    verification += ["## Test suites, by kind", "", *_test_inventory()]
    coverage = ROOT / "paper_evidence" / "coverage.json"
    if coverage.exists():
        totals = json.loads(coverage.read_text(encoding="utf-8"))["totals"]
        verification += [
            "",
            f"Line + branch coverage over `packages/`: **{totals['percent_covered']:.1f}%** "
            f"({totals['num_statements']:,} statements, {totals['missing_lines']:,} uncovered, "
            f"{totals['num_branches']:,} branches).",
        ]
    verification += ["", "## Security testing", "", *_security_section()]
    verification += ["", "## Accessibility conformance", "", *_accessibility_section()]
    (OUT / "VERIFICATION.md").write_text("\n".join(verification) + "\n", encoding="utf-8")

    # A machine-readable companion so a table in the paper can cite a file rather than the PDF.
    with (OUT / "tables" / "T16_models.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["component", "kind", "artifact_present", "headline_metric"])
        metrics_path = ROOT / "models" / "risk-xgboost" / "metrics.json"
        if metrics_path.exists():
            m = json.loads(metrics_path.read_text(encoding="utf-8"))
            writer.writerow([
                "risk regressor", "XGBoost + split conformal", "yes",
                f"test MAE {m['test_mae']:.4f}, coverage {m['empirical_test_coverage']:.2%} "
                f"at {m['target_coverage']:.0%} target",
            ])  # fmt: skip
        writer.writerow([
            "sensitivity classifier", "DistilBERT fine-tune",
            "yes" if (ROOT / "models" / "sensitivity-distilbert").is_dir() else "no",
            "not trained in this checkout — no metric reported",
        ])  # fmt: skip
        writer.writerow([
            "patch generator", "qwen2.5-coder 7B via Ollama", "external (Ollama)",
            "acceptance measured over the 26-repository corpus, see T08/T09",
        ])  # fmt: skip

    print("MODELS.md, VERIFICATION.md, tables/T16_models.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
