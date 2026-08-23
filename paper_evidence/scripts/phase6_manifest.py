"""Phase 6a: the manifest, computed from what is actually on disk.

The previous manifest was written by hand and went stale the moment an artifact was added, which is
the failure mode a manifest exists to prevent. Every row here is decided by looking for the file,
so a status can only be wrong if the file is.

    uv run python paper_evidence/scripts/phase6_manifest.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT

DONE, PARTIAL, MISSING, NA = "DONE", "PARTIAL", "MISSING", "N/A"

#: (id, description, artifact relative to paper_evidence/, note when the artifact is absent or
#: only partly satisfies the specification). An empty artifact means the row is judged, not found.
SPEC: list[tuple[str, str, str, str, str]] = [
    # id, item, artifact, status-if-present, note
    ("A1", "Module inventory + LOC", "tables/T_modules.csv", DONE, ""),
    ("A2", "Language breakdown", "tables/T_languages.csv", DONE, "source separated from config"),
    ("A3", "Dependencies, pinned", "env/versions.lock", DONE, ""),
    (
        "A4",
        "Tech stack table",
        "tables/T03_tech_stack.csv",
        DONE,
        "versions resolved, not declared",
    ),
    (
        "A5",
        "Architecture diagram",
        "figures/F02_architecture.svg",
        DONE,
        "from the real import graph",
    ),
    ("A6", "Pipeline / workflow diagram", "figures/F03_workflow.svg", DONE, "stages from the code"),
    ("A7", "Data model / schema", "figures/F05_data_model.svg", DONE, "introspected from metadata"),
    ("A8", "Config surface", "tables/T_config.csv", DONE, ""),
    ("A9", "Public API / CLI surface", "tables/T_api.md", DONE, ""),
    (
        "A10",
        "Test inventory + coverage",
        "tables/T_tests.csv",
        DONE,
        "line+branch coverage in tables/T_coverage.md; suites by kind in VERIFICATION.md",
    ),
    ("A11", "Hardware / OS / digests", "env/hardware.txt", DONE, ""),
    (
        "A12",
        "Truth tables",
        "tables/T12_validation_gate.md",
        DONE,
        "validation gate enumerated over all 243 combinations",
    ),
    (
        "A13",
        "Prompt templates verbatim",
        "cards/prompts.md",
        DONE,
        "the builder function, not a rendered sample",
    ),
    ("B1", "Throughput", "data/performance.csv", DONE, "5 reps, quiet machine, mean +/- SD"),
    ("B2", "Latency p50/p95", "data/performance.csv", DONE, "5 reps, quiet machine"),
    ("B3", "Per-stage latency", "data/performance.csv", DONE, "5 reps, quiet machine"),
    ("B4", "Peak memory", "data/performance.csv", DONE, "tracemalloc, Python allocations only"),
    (
        "B5",
        "Scalability curve",
        "figures/F12_sweep_cost.svg",
        PARTIAL,
        "one corpus-sweep run; F13/F14 carry the 5-rep timing instead",
    ),
    ("B6", "Parallel scaling", "", NA, "the sweep is serial by design"),
    ("B7", "Cost per unit", "", NA, "local inference: no token cost; energy not instrumented"),
    ("B8", "Accuracy per class + CI", "tables/T07.csv", DONE, "Wilson + bootstrap by repository"),
    ("B9", "PR curves", "", NA, "categorical output with no score"),
    ("B10", "Calibration / ECE / Brier", "", NA, "no probabilistic output"),
    ("B11", "Confusion matrix", "tables/T_confusion_holdout.md", DONE, "both cohorts"),
    (
        "B12",
        "Ablations",
        "tables/T08_ablation.csv",
        DONE,
        "constant folding on/off, reproduced by --no-fold",
    ),
    (
        "B13",
        "Baseline comparison",
        "tables/T09_groundtruth.csv",
        DONE,
        "vs CryptoAPI-Bench published ground truth, comparable to CryptoGuard",
    ),
    ("B14", "Statistical tests", "tables/T11.csv", DONE, "exact McNemar, paired, Holm-Bonferroni"),
    ("B15", "Learning curves", "", NA, "nothing is trained"),
    (
        "B16",
        "Sensitivity analysis",
        "figures/F11_sensitivity.svg",
        DONE,
        "tornado over the Mosca-margin inputs, tables/T15_sensitivity.csv",
    ),
    ("B17", "Convergence", "data/convergence.csv", DONE, ""),
    ("B18", "Failure cases", "data/failures.md", DONE, ""),
    (
        "B19",
        "Case study before/after",
        "data/case_study.md",
        DONE,
        "26-repo migration run, one full diff",
    ),
    ("T01", "Notation", "tables/T01_notation.csv", DONE, ""),
    ("T02", "Taxonomy / definitions", "tables/T02_taxonomy.csv", DONE, "from PROTOCOL.md"),
    ("T03", "Tech stack", "tables/T03_tech_stack.csv", DONE, ""),
    (
        "T04",
        "Dataset characteristics",
        "tables/T04_dataset.csv",
        DONE,
        "stratum and primary language reported separately",
    ),
    (
        "T05",
        "Coverage matrix",
        "tables/T05_coverage.csv",
        DONE,
        "rules per grammar, explicit vs resolved PQC",
    ),
    ("T06", "Hyperparameters", "cards/model_migration_llm.md", DONE, ""),
    ("T07", "Main results with CI", "tables/T07.csv", DONE, ""),
    ("T08", "Ablations", "tables/T08_ablation.csv", DONE, "see B12"),
    ("T09", "Baseline comparison", "tables/T09_groundtruth.csv", DONE, "see B13"),
    ("T10", "Efficiency / resources", "data/performance.csv", DONE, "see B1-B4"),
    ("T11", "Statistical tests", "tables/T11.csv", DONE, ""),
    ("T12", "Truth tables", "tables/T12_screening_classifier.md", DONE, "4 decision points"),
    (
        "T13",
        "Threats to validity",
        "QUESTIONS.md",
        PARTIAL,
        "drafted in Q11, awaiting author endorsement",
    ),
    (
        "T14",
        "Compliance / standard mapping",
        "tables/T14_cnsa2.csv",
        DONE,
        "CNSA 2.0 milestones and weights",
    ),
    (
        "T15",
        "Sensitivity analysis (risk model)",
        "tables/T15_sensitivity.csv",
        DONE,
        "tornado over the Mosca-margin inputs",
    ),
    (
        "T16",
        "Learned tiers / model cards",
        "tables/T16_models.csv",
        DONE,
        "XGBoost conformal metrics, DistilBERT, local rewriter",
    ),
    (
        "V1",
        "Security testing",
        "VERIFICATION.md",
        DONE,
        "live probes; SSRF-to-metadata and missing headers found and fixed",
    ),
    (
        "V2",
        "Accessibility conformance (WCAG 2.2 AA)",
        "VERIFICATION.md",
        DONE,
        "axe-core 0 violations, SC 2.5.8/2.4.7/2.4.11 checked, pinned by e2e",
    ),
    ("F01", "Motivating example", "data/case_study.md", DONE, "SHA-1 -> SHA-256, both arms"),
    ("F02", "Architecture", "figures/F02_architecture.svg", DONE, ""),
    ("F03", "Workflow", "figures/F03_workflow.svg", DONE, ""),
    ("F04", "Sample output listing", "data/case_study.md", DONE, "real diff_text, both arms"),
    ("F05", "Data model", "figures/F05_data_model.svg", DONE, ""),
    ("F07", "Convergence", "figures/F07_bootstrap_convergence.svg", DONE, ""),
    ("F09", "PR curves", "", NA, "see B9"),
    (
        "F10",
        "Human agreement",
        "figures/F10_human_agreement.svg",
        DONE,
        "real inter-rater kappa, second annotator; slot repurposed from calibration (N/A here)",
    ),
    ("F11", "Sensitivity", "figures/F11_sensitivity.svg", DONE, "see B16"),
    (
        "F12",
        "Scalability log-log",
        "figures/F12_sweep_cost.svg",
        PARTIAL,
        "one corpus-sweep run; see F13/F14",
    ),
    ("F13", "Throughput vs baselines", "figures/F13_throughput.svg", DONE, "5 reps, quiet machine"),
    ("F14", "Stage latency", "figures/F14_stage_latency.svg", DONE, "5 reps, quiet machine"),
    ("F16", "Ablations", "figures/F16_ablation.svg", DONE, "recall by analysis dimension"),
    (
        "F17",
        "Overhead vs baseline",
        "figures/F17_overhead.svg",
        DONE,
        "wall-clock vs the 4 baseline detectors, data/detector_overhead.csv",
    ),
    ("F18", "Case study before/after", "data/case_study.md", DONE, "see B19"),
    (
        "F19",
        "UI screenshot",
        "figures/F19_ui.png",
        DONE,
        "real scan (multica-ai/multica, 298 assets) via Playwright; see F19_ui_overview.png too",
    ),
]


def build() -> int:
    rows = []
    for spec_id, item, artifact, present_status, note in SPEC:
        if present_status == NA:
            status = NA
        elif artifact and (OUT / artifact).exists():
            status = present_status
        elif artifact:
            status = MISSING
        else:
            status = present_status
        rows.append((spec_id, item, status, artifact, note))

    counts = {s: sum(1 for r in rows if r[2] == s) for s in (DONE, PARTIAL, MISSING, NA)}

    lines = [
        "# Manifest",
        "",
        "Every identifier in the evidence specification, with its status decided by looking",
        "for the artifact rather than by remembering whether it was built. `PARTIAL` names the",
        "shortfall.",
        "`N/A` records why an item does not apply, so an absence is not mistaken for an omission.",
        "",
        f"**{counts[DONE]} DONE · {counts[PARTIAL]} PARTIAL · {counts[MISSING]} MISSING · "
        f"{counts[NA]} N/A**",
        "",
        "| id | item | status | artifact | note |",
        "|---|---|---|---|---|",
    ]
    for spec_id, item, status, artifact, note in rows:
        shown = f"`{artifact}`" if artifact and status not in (MISSING, NA) else ""
        lines.append(f"| {spec_id} | {item} | {status} | {shown} | {note} |")

    lines += [
        "",
        "## Regenerating the pack",
        "",
        "```",
        "uv run python paper_evidence/scripts/phase0_architecture.py",
        "uv run python paper_evidence/scripts/phase1_extract.py",
        "uv run python paper_evidence/scripts/phase1_reference.py",
        "uv run python paper_evidence/scripts/phase1_truth_tables.py",
        "uv run python paper_evidence/scripts/phase2_accuracy.py",
        "uv run python paper_evidence/scripts/phase2_groundtruth.py",
        "uv run python paper_evidence/scripts/phase2_figures.py",
        "uv run python paper_evidence/scripts/phase3_sensitivity.py",
        "uv run python paper_evidence/scripts/phase4_models_and_verification.py",
        "uv run python paper_evidence/scripts/phase3_overhead.py",
        "uv run python paper_evidence/scripts/phase6_manifest.py",
        "uv run python paper_evidence/scripts/build_pack.py",
        "```",
        "",
        "Slower, heavier steps that need extra state (a quiet machine, corpus clones on disk, or",
        "Ollama running) and are run separately rather than on every regen:",
        "",
        "```",
        "uv run python paper_evidence/scripts/phase3_migration.py --repos 26 --limit 10",
        "uv run python paper_evidence/scripts/phase3_case_study.py",
        "uv run python paper_evidence/scripts/phase3_performance.py --reps 5",
        "uv run pytest packages benchmarks -q --cov=packages "
        "--cov-report=json:paper_evidence/coverage.json",
        "```",
        "",
        "Deleting `paper_evidence/` and running those in order reproduces everything except",
        "the two",
        "hand-written pages (`GAPS.md`, `QUESTIONS.md`). Anything that does not reappear was",
        "hand-edited residue and does not belong in the pack.",
    ]
    (OUT / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"manifest: {counts[DONE]} DONE, {counts[PARTIAL]} PARTIAL, "
        f"{counts[MISSING]} MISSING, {counts[NA]} N/A"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(build())
