# Manifest

Every identifier in the evidence specification, with its status decided by looking
for the artifact rather than by remembering whether it was built. `PARTIAL` names the
shortfall.
`N/A` records why an item does not apply, so an absence is not mistaken for an omission.

**57 DONE · 3 PARTIAL · 0 MISSING · 6 N/A**

| id | item | status | artifact | note |
|---|---|---|---|---|
| A1 | Module inventory + LOC | DONE | `tables/T_modules.csv` |  |
| A2 | Language breakdown | DONE | `tables/T_languages.csv` | source separated from config |
| A3 | Dependencies, pinned | DONE | `env/versions.lock` |  |
| A4 | Tech stack table | DONE | `tables/T03_tech_stack.csv` | versions resolved, not declared |
| A5 | Architecture diagram | DONE | `figures/F02_architecture.svg` | from the real import graph |
| A6 | Pipeline / workflow diagram | DONE | `figures/F03_workflow.svg` | stages from the code |
| A7 | Data model / schema | DONE | `figures/F05_data_model.svg` | introspected from metadata |
| A8 | Config surface | DONE | `tables/T_config.csv` |  |
| A9 | Public API / CLI surface | DONE | `tables/T_api.md` |  |
| A10 | Test inventory + coverage | DONE | `tables/T_tests.csv` | line+branch coverage in tables/T_coverage.md; suites by kind in VERIFICATION.md |
| A11 | Hardware / OS / digests | DONE | `env/hardware.txt` |  |
| A12 | Truth tables | DONE | `tables/T12_validation_gate.md` | validation gate enumerated over all 243 combinations |
| A13 | Prompt templates verbatim | DONE | `cards/prompts.md` | the builder function, not a rendered sample |
| B1 | Throughput | DONE | `data/performance.csv` | 5 reps, quiet machine, mean +/- SD |
| B2 | Latency p50/p95 | DONE | `data/performance.csv` | 5 reps, quiet machine |
| B3 | Per-stage latency | DONE | `data/performance.csv` | 5 reps, quiet machine |
| B4 | Peak memory | DONE | `data/performance.csv` | tracemalloc, Python allocations only |
| B5 | Scalability curve | PARTIAL | `figures/F12_sweep_cost.svg` | one corpus-sweep run; F13/F14 carry the 5-rep timing instead |
| B6 | Parallel scaling | N/A |  | the sweep is serial by design |
| B7 | Cost per unit | N/A |  | local inference: no token cost; energy not instrumented |
| B8 | Accuracy per class + CI | DONE | `tables/T07.csv` | Wilson + bootstrap by repository |
| B9 | PR curves | N/A |  | categorical output with no score |
| B10 | Calibration / ECE / Brier | N/A |  | no probabilistic output |
| B11 | Confusion matrix | DONE | `tables/T_confusion_holdout.md` | both cohorts |
| B12 | Ablations | DONE | `tables/T08_ablation.csv` | constant folding on/off, reproduced by --no-fold |
| B13 | Baseline comparison | DONE | `tables/T09_groundtruth.csv` | vs CryptoAPI-Bench published ground truth, comparable to CryptoGuard |
| B14 | Statistical tests | DONE | `tables/T11.csv` | exact McNemar, paired, Holm-Bonferroni |
| B15 | Learning curves | N/A |  | nothing is trained |
| B16 | Sensitivity analysis | DONE | `figures/F11_sensitivity.svg` | tornado over the Mosca-margin inputs, tables/T15_sensitivity.csv |
| B17 | Convergence | DONE | `data/convergence.csv` |  |
| B18 | Failure cases | DONE | `data/failures.md` |  |
| B19 | Case study before/after | DONE | `data/case_study.md` | 26-repo migration run, one full diff |
| T01 | Notation | DONE | `tables/T01_notation.csv` |  |
| T02 | Taxonomy / definitions | DONE | `tables/T02_taxonomy.csv` | from PROTOCOL.md |
| T03 | Tech stack | DONE | `tables/T03_tech_stack.csv` |  |
| T04 | Dataset characteristics | DONE | `tables/T04_dataset.csv` | stratum and primary language reported separately |
| T05 | Coverage matrix | DONE | `tables/T05_coverage.csv` | rules per grammar, explicit vs resolved PQC |
| T06 | Hyperparameters | DONE | `cards/model_migration_llm.md` |  |
| T07 | Main results with CI | DONE | `tables/T07.csv` |  |
| T08 | Ablations | DONE | `tables/T08_ablation.csv` | see B12 |
| T09 | Baseline comparison | DONE | `tables/T09_groundtruth.csv` | see B13 |
| T10 | Efficiency / resources | DONE | `data/performance.csv` | see B1-B4 |
| T11 | Statistical tests | DONE | `tables/T11.csv` |  |
| T12 | Truth tables | DONE | `tables/T12_screening_classifier.md` | 4 decision points |
| T13 | Threats to validity | PARTIAL | `QUESTIONS.md` | drafted in Q11, awaiting author endorsement |
| T14 | Compliance / standard mapping | DONE | `tables/T14_cnsa2.csv` | CNSA 2.0 milestones and weights |
| T15 | Sensitivity analysis (risk model) | DONE | `tables/T15_sensitivity.csv` | tornado over the Mosca-margin inputs |
| T16 | Learned tiers / model cards | DONE | `tables/T16_models.csv` | XGBoost conformal metrics, DistilBERT, local rewriter |
| V1 | Security testing | DONE | `VERIFICATION.md` | live probes; SSRF-to-metadata and missing headers found and fixed |
| V2 | Accessibility conformance (WCAG 2.2 AA) | DONE | `VERIFICATION.md` | axe-core 0 violations, SC 2.5.8/2.4.7/2.4.11 checked, pinned by e2e |
| F01 | Motivating example | DONE | `data/case_study.md` | SHA-1 -> SHA-256, both arms |
| F02 | Architecture | DONE | `figures/F02_architecture.svg` |  |
| F03 | Workflow | DONE | `figures/F03_workflow.svg` |  |
| F04 | Sample output listing | DONE | `data/case_study.md` | real diff_text, both arms |
| F05 | Data model | DONE | `figures/F05_data_model.svg` |  |
| F07 | Convergence | DONE | `figures/F07_bootstrap_convergence.svg` |  |
| F09 | PR curves | N/A |  | see B9 |
| F10 | Human agreement | DONE | `figures/F10_human_agreement.svg` | real inter-rater kappa, second annotator; slot repurposed from calibration (N/A here) |
| F11 | Sensitivity | DONE | `figures/F11_sensitivity.svg` | see B16 |
| F12 | Scalability log-log | PARTIAL | `figures/F12_sweep_cost.svg` | one corpus-sweep run; see F13/F14 |
| F13 | Throughput vs baselines | DONE | `figures/F13_throughput.svg` | 5 reps, quiet machine |
| F14 | Stage latency | DONE | `figures/F14_stage_latency.svg` | 5 reps, quiet machine |
| F16 | Ablations | DONE | `figures/F16_ablation.svg` | recall by analysis dimension |
| F17 | Overhead vs baseline | DONE | `figures/F17_overhead.svg` | wall-clock vs the 4 baseline detectors, data/detector_overhead.csv |
| F18 | Case study before/after | DONE | `data/case_study.md` | see B19 |
| F19 | UI screenshot | DONE | `figures/F19_ui.png` | real scan (multica-ai/multica, 298 assets) via Playwright; see F19_ui_overview.png too |

## Regenerating the pack

```
uv run python paper_evidence/scripts/phase0_architecture.py
uv run python paper_evidence/scripts/phase1_extract.py
uv run python paper_evidence/scripts/phase1_reference.py
uv run python paper_evidence/scripts/phase1_truth_tables.py
uv run python paper_evidence/scripts/phase2_accuracy.py
uv run python paper_evidence/scripts/phase2_groundtruth.py
uv run python paper_evidence/scripts/phase2_figures.py
uv run python paper_evidence/scripts/phase3_sensitivity.py
uv run python paper_evidence/scripts/phase4_models_and_verification.py
uv run python paper_evidence/scripts/phase3_overhead.py
uv run python paper_evidence/scripts/phase6_manifest.py
uv run python paper_evidence/scripts/build_pack.py
```

Slower, heavier steps that need extra state (a quiet machine, corpus clones on disk, or
Ollama running) and are run separately rather than on every regen:

```
uv run python paper_evidence/scripts/phase3_migration.py --repos 26 --limit 10
uv run python paper_evidence/scripts/phase3_case_study.py
uv run python paper_evidence/scripts/phase3_performance.py --reps 5
uv run pytest packages benchmarks -q --cov=packages --cov-report=json:paper_evidence/coverage.json
```

Deleting `paper_evidence/` and running those in order reproduces everything except
the two
hand-written pages (`GAPS.md`, `QUESTIONS.md`). Anything that does not reappear was
hand-edited residue and does not belong in the pack.
