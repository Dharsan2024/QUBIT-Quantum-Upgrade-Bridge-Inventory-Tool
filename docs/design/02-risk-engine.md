# QUBIT Design 02 — HNDL Risk Quantification Engine (`qubit-risk`)

Status: v1 design, conforms to `00-architecture-frame.md` (v1, binding).
Owner: risk-engine lead (1 of 2 team members, primary). Reviewer: second member + guide.

---

## 1. Purpose & requirements

### 1.1 Purpose

`qubit-risk` turns the raw cryptographic inventory produced by `qubit-scanner` into a **ranked, probabilistic, explainable migration queue**. For every `CryptoAsset` in the registry it answers one question:

> *What is the probability that data protected by this asset is harvested today and decrypted by a quantum adversary before the data stops mattering?*

It does this with five cooperating models:

| # | Model | Output |
|---|-------|--------|
| a | Monte Carlo CRQC timeline simulator | `F_a(T) = P(CRQC breaks algorithm a by year T)` per algorithm/key-size |
| b | Bayesian network (pgmpy) | `P_HNDL = P(decrypted before obsolete)` per asset |
| c | Data-sensitivity classifier (DistilBERT + heuristic fallback) | sensitivity class + shelf-life prior (Mosca *X*) |
| d | XGBoost risk regressor | `risk.score ∈ [0,1]` + conformal confidence interval |
| e | Mosca inequality calculator | `mosca_margin_years` (can be negative) per asset |

plus **(f)** a risk service that annotates assets in the DB and exposes distributions/curves to the dashboard, CLI, and `qubit-migrate`.

This package is one of the two novelty pillars of the paper (the other is the LLM transformer): *no published work combines hardware-anchored CRQC Monte Carlo simulation with per-asset code-context sensitivity classification into a continuous HNDL score.* Everything here must therefore be **reproducible** (seeded, parameterized in versioned YAML) and **honest about its epistemics** (expert-elicited CPDs are labeled as such; the regressor's labeling strategy is documented, not hidden).

### 1.2 Functional requirements

- **FR1** Compute `F_a(T)` curves for every algorithm in the canonical registry that is quantum-vulnerable (Shor family), for T ∈ [2026, 2100], with Monte Carlo standard error reported. Grover-affected symmetric algorithms get a documented tier treatment (§6.1.6), not a fake CDF.
- **FR2** Given a `CryptoAsset`, produce `sensitivity`, `shelf_life_years`, `risk.score`, `risk.ci_low`, `risk.ci_high`, `risk.mosca_margin_years`, `risk.priority_rank` and persist them on the asset row (fields already reserved in the shared schema).
- **FR3** Every score must be explainable: top feature contributions (TreeSHAP), the BN factor table, and the classifier rule/attention trace must be retrievable per asset (`qubit risk explain <id>`).
- **FR4** Expose REST endpoints (mounted by `qubit-api`) for: batch assessment, timeline curves, per-asset detail, posture summary, Mosca table, and what-if simulation (dashboard sliders re-run the MC with user parameters).
- **FR5** All model parameters (hardware priors, expert-survey anchors, CPDs, shelf-life priors, heuristic rules) live in versioned YAML under `params/`; a run records the params hash so results are reproducible.
- **FR6** Batch-assess 10,000 assets end-to-end **on the heuristic path** (excluding first-time model download) in < 5 min on a 4-core laptop, no GPU. The BERT tier is *not* covered by this budget: DistilBERT-base at 256 tokens costs ~0.3–0.7 s/asset on 4 CPU cores, so the pipeline (i) dedupes context windows by content hash (real inventories are highly repetitive), (ii) runs heuristic-first and invokes BERT **only where the rules abstain or conflict**, and (iii) budgets ≤ 10 min per 1,000 *unique* BERT contexts. Heuristic-path latency and BERT throughput are separate acceptance criteria — never demanded jointly.
- **FR7** Work fully offline after initial model fetch (frame requirement 5).

### 1.3 Non-functional requirements

- **NFR1** Determinism: same DB state + same params hash + same seed ⇒ identical scores (bitwise for MC/BN/Mosca; identical to 1e-6 for XGBoost/BERT).
- **NFR2** Graceful degradation ladder (§7): DistilBERT missing → heuristic classifier; pgmpy failure → closed-form probability; XGBoost model missing → BN probability used directly as score with wide CI. The pipeline never hard-fails a batch because one model is unavailable.
- **NFR3** ≥ 70% pytest coverage (frame CI gate); mypy-clean; ruff-clean.
- **NFR4** All runtime dependencies permissive-licensed and pip-installable (verified in §3).
- **NFR5** Memory ceiling 4 GB RSS during batch assessment (DistilBERT-base ≈ 260 MB weights; batch inference batched at 32).
- **NFR6** No network calls at assess time (models pre-fetched by `qubit risk fetch-models`).

### 1.4 Out of scope (owned elsewhere)

- Discovery of assets (`qubit-scanner`), migration effort estimation *Y* beyond a default lookup table (`qubit-migrate` writes `migration.effort_estimate`; we consume it when present), patch generation, dashboard rendering (we only serve JSON curve data).

---

## 2. Component breakdown

```
packages/qubit-risk/
  pyproject.toml                     # uv-workspace member, pip-installable as qubit-risk
  src/qubit_risk/
    __init__.py                      # public API re-exports
    config.py                        # RiskConfig (pydantic-settings), params loading + hashing
    params/                          # versioned YAML, shipped as package data
      resource_estimates.yaml        #   logical-qubit / Toffoli counts per algorithm
      hardware_priors.yaml           #   qubit-growth & error-rate prior distributions
      expert_survey.yaml             #   GRI-2025 aggregate anchor points
      bn_cpds.yaml                   #   harvest-likelihood CPDs, discretization bins
      sensitivity_rules.yaml         #   heuristic classifier rules
      shelf_life_priors.yaml         #   class → shelf-life distribution
      mosca.yaml                     #   default Y table, percentile choices
    timeline/
      surface_code.py                # footprint & wall-time formulas (pure functions)
      simulator.py                   # CRQCTimelineSimulator (Monte Carlo loop)
      survey.py                      # survey-CDF fitting + blending
    bn/
      network.py                     # HndlBayesNet build/infer + closed-form fallback
    sensitivity/
      heuristic.py                   # HeuristicClassifier (rules engine)
      bert.py                        # BertClassifier (DistilBERT inference wrapper)
      datagen.py                     # training-corpus synthesis + weak labeling
      train_bert.py                  # fine-tune entrypoint (runs on Colab or local GPU)
    regressor/
      features.py                    # FeatureExtractor: CryptoAsset → np vector
      labels.py                      # synthetic label generation (teacher pipeline)
      train.py                       # XGBoost + conformal calibration training
      predict.py                     # RiskRegressor: predict score + CI + SHAP
    mosca.py                         # MoscaCalculator
    pipeline.py                      # RiskPipeline: orchestrates a→e per asset batch
    service.py                       # DB-facing functions used by API/CLI (annotate, query)
    api.py                           # fastapi.APIRouter (mounted by qubit-api) — public
    cli.py                           # typer.Typer sub-app (registered by qubit-cli) — public
  models/                            # .gitignore'd; artifacts fetched/trained locally
    sensitivity-distilbert/          #   fine-tuned checkpoint (HF format)
    risk-xgb.ubj                     #   XGBoost booster (UBJSON)
    conformal.json                   #   calibration residual quantiles
    MODELCARD.md
  tests/
    fixtures/make_fixtures.py        # builds synthetic asset sets + golden files
    ...
```

| Component | Responsibility | Depends on |
|---|---|---|
| `timeline.simulator` | Sample hardware trajectories + resource requirements → empirical CDF per algorithm; cache curves keyed by params hash | `surface_code`, `survey`, numpy/scipy |
| `timeline.survey` | Fit parametric CDF to expert-survey anchors; blend with hardware CDF | scipy.optimize |
| `bn.network` | Build 6-node discrete BN, run VariableElimination per asset evidence; closed-form integral fallback | pgmpy, timeline curves |
| `sensitivity.heuristic` | Deterministic scored regex/keyword rules over code context → class + trace | qubit-core asset models |
| `sensitivity.bert` | DistilBERT sequence classification on constructed context window; confidence gating | transformers, torch |
| `sensitivity.datagen` | Build training corpus: templates + weak labels (rules + local LLM) + human-verified eval split | Ollama (offline optional) |
| `regressor.*` | Feature extraction, teacher-label synthesis, XGBoost train, conformal CI, TreeSHAP explanations | xgboost, MAPIE, scikit-learn |
| `mosca` | Margin computation, "too-late probability" per asset | timeline curves |
| `pipeline` | Batch orchestration, degradation ladder, run bookkeeping | all above |
| `service` | Read/write `CryptoAsset` rows + risk tables via qubit-core SQLAlchemy models | qubit-core, SQLAlchemy |
| `api` / `cli` | Public interfaces (§5) | FastAPI, Typer |

Communication with other packages follows the frame: **only** qubit-core models, the DB, and REST. `qubit-api` imports the public `qubit_risk.api.router`; `qubit-cli` imports the public `qubit_risk.cli.app`. `qubit-migrate` never imports us — it reads `risk.priority_rank` from the DB.

---

## 3. Exact tech stack

All verified as of July 2026; versions are pins for `pyproject.toml` (compatible-release `~=` pins so patch releases flow).

| Library | Version pin | License | Role | Verification note |
|---|---|---|---|---|
| Python | ≥3.12,<3.14 | PSF | frame-binding | pgmpy 1.1.x supports 3.10–3.14 (verified on PyPI) |
| numpy | ~=2.2 | BSD-3 | MC vectorization | — |
| scipy | ~=1.15 | BSD-3 | distributions, CDF fitting (`scipy.optimize.least_squares`, `scipy.stats`) | — |
| pgmpy | ~=1.1 | MIT | discrete Bayesian network | v1.1.2 released 2026-04-30. **Breaking change vs old tutorials:** class is `pgmpy.models.DiscreteBayesianNetwork` (the old `BayesianNetwork`/`BayesianModel` names were removed in 1.0). Verified via pgmpy docs/releases. |
| xgboost | >=3.2,<4 | Apache-2.0 | risk regressor | v3.2.0 released 2026-02-09; 3.3.0 current 2026-06-17 (range pin lets 3.3.x flow). Primary path uses `reg:squarederror` + split conformal (§6.4.4). Native quantile regression (`reg:quantileerror`, `tree_method="hist"`) is used ONLY by the CQR stretch path; its quantile-crossing caveat (GH #9848/#9912) applies there → monotonic sort. |
| MAPIE | ~=1.4 | BSD-3 | conformal prediction intervals | v1.4.1 current; v1 API classes `SplitConformalRegressor` / `ConformalizedQuantileRegressor` (renamed from v0's `MapieRegressor`). scikit-learn-contrib project. Verified via readthedocs/PyPI. |
| scikit-learn | ~=1.6 | BSD-3 | splits, metrics, calibration plots | MAPIE dependency anyway |
| transformers | ~=5.13 | Apache-2.0 | DistilBERT fine-tune + inference | v5.13.1 released 2026-07-11. **v5 is a breaking major over v4** — pin ≥5 and write against v5 `Trainer`/`AutoModelForSequenceClassification` APIs; do not copy v4-era tutorials blindly. Verified via PyPI/HF release notes. |
| torch (CPU wheels) | ~=2.7 | BSD-style | BERT backend | CPU-only install documented (`--index-url https://download.pytorch.org/whl/cpu`) to keep docker image small |
| datasets | ~=3.x | Apache-2.0 | training corpus handling | train-time only (extra) |
| pydantic / pydantic-settings | ~=2.x | MIT | config + API schemas | frame-binding |
| SQLAlchemy | ~=2.0 | MIT | via qubit-core | frame-binding |
| FastAPI / Typer | per qubit-api / qubit-cli lockfile | MIT | interfaces | frame-binding |
| PyYAML | ~=6.0 | MIT | params files | — |
| hypothesis | ~=6.x (dev only) | MPL-2.0 | property tests | dev dependency only, not shipped |

Base model: `distilbert-base-uncased` (Apache-2.0, ~66M params, ~260 MB fp32). Fetched once by `qubit risk fetch-models`, cached under `platformdirs.user_cache_dir("qubit")/models` (never a hand-rolled `~/.cache` path — Windows-correct). Windows dev notes: (a) the HF Hub cache uses symlinks that silently degrade to file copies without Developer Mode — documented, harmless; (b) the CPU torch index is encoded in `[tool.uv.sources]` in `pyproject.toml` so `uv sync` on Windows never pulls ~2.5 GB CUDA wheels. **Supply chain:** `fetch-models` verifies every downloaded artifact against a sha256 manifest committed in-repo (`models/MANIFEST.sha256`) — a security tool that fetches unpinned model weights would be a referee-visible embarrassment.

Optional extras (declared, not default): `qubit-risk[train]` = datasets + accelerate; `qubit-risk[labeling]` = ollama client for weak labeling (dataset construction only, never at assess time).

Deliberately **not** used: GPU-only libs, `optimum`/ONNX (nice-to-have, cut-line C1), any cloud API.

---

## 4. Data models / schemas

### 4.1 Shared `CryptoAsset` fields we read and write (binding, unchanged)

We conform exactly to the frame schema. Read: `id`, `source_scanner`, `location`, `asset_type`, `algorithm`, `key_size`, `protocol_detail`, `library`, `usage_context`, `quantum_vulnerable`, `evidence`, `migration.effort_estimate`. Write:

```text
sensitivity        : pii | phi | financial | ip | credentials | ephemeral | public | unknown
shelf_life_years   : float | null           # E[L] under the class prior (Mosca X); null only if class=public
risk: {
  score            : float 0..1             # calibrated P(decrypted before obsolete)
  ci_low, ci_high  : float 0..1             # 90% conformal interval, clipped to [0,1]
  mosca_margin_years : float                # Z_med − (X_p90 + Y); negative ⇒ already too late
  priority_rank    : int                    # 1 = migrate first, dense rank over current inventory
}
```

**Frame deviations: none.** Extra detail that does not fit the shared schema goes into risk-owned side tables (below), keyed by `asset_id` — an extension, not a schema change.

### 4.2 Risk-owned tables (SQLAlchemy models in `qubit_risk`, migrated via Alembic)

```python
class RiskRun(Base):
    __tablename__ = "risk_runs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid4)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    status: Mapped[str]                  # running | done | failed | partial
    params_hash: Mapped[str]             # sha256 over canonicalized params/*.yaml
    seed: Mapped[int]
    n_assets: Mapped[int]
    n_trials: Mapped[int]                # MC trials used
    engine_version: Mapped[str]          # qubit-risk __version__
    degradations: Mapped[dict] = mapped_column(JSON)   # e.g. {"bert": "fallback:heuristic"}

class TimelineCurve(Base):
    __tablename__ = "timeline_curves"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("risk_runs.id"))
    algorithm: Mapped[str]               # canonical name, e.g. "RSA-2048"
    params_hash: Mapped[str]             # cache key (curve reused across runs if hash equal)
    years: Mapped[list[int]] = mapped_column(JSON)      # [2026..2100]
    cdf: Mapped[list[float]] = mapped_column(JSON)      # F_a(T), same length
    cdf_stderr: Mapped[list[float]] = mapped_column(JSON)
    median_year: Mapped[float | None]    # null if F(2100) < 0.5
    p05_year: Mapped[float | None]
    p95_year: Mapped[float | None]
    n_trials: Mapped[int]

class RiskExplanation(Base):
    __tablename__ = "risk_explanations"
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("crypto_assets.id"), primary_key=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("risk_runs.id"), primary_key=True)
    p_hndl_bn: Mapped[float]             # raw BN output before regressor
    p_too_late: Mapped[float]            # F_a(now + X_p90 + Y)  (§6.5)
    bn_factors: Mapped[dict] = mapped_column(JSON)      # per-node evidence + posteriors
    shap_top: Mapped[list] = mapped_column(JSON)        # [(feature, contribution)] top 8
    classifier: Mapped[dict] = mapped_column(JSON)      # {"method": "bert|heuristic", "probs": {...},
                                                        #  "trace": [...matched rules or top tokens...]}
    score_source: Mapped[str]            # xgb | bn-fallback | static-fallback
```

### 4.3 Pydantic API schemas (in `qubit_risk/api.py`, mirrored to dashboard TS types)

```python
class TimelineCurveOut(BaseModel):
    algorithm: str
    years: list[int]
    cdf: list[float]
    cdf_stderr: list[float]
    median_year: float | None
    p05_year: float | None
    p95_year: float | None
    params_hash: str

class AssetRiskOut(BaseModel):
    asset_id: UUID
    algorithm: str
    sensitivity: SensitivityClass          # enum from qubit-core
    shelf_life_years: float | None
    score: float
    ci_low: float
    ci_high: float
    mosca_margin_years: float
    p_too_late: float
    priority_rank: int
    explanation: ExplanationOut | None     # included when ?explain=true

class AssessRequest(BaseModel):
    asset_ids: list[UUID] | None = None    # None ⇒ all assets in registry
    force_retimeline: bool = False         # ignore cached curves
    seed: int | None = None

class SimulateRequest(BaseModel):          # dashboard what-if sliders
    qubit_growth_rate_mean: float | None = None      # overrides hardware_priors.yaml
    error_rate_improvement_mean: float | None = None
    survey_weight: float | None = Field(None, ge=0, le=1)
    algorithms: list[str] = ["RSA-2048", "ECDSA-P256"]
    n_trials: int = Field(2000, le=20000)
```

### 4.4 Params files (field-level, with real defaults)

`params/hardware_priors.yaml`:

```yaml
version: 1
reference_year: 2026
horizon_year: 2100
n_trials: 10000
seed: 42
survey_weight: 0.5            # w in F = w·F_hw + (1−w)·F_survey
physical_qubits_now:          # Q0 ~ LogNormal
  dist: lognormal
  mu_ln: 8.29                 # ln(4000) — frontier device scale, 2026
  sigma_ln: 0.5
qubit_growth_rate:            # g in Q(t) = Q0·exp(g·(t−t0)); g=0.47 ⇒ ×1.6/yr
  dist: truncnorm
  mu: 0.47
  sigma: 0.15
  low: 0.10
  high: 1.10
error_rate_now:               # p0 ~ LogNormal, two-qubit gate error
  dist: lognormal
  mu_ln: -5.81                # ln(3e-3)
  sigma_ln: 0.35
error_improvement_rate:       # r in p(t) = p0·exp(−r·(t−t0))
  dist: truncnorm
  mu: 0.10
  sigma: 0.05
  low: 0.0
  high: 0.4
architecture_efficiency:      # η multiplies baseline resource estimates
  dist: loguniform            # captures GE2019 → Gidney-2025-style reductions
  low: 0.05
  high: 1.0
attack_window_days: 30        # HNDL adversary patience T_max
surface_code:
  A: 0.1
  p_threshold: 0.01
  eps_fail: 0.05              # total tolerated logical failure prob per run
  routing_overhead: 2.0       # physical qubits per logical = overhead · d²
  factory_overhead:           # γ: extra fraction for magic-state factories
    dist: uniform
    low: 0.2
    high: 0.5
  t_cycle_us: {dist: loguniform, low: 0.1, high: 10.0}
  t_reaction_us: {dist: loguniform, low: 1.0, high: 100.0}
```

`params/resource_estimates.yaml` (values seeded from literature; an M1 task re-derives each from the cited paper and records the derivation in the file — uncertainty is expressed as a sampled range, not false precision):

```yaml
version: 1
# Q_L: logical qubits. N_tof: Toffoli count. Ranges span published estimates;
# simulator samples N_tof ~ LogUniform(low, high) per trial.
algorithms:
  RSA-2048:   {attack: shor, Q_L: 6200,  N_tof: {low: 1.3e9, high: 5.4e9},  source: "Gidney-Ekerå 2019; Gidney 2025 (arXiv:2505.15917)"}
  RSA-3072:   {attack: shor, Q_L: 9300,  N_tof: {low: 5.0e9, high: 2.0e10}, source: "GE2019 n^3 scaling"}
  RSA-4096:   {attack: shor, Q_L: 12400, N_tof: {low: 1.2e10, high: 4.6e10}, source: "GE2019 scaling"}
  DH-2048:    {alias: RSA-2048, note: "dlog mod p ≈ factoring cost at same size"}
  ECDSA-P256: {attack: shor, Q_L: 2400,  N_tof: {low: 5.0e7, high: 1.3e9},  source: "Häner+ 2020; Litinski 2023; Webber+ 2022 anchors"}
  ECDH-P256:  {alias: ECDSA-P256}
  X25519:     {alias: ECDSA-P256, note: "≈256-bit ECDLP"}
  ECDSA-P384: {attack: shor, Q_L: 3450,  N_tof: {low: 1.7e8, high: 4.4e9},  source: "n^3 scaling from P256"}
grover_tier:                  # no CDF — tier treatment, §6.1.6
  AES-128:  {attack: grover, tier: marginal,   note: "~2^64 serial oracle calls; depth-limited beyond horizon"}
  3DES-112: {attack: grover, tier: marginal-plus-classical-weak}
  AES-256:  {attack: none,   tier: safe}
  SHA-256:  {attack: none,   tier: safe}       # Grover preimage impractical
pqc_safe: [ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA, X25519MLKEM768]
calibration_anchors:          # unit tests assert model reproduces these within ×2 (§8)
  # the anchor harness PINS eta: 1.0 and gamma: 0.35 (fixed, not sampled) so the
  # assertion is well-defined — the 1h anchor sits in the parallelization-sensitive regime
  - {alg: ECDSA-P256, t_cycle_us: 1.0, t_reaction_us: 10.0, p: 1.0e-3, window: 1h,  eta: 1.0, gamma: 0.35, expect_Q_P: 3.17e8, source: "Webber+ 2022"}
  - {alg: ECDSA-P256, t_cycle_us: 1.0, t_reaction_us: 10.0, p: 1.0e-3, window: 24h, eta: 1.0, gamma: 0.35, expect_Q_P: 1.3e7,  source: "Webber+ 2022"}
  - {alg: RSA-2048,   t_cycle_us: 1.0, t_reaction_us: 10.0, p: 1.0e-3, window: 8h,  eta: 1.0, gamma: 0.35, expect_Q_P: 2.0e7,  source: "Gidney-Ekerå 2019"}
```

`params/expert_survey.yaml` (Global Risk Institute *Quantum Threat Timeline Report 2025*, 26-expert aggregate — anchor points to fit the survey CDF; re-check against the published cumulative table during M1):

```yaml
version: 1
source: "GRI Quantum Threat Timeline Report 2025 (evolutionQ), 26 experts"
reference_algorithm: RSA-2048       # survey asks about breaking RSA-2048 in 24h
reference_year: 2025
anchors:                            # P(CRQC within N years), aggregate midpoints
  - {years: 5,  p_low: 0.05, p_high: 0.15, interpolated: true}   # NOT a GRI headline number
  - {years: 10, p_low: 0.28, p_high: 0.49}   # published headline range
  - {years: 15, p_low: 0.51, p_high: 0.70}   # published headline range
  - {years: 20, p_low: 0.65, p_high: 0.85}   # 92% of experts ≥50% at 20y (headline-adjacent)
  - {years: 30, p_low: 0.80, p_high: 0.95, interpolated: true}   # NOT a GRI headline number
# interpolated anchors are team extrapolations for fit stability; the fit is
# re-checked against the published cumulative table during M1 and the paper's
# sensitivity analysis sweeps them
fit: lognormal                      # F_survey(t) fitted to anchor midpoints, §6.1.4
```

`params/shelf_life_priors.yaml`:

```yaml
version: 1
# L ~ LogNormal(mu_ln, sigma_ln) years, per sensitivity class.
# Rationale documented per row; sensitivity-analyzed in the paper.
classes:
  phi:        {mu_ln: 3.40, sigma_ln: 0.30, note: "≈30y median; HIPAA retention + patient lifetime"}
  pii:        {mu_ln: 3.00, sigma_ln: 0.40, note: "≈20y; identity data outlives breach cycles"}
  ip:         {mu_ln: 2.71, sigma_ln: 0.50, note: "≈15y; trade-secret horizon"}
  financial:  {mu_ln: 2.30, sigma_ln: 0.40, note: "≈10y; PCI/regulatory + fraud value decay"}
  credentials:{mu_ln: 0.00, sigma_ln: 0.50, note: "≈1y; rotation assumed"}
  ephemeral:  {mu_ln: -2.30, sigma_ln: 0.50, note: "≈0.1y; session tokens"}
  public:     {fixed: 0.0}
  unknown:    {dist: loguniform, low: 1.0, high: 25.0, note: "deliberately broad"}
```

`params/sensitivity_rules.yaml` (heuristic classifier — excerpt with real rules):

```yaml
version: 1
score_threshold: 1.0        # min accumulated weight to assign a class (else unknown)
# `where` values are limited to what the evidence contract actually provides:
# identifier | comment | file_path (all derived from evidence.snippet + location).
# Endpoint-scoped rules were deliberately downgraded to file_path heuristics —
# no subsystem produces route-to-crypto-call mappings.
rules:
  - {class: pii,        weight: 1.0, where: [identifier],           regex: '(?i)\b(ssn|social_sec|aadhaar|passport(_no)?|national_id|dob|date_of_birth|driver_?licen[cs]e)\b'}
  - {class: pii,        weight: 0.6, where: [identifier, comment],  regex: '(?i)\b(email|phone|address|first_?name|last_?name|customer)\b'}
  - {class: phi,        weight: 1.0, where: [identifier, comment],  regex: '(?i)\b(patient|diagnos(is|tic)|icd10|hl7|fhir|medical_record|mrn|prescription|ehr|phi)\b'}
  - {class: financial,  weight: 1.0, where: [identifier, file_path],regex: '(?i)\b(card_?(number|num|no)|pan\b|cvv|iban|swift|account_balance|txn|payment|invoice|payroll|billing)\b'}
  - {class: credentials,weight: 1.0, where: [identifier],           regex: '(?i)\b(passw(or)?d|secret_?key|api_?key|bearer|jwt|refresh_token|private_?key)\b'}
  - {class: ip,         weight: 0.8, where: [comment, file_path],   regex: '(?i)\b(proprietary|confidential|trade\s?secret|internal[-_ ]only|patent)\b'}
  - {class: ephemeral,  weight: 0.8, where: [identifier],           regex: '(?i)\b(session_?(id|token)|nonce|csrf|cache_key|otp)\b'}
  - {class: public,     weight: 0.8, where: [file_path],            regex: '(?i)(/public/|/static/|sitemap|robots\.txt|healthz)'}
tie_break_order: [phi, financial, pii, credentials, ip, ephemeral, public]   # highest-stakes wins ties
```

`params/bn_cpds.yaml`:

```yaml
version: 1
crqc_bins:  [2030, 2035, 2040, 2050, 2070]     # bin edges → 6 states: ≤2030 … >2070
shelf_bins: [1, 5, 15, 30]                     # 5 states: <1y … >30y
exposure_map:                                  # derived from asset fields, §6.2.2
  network: {source_scanner: [network], usage_context: [tls, kex]}
  at_rest: {usage_context: [encryption-at-rest, token, password]}
  offline: {source_scanner: [cert, key], protocol_detail: null}   # key material on disk, no network context
  default: at_rest
harvest_cpd:            # P(Harvested=yes | Exposure, SensTier). EXPERT-ELICITED (documented in paper §threats)
  network:  {high: 0.80, low: 0.40}
  at_rest:  {high: 0.30, low: 0.10}
  offline:  {high: 0.05, low: 0.02}
sens_tier: {high: [phi, pii, financial, ip, credentials], low: [ephemeral, public, unknown]}
```

---

## 5. Public interfaces

### 5.1 CLI (`qubit risk …`, Typer sub-app registered by qubit-cli)

```
qubit risk fetch-models                  # download distilbert base + fine-tuned weights into cache
qubit risk timeline [--algorithm RSA-2048] [--trials 10000] [--seed 42] [--json|--csv|--plot out.html]
qubit risk assess [--scan-id ID | --asset-id ID ...] [--all] [--force-retimeline] [--seed 42]
qubit risk explain <asset-id>            # human-readable: score, CI, Mosca, BN factors, SHAP, classifier trace
qubit risk mosca [--format table|json]   # margin table for whole inventory
qubit risk simulate --set qubit_growth_rate.mu=0.6 --set survey_weight=0.3   # what-if, prints curve deltas
qubit risk train xgb  [--n-synthetic 50000] [--out models/risk-xgb.ubj]      # §6.4
qubit risk train bert [--corpus data/sens-corpus/] [--epochs 3]              # §6.3
qubit risk eval  [--component bert|xgb|bn|timeline]                          # paper-experiment harness
```

Exit codes: 0 ok; 3 partial (degradations occurred — listed on stderr); 4 params invalid; 5 DB unavailable.

### 5.2 Python API (what other code in-package and notebooks use)

```python
from qubit_risk import RiskPipeline, RiskConfig
from qubit_risk.timeline import CRQCTimelineSimulator
from qubit_risk.bn import HndlBayesNet
from qubit_risk.sensitivity import classify_sensitivity
from qubit_risk.mosca import mosca_margin

cfg = RiskConfig.load()                                    # reads params/*.yaml, computes params_hash

sim = CRQCTimelineSimulator(cfg)
curve = sim.simulate("RSA-2048")                           # -> TimelineCurveResult(years, cdf, stderr, ...)
curves = sim.simulate_all()                                # dict[str, TimelineCurveResult], cached by hash

res = classify_sensitivity(asset, cfg, model=None)         # -> SensitivityResult(cls, probs, shelf_prior, method, trace)

bn = HndlBayesNet(cfg, curves)
p = bn.p_hndl(asset, sens=res)                             # -> float, plus bn.last_factors for explanation

pipe = RiskPipeline(cfg, session_factory)                  # SQLAlchemy session factory from qubit-core
run = pipe.assess(asset_ids=None, seed=42)                 # annotates DB, returns RiskRun
```

Key signatures (implementation contracts):

```python
class CRQCTimelineSimulator:
    def __init__(self, cfg: RiskConfig, rng: np.random.Generator | None = None): ...
    def simulate(self, algorithm: str, n_trials: int | None = None) -> TimelineCurveResult: ...
    def simulate_all(self, algorithms: Sequence[str] | None = None) -> dict[str, TimelineCurveResult]: ...

def required_physical_qubits(Q_L: int, N_tof: float, p: float, *, sc: SurfaceCodeParams,
                             window_s: float, eta: float, gamma: float) -> float: ...
def break_year(trial: HardwareTrial, req: ResourceEstimate, cfg: RiskConfig) -> float | None: ...

def classify_sensitivity(asset: CryptoAsset, cfg: RiskConfig,
                         model: BertClassifier | None) -> SensitivityResult: ...

class RiskRegressor:
    @classmethod
    def load(cls, path: Path) -> "RiskRegressor": ...
    def predict(self, X: np.ndarray) -> RiskPrediction:   # .score, .ci_low, .ci_high, .shap_top
    def is_available(self) -> bool: ...

def mosca_margin(curve: TimelineCurveResult, shelf_p90: float, migration_years: float,
                 *, z_percentile: float = 0.5) -> MoscaResult: ...
```

### 5.3 REST endpoints (exposed: `qubit_risk.api.router`, mounted by qubit-api at `/api/v1/risk`)

| Method & path | Body / params | Returns | Notes |
|---|---|---|---|
| `POST /api/v1/risk/assess` | `AssessRequest` | `202 {run_id}` | FastAPI background task; progress via `GET /runs/{id}` |
| `GET /api/v1/risk/runs/{run_id}` | — | `RiskRun` status + degradations | dashboard polls |
| `GET /api/v1/risk/timeline` | `?algorithm=RSA-2048` (repeatable) | `list[TimelineCurveOut]` | cached curves; the dashboard CDF plot |
| `GET /api/v1/risk/assets/{id}` | `?explain=true` | `AssetRiskOut` | single-asset drill-down |
| `GET /api/v1/risk/assets` | `?min_score=&sensitivity=&sort=priority_rank&limit=&offset=` | paged `list[AssetRiskOut]` | migration-queue view |
| `GET /api/v1/risk/summary` | — | histogram of scores, counts per sensitivity/tier, worst-10, % assets with negative Mosca margin | posture widget |
| `GET /api/v1/risk/mosca` | — | per-asset `{asset_id, X_p90, Y, Z_med, margin, p_too_late}` | Mosca table |
| `POST /api/v1/risk/simulate` | `SimulateRequest` | `list[TimelineCurveOut]` | what-if sliders; **never** persisted, capped trials. **M3 stretch — first cut-line in the normative API registry (doc 05)** |

Consumed by us: none over REST (we read assets via the DB per the frame's data flow). Consumed by others: dashboard (all GETs), `qubit-migrate` (DB `risk.priority_rank`), CBOM exporter in qubit-core (reads risk fields off the asset rows).

---

## 6. Key algorithms & flows

### 6.1 Monte Carlo CRQC timeline simulator

**Idea:** sample plausible worlds (hardware trajectory + resource-estimate uncertainty), compute the first year each world can break algorithm *a* within the attack window, and report the empirical CDF — then blend with the expert-survey CDF so the absolute anchor comes from the 26-expert GRI aggregate while the *relative* difficulty between algorithms comes from physics.

**6.1.1 Surface-code footprint (per trial).** Logical error per logical qubit per code cycle at distance *d*:

```
p_L(d) = A · (p / p_th)^((d+1)/2)          A = 0.1, p_th = 10⁻²
```

Total code cycles for the computation (reaction-limited lattice surgery, first-order Webber-style model):

```
N_cycles = N_tof · d                        (measurement-depth-limited serial estimate)
```

Choose the smallest odd *d* such that the whole run succeeds with probability ≥ 1 − ε:

```
Q_L · N_cycles · p_L(d) ≤ ε_fail            (ε_fail = 0.05)
```

Physical qubit requirement and wall time:

```
Q_P = routing_overhead · Q_L · d² · (1 + γ) · η
T_wall = max(N_tof · d · t_cycle,  N_tof · t_reaction)
```

`η` (architecture efficiency, LogUniform[0.05, 1]) captures post-2019 improvements (windowed arithmetic → Gidney 2025's sub-million-qubit RSA-2048 estimate) without pretending we know which architecture wins.

**Parallelization respects the reaction limit** (Webber et al.'s central result: adding qubits accelerates only up to the reaction-limited rate — the `N_tof · t_reaction` term is a *serial-depth floor* that cannot be bought down with qubits):

```
if N_tof · t_reaction > attack_window:
    trial fails for algorithm a this year — no parallelization escape
else:
    k = min(100, ceil((N_tof · d · t_cycle) / attack_window))   # compress ONLY the cycle-limited term
    Q_P ← Q_P · k
    T_wall = max(N_tof · d · t_cycle / k,  N_tof · t_reaction)
```

**6.1.2 Hardware trajectory (per trial).** Draw `(Q0, g, p0, r, t_cycle, t_reaction, η, γ)` from `hardware_priors.yaml`, then:

```
Q_avail(t) = Q0 · exp(g · (t − 2026))
p(t)       = max(1e-5, p0 · exp(−r · (t − 2026)))
```

**6.1.3 Break year.**

```
def break_year(trial, req, cfg) -> float | None:
    for t in range(2026, 2101):
        d  = min_distance(req.Q_L, sampled_N_tof, trial.p(t), cfg.sc)
        Qp = required_physical_qubits(... at p(t), window=cfg.window ...)
        if trial.Q_avail(t) >= Qp:
            return t
    return None            # no break by 2100 in this world
```

Empirical hardware CDF: `F_hw_a(T) = (1/N) Σ 1[break_year_i ≤ T]`. Monte Carlo standard error: `se(T) = sqrt(F(1−F)/N)` — reported per point and drawn as a band on the dashboard. N = 10,000 trials ⇒ se ≤ 0.005; runs in seconds (vectorized numpy over the year grid).

**6.1.4 Survey CDF.** Fit LogNormal `F_survey(t; μ, σ)` to the GRI-2025 anchor midpoints by least squares on `(years_i, p_i)`; the survey's low/high anchor bounds give two more fits used as an uncertainty band. The survey references **RSA-2048-in-24h** — therefore all hardware CDFs used for blending and anchoring are computed at a matched `attack_window = 24 h` (the risk-scenario default of 30 days in `hardware_priors.yaml` applies only to the standalone risk curves, never to the blend — mixing the two event definitions would systematically shift the hardware curve earlier than the surveyed event).

**6.1.5 Blending + algorithm offsets.**

```
F_RSA2048(T)  = w · F_hw_RSA2048@24h(T) + (1−w) · F_survey(T − 2025)      w = 0.5 default
Δ(a)          = q25(F_hw_a@24h) − q25(F_hw_RSA2048@24h)                   # physics-derived offset
                # q25 = first year with F ≥ 0.25 — guaranteed to exist for every curve we blend
                # (fallback: if F_a(2100) < 0.25, Δ(a) = horizon offset and the curve is
                #  flagged beyond_horizon — same flag as F8)
F_a(T)        = w · F_hw_a@24h(T) + (1−w) · F_survey(T − 2025 − Δ(a))
```

So ECDSA-P256 (cheaper to break) lands *earlier* than RSA-2048 by exactly the amount the hardware model says, while the absolute calibration leans on the expert aggregate. `w` is a dashboard slider (`/simulate`) and a paper sensitivity axis.

**6.1.6 Grover / symmetric tier.** No CDF is produced. Grover on AES-128 needs ≈2⁶⁴ *serial* oracle iterations; at optimistic 100 ns effective iteration time that is > 5×10⁴ years of serial depth — parallelization only helps by √machines. Following NIST's own guidance we classify: `AES-128/3DES → tier "marginal"` (contributes a fixed feature value to the regressor, and 3DES is additionally flagged classically weak by the scanner), `AES-256/SHA-256 → "safe"`, PQC algorithms → `"safe"`. This is documented user-facing text, not a hidden zero.

### 6.2 Bayesian network (pgmpy)

**6.2.1 Structure** (5 nodes + target = 6 total; matches `bn_cpds.yaml` and the closed form exactly — no intermediate `HarvestLikelihood` node):

```
Exposure ──►┐
SensTier ──►│ Harvested ──────────────────────┐
            │                                 ├──► DecryptedBeforeObsolete
ShelfLife ──┼─────────────────────────────────┤
CRQCArrival ┴─────────────────────────────────┘
```

- `CRQCArrival`: 6 states from `crqc_bins`; CPD = per-algorithm probability mass in each bin, read directly off `F_a(T)` (this is how the MC plugs into the BN — the CPD is rebuilt per algorithm, cheap because the net is tiny).
- `ShelfLife`: 5 states; CPD = mass of the class shelf-life LogNormal in each `shelf_bins` bin (mixture over class probabilities when the classifier is uncertain).
- `Exposure` (network / at_rest / offline): deterministic evidence derived from `source_scanner` + `usage_context` via `exposure_map` (`offline` = `source_scanner ∈ {cert, key}` with no `protocol_detail` — key material found on disk with no observed network context).
- `Harvested | Exposure, SensTier`: **directly** the scalar `P(Harvested=yes | Exposure, SensTier)` from `harvest_cpd` (expert-elicited, YAML, sensitivity-analyzed in the paper — we do not pretend these are learned). This matches the YAML's documented semantics and the closed form, so the BN ≡ integral CI gate (§8.1.4) is achievable by construction.
- `DecryptedBeforeObsolete | Harvested, CRQCArrival, ShelfLife`: deterministic comparison CPD — state `yes` iff `Harvested=yes ∧ midpoint(CRQCArrival bin) ≤ now + midpoint(ShelfLife bin)`, with fractional credit for partially overlapping bins (overlap fraction computed once from the continuous distributions).

**6.2.2 The quantity it computes.** Continuous form (also implemented directly as the closed-form fallback, and used to generate regressor labels):

```
P_HNDL = P(H=1 | E, S) · ∫₀^∞ f_L(ℓ) · F_a(t_now + ℓ) dℓ
```

i.e. probability the asset is harvested × probability CRQC arrives while the data still matters, marginalized over shelf-life uncertainty. The integral is evaluated by 512-point Gauss-Legendre over the LogNormal support (`scipy`). The BN discretization agrees with the integral to <0.02 absolute (unit-tested); the BN exists because (i) it makes the factorization explicit and explainable in the dashboard/paper, (ii) it lets users override any CPD.

**6.2.3 Implementation.**

```python
from pgmpy.models import DiscreteBayesianNetwork          # pgmpy ≥1.0 name!
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

class HndlBayesNet:
    def __init__(self, cfg, curves): ...
    def p_hndl(self, asset, sens: SensitivityResult) -> float:
        model = self._model_for(asset.algorithm)          # swaps CRQCArrival CPD, cached per algorithm
        inf = VariableElimination(model)
        q = inf.query(["DecryptedBeforeObsolete"],
                      evidence={"Exposure": self._exposure(asset)},
                      virtual_evidence=[self._shelf_soft_evidence(sens)])
        self.last_factors = self._collect_factors(inf)    # for RiskExplanation.bn_factors
        return float(q.values[1])
```

### 6.3 Data-sensitivity classifier

**6.3.1 Context window construction** (shared by both tiers). **Producer contract (agreed with 01-discovery-inventory §4.3):** the scanner guarantees `evidence.snippet` = ±5 lines around the finding plus `location{file_path, line}` — nothing more. qubit-risk tokenizes identifiers and comments *from the snippet itself* (cheap regex pass: identifier tokens, comment lines); there is no enclosing-function or REST-endpoint extraction anywhere in the pipeline (route-to-crypto-call attribution is a nontrivial static analysis explicitly out of scope for v1). The window is:

```
"path: src/billing/payments.py | ids: card_number, cvv_cache, stripe_txn
 | comments: store PAN for recurring billing | code: <±5-line snippet>"
```

truncated to 256 DistilBERT tokens. Network/cert assets (no code context) use SNI/hostname/service/port + cert subject fields; if that's all we have, confidence is capped and `unknown` is likely — by design.

**BERT invocation gating + dedup (FR6):** context windows are content-hashed; each unique window is classified at most once per run (LRU-cached across runs keyed by params hash). The heuristic tier runs first on every asset; BERT is invoked only where the heuristic **abstains** (`max weight < score_threshold`) **or two classes tie/conflict**. Typical inventories see >80% cache/abstention savings.

**6.3.2 Tier 1 — heuristic (always on, transparent).** Apply `sensitivity_rules.yaml`: each matching rule adds `weight` to its class; class = argmax if `max ≥ score_threshold`, else `unknown`; ties broken by `tie_break_order`. Output includes the matched-rule trace verbatim (this *is* the explanation). ~50 rules at ship; adding a rule is a YAML edit + fixture test.

**6.3.3 Tier 2 — DistilBERT.** `AutoModelForSequenceClassification` head over 7 classes (all but `unknown`). Accept the BERT label iff `max softmax ≥ 0.55` **and** it doesn't contradict a weight-≥1.0 heuristic hit (contradiction ⇒ take the heuristic, flag disagreement in trace — safer and paper-analyzable). Otherwise fall back to Tier 1. `unknown` is never predicted; it's the abstention outcome.

**6.3.4 Training data — the honest plan.** There is no public labeled corpus of "code context around crypto call → data sensitivity". We build one, and we say exactly how in the paper:

1. **Template synthesis (~12k examples):** per-class identifier/comment/endpoint vocabularies (≈80 stems/class) × code templates in Python/Java/Go/JS (≈40 templates) with distractor noise; labels are true by construction.
2. **Weak-labeled real code (~8k examples):** scan permissively-licensed GitHub repos that use crypto APIs (harvest via `qubit-scanner` itself on a curated repo list — dual use as a scanner test). Weak label = heuristic ruleset ∧ local-LLM zero-shot label (Ollama, `qwen2.5-coder:7b`, fixed prompt, temperature 0). Agreement examples become weak labels.
3. **The disagreement queue is the valuable training data, not discard** — where heuristic and LLM *disagree* is exactly where the rules fail and a model has headroom. Training only on agreements would teach BERT to imitate the heuristic (structural circularity making any "beats heuristic" gate unpassable on real code). Both team members **human-adjudicate the disagreement queue** (~1.5–2k examples at ~15 s each ≈ 2 × 4 h sessions) and those adjudicated examples are *included in training* with 3× sample weight.
4. **Human-verified evaluation set (600 examples, never trained on):** stratified sample of real-code contexts — **stratified to over-sample the disagreement region** (the stratum where the model must prove itself) — labeled independently by both team members; disagreements adjudicated with the guide; report Cohen's κ in the paper (target κ ≥ 0.7; if lower, the label taxonomy gets simplified before we trust any model).
5. Fine-tune: 3 epochs, lr 2e-5, batch 16, weighted cross-entropy (class imbalance), 10% templates held out for early stopping. Runs in <1 h on a free Colab T4 or overnight on CPU; the checkpoint is committed to a HF Hub repo under the project org and fetched by `fetch-models` (sha256-pinned, §3).

**Acceptance for shipping the BERT tier at all:** macro-F1 ≥ heuristic baseline **+ 5 points on the full human-verified set AND ≥ heuristic on the disagreement stratum specifically, with a per-class breakdown reported** (the +10-overall gate was structurally unpassable when training excluded disagreements); otherwise M2 ships heuristic-only (cut-line C3) and the paper reports the negative result honestly. **Ship/no-ship decision date: Oct 15, 2026** (hard calendar gate, not "end of M2").

**6.3.5 Shelf-life prior.** `class → LogNormal(μ,σ)` from `shelf_life_priors.yaml`. `shelf_life_years` on the asset = E[L] = exp(μ+σ²/2). The BN/labeler use the full distribution; Mosca uses P90.

### 6.4 XGBoost risk regressor + confidence intervals

**6.4.1 What it is for (honest framing).** True HNDL outcomes are unobservable until a CRQC exists — there is no ground-truth label set, and we say so. The regressor is therefore a **distillation + fusion layer**, not an oracle: it (i) distills the full MC+BN pipeline into a millisecond scorer with smooth behavior across the whole feature space, (ii) fuses in features the BN doesn't model (protocol version, cert expiry, deprecated library flags), and (iii) carries the uncertainty machinery (conformal CIs). Its validation is *rank agreement with human expert judgment*, not label accuracy — the only defensible standard for this problem.

**6.4.2 Feature vector (34 dims — 10+1+1+3+1+7+2+3+1+3+2, the spec contract for `features.py`, model files, and golden tests):**

```
alg_family one-hot (10) · log2(key_size) · attack{none,grover,shor}→{0,1,2}
p_crqc_2030 · p_crqc_2035 · p_crqc_2040 · break_year_median (per-asset algorithm curve)
sens_probs (7) · shelf_life_mean · shelf_life_p90
exposure one-hot (3) · usage_context ordinal
tls_lt_1_3 flag · cert_expired flag · deprecated_lib flag
bn_p_hndl · harvest_prob
```

Missing values: explicit sentinel (-1) — XGBoost handles natively; `unknown` sensitivity contributes its broad prior, never a silent zero.

**6.4.3 Training data (exact recipe, `regressor/labels.py`):**

1. Sample **N = 50,000 synthetic assets** by stratified draws over the priors: algorithm ~ realistic inventory frequencies (from demo-lab + published CBOM stats), sensitivity ~ Dirichlet-perturbed class mix, exposure/usage ~ conditional tables, flags ~ Bernoulli.
2. For each synthetic asset, run the *continuous* pipeline (closed-form §6.2.2) **K = 200 times**, each with a fresh draw of MC hardware parameters and CPD perturbations (harvest CPD entries jittered ±0.1 truncated-normal — this encodes our stated uncertainty in the expert-elicited numbers). Rule-based adjustments inject the extra features (e.g., `tls_lt_1_3 ⇒ harvest_prob × 1.15` clipped — rules listed in `labels.py`, reviewed by guide).
3. Targets: `y = median_k P_HNDL` for the primary model. The per-asset draw quantiles `y_05, y_95` are retained in the dataset **only for the CQR stretch path (C2)**, which — if ever built — fits quantile models on the *expanded per-draw labels* (each asset contributing its K draws), not on medians.
4. Split 70/15/15 train/calibration/test, stratified by algorithm family.

This makes the regressor a *calibrated surrogate of the probabilistic model under parameter uncertainty* — circularity is avoided because (a) the label integrates over parameter draws the online BN doesn't, (b) features beyond the BN's inputs shift labels via reviewed rules, and (c) external validation is human ranking (below), not the teacher.

**6.4.4 Model + CI (primary path: plain median regressor + split conformal — no multi-quantile):**

```python
booster = xgb.XGBRegressor(
    objective="reg:squarederror",
    tree_method="hist", n_estimators=600, max_depth=6, learning_rate=0.05,
    min_child_weight=10, subsample=0.9, random_state=42)
booster.fit(X_train, y_train)                       # y = median teacher labels (§6.4.3)
y_hat = booster.predict(X)
```

Then **split-conformal calibration** (MAPIE v1 `SplitConformalRegressor`, or the 15-line manual equivalent to avoid API drift): conformity scores on the calibration set `s_i = |y_i − ŷ(x_i)|`, `q̂ = quantile_{⌈(n+1)(1−α)⌉/n}(s)` with α = 0.10. Reported interval:

```
ci = [clip(ŷ − q̂, 0, 1), clip(ŷ + q̂, 0, 1)]      # guaranteed ≥90% marginal coverage
```

*Why no multi-quantile primary:* fitting `reg:quantileerror` heads on **median-only labels** would make q05/q95 learn the cross-asset spread of the median — not the label's epistemic spread — i.e. meaningless quantiles; and intersecting those with the conformal band destroys the coverage guarantee. The adaptive-width upgrade is strictly the **CQR stretch (cut-line C2)**: Conformalized Quantile Regression fitted on the *expanded per-draw labels* (§6.4.3 step 3), never on medians.

Split conformal gives the finite-sample marginal coverage guarantee `P(y ∈ CI) ≥ 1−α` assuming exchangeability with the calibration set — stated with that caveat in the paper. Empirical coverage on the test fold is a CI-gated test (§8). `score = ŷ`; `score_source = "xgb"`.

**6.4.5 External validation (paper experiment, M3):** both members + guide independently rank 40 real assets from the demo-lab scan (pairwise comparisons → Bradley-Terry consensus). Report Spearman ρ between XGBoost scores and human consensus, against baselines: (i) heuristic static table, (ii) BN-only, (iii) CVSS-style checklist. Target ρ ≥ 0.7 and beating baselines — this is the headline evaluation of the engine.

**6.4.6 Explanation:** `booster.get_booster().predict(dmat, pred_contribs=True)` (built-in TreeSHAP, no extra dependency) → top-8 contributions stored in `RiskExplanation.shap_top`.

### 6.5 Mosca calculator

Per asset (all inputs already computed):

```
X = shelf-life P90 (class prior)                    # conservative on secrecy need
Y = migration.effort_estimate (years) if set by qubit-migrate,
    else default table: {code-change: 0.25, protocol/tls: 0.5, cert: 0.1, library-upgrade: 0.5,
                         hsm/key-ceremony: 1.0} + org_overhead (default 0.5y, config)
Z = F_a⁻¹(0.5)   (median CRQC year − now); Z_conservative = F_a⁻¹(0.05) − now

mosca_margin_years = Z − (X + Y)
p_too_late         = F_a(t_now + X + Y)             # prob. migration finishes after the break
```

Both stored (`margin` on the asset per shared schema; `p_too_late` in `RiskExplanation`). Negative margin renders red in the dashboard; `p_too_late` is the more nuanced number the paper argues for.

### 6.6 End-to-end batch flow (`pipeline.assess`)

```
1. create RiskRun(params_hash, seed); load assets (all or ids) via qubit-core session
2. curves = simulator.simulate_all(distinct vulnerable algorithms)      # cache hit if hash unchanged
3. for each asset (batched):
     a. sens = classify_sensitivity(asset)            # BERT batch-32 → heuristic fallback per §6.3
     b. write asset.sensitivity, asset.shelf_life_years
     c. p_hndl = bn.p_hndl(asset, sens)               # or closed form if pgmpy degraded
     d. x = features(asset, sens, curves);  pred = regressor.predict(x)
     e. mosca = mosca_margin(curves[alg], sens.shelf_p90, effort(asset))
     f. asset.risk = {score, ci_low, ci_high, mosca_margin_years, priority_rank: None}
     g. insert RiskExplanation row
4. priority_rank = dense rank by (score desc, p_too_late desc, ci_width asc); write back
5. non-vulnerable assets (attack == none / pqc_safe): score=0.0, ci=[0,0], rank after all
   vulnerable assets, sensitivity still classified (inventory value); skip BN/regressor
6. finalize RiskRun(status, degradations); emit summary
```

Commits are chunked (500 assets/transaction) so a crash leaves a resumable partial run.

---

## 7. Failure modes & handling

| # | Failure | Detection | Handling | User-visible |
|---|---|---|---|---|
| F1 | DistilBERT weights absent / torch import fails / OOM | import & load probe at pipeline start | heuristic-only classification | run flagged `degradations.bert`, exit 3, docs point to `fetch-models` |
| F2 | pgmpy inference error (CPD mismatch after params edit) | exception per asset | closed-form integral fallback (§6.2.2) — same number, less explanation | `degradations.bn`; BN factor panel hidden |
| F3 | XGBoost model file missing/corrupt | UBJSON load fails | `score = p_hndl_bn`, `ci = [max(0,s−0.2), min(1,s+0.2)]`, `score_source="bn-fallback"` | wide CIs; dashboard badge "uncalibrated" |
| F4 | Unknown algorithm string (scanner found something not in registry) | lookup miss | map via qubit-core canonicalizer; if still unknown: `quantum_vulnerable` unchanged, score from most-conservative family (RSA-2048 curve), flag `assumed_worst_case` | explanation states the assumption |
| F5 | Asset lacks code context (network/cert scanners) | empty context window | classifier runs on host/cert fields only; confidence capped ⇒ usually `unknown` + broad shelf prior | wider CI, honest `unknown` |
| F6 | Params YAML invalid / bin edges non-monotone | pydantic validation at `RiskConfig.load()` | refuse to run (exit 4) with field-level error | error message names file+field |
| F7 | Quantile crossing (q05 > q50 etc.) — **CQR stretch path only** | post-predict check | `np.sort` per row (documented XGBoost hist caveat); primary split-conformal path has no quantile heads | none |
| F13 | SQLite "database is locked" — background assess commits 500-asset chunks while dashboard polls GETs | SQLAlchemy `OperationalError` | qubit-core engine setup REQUIRES WAL mode + `busy_timeout` (frame-level requirement, set by qubit-api's engine factory); GETs use read-only sessions; chunk commit retries ×3 with backoff | transient latency only |
| F8 | MC produces `F(2100) < 0.5` (median undefined) for some algorithm | post-sim check | `median_year = None`; Mosca uses `Z = horizon − now` with flag `beyond_horizon` | dashboard shows ">2100" |
| F9 | Simulate endpoint abused (huge trials) | request validation | `n_trials ≤ 20000`, 10 s timeout, never persisted | 422 |
| F10 | Concurrent assess runs | `risk_runs` status check | second run rejected 409 unless `force` | CLI prints running run id |
| F11 | Partial batch crash | chunked commits + run status `partial` | `assess --resume <run_id>` skips annotated assets | resumable |
| F12 | Model/param drift (scores change after params edit) | params_hash mismatch vs last run | old explanations kept (keyed by run); dashboard shows curve version | reproducibility preserved |

Global principle: **the pipeline never invents certainty** — every degradation widens CIs or falls back to a more conservative, flagged number, and lands in `RiskRun.degradations`.

---

## 8. Testing strategy

### 8.1 Layers

1. **Pure-function unit tests** (`surface_code`, blending, Mosca, features): golden values computed by hand in the test docstring. Example: with `A=0.1, p=1e-3, p_th=1e-2, d=15` ⇒ `p_L = 0.1·0.1⁸ = 1e-9` — asserted exactly.
2. **Literature calibration tests (the anchor tests):** feed `calibration_anchors` from `resource_estimates.yaml` through `required_physical_qubits` and assert the result is within **×2** of the published figure (Webber 317M/1h and 13M/24h for ECC-256; Gidney-Ekerå 20M/8h for RSA-2048). These tests are the scientific credibility gate of the whole simulator and run in CI.
3. **Property tests (hypothesis):** monotonicity invariants — larger key size ⇒ stochastically later break year (`F_RSA4096(T) ≤ F_RSA2048(T) ∀T`); longer shelf life ⇒ `P_HNDL` non-decreasing; `offline` exposure ⇒ score ≤ same asset `network`-exposed; CI always contains score; all outputs in [0,1].
4. **BN ≡ closed-form agreement:** random assets, assert `|BN − integral| < 0.02`.
5. **Classifier tests:** frozen 600-example human-verified set → macro-F1 regression gate (fails CI if F1 drops >2 points vs recorded baseline); heuristic ruleset has one fixture per rule.
6. **Conformal coverage test:** on the held-out synthetic test fold, empirical coverage of the 90% CI must be in [0.87, 0.95].
7. **Determinism test:** two full pipeline runs, same seed ⇒ identical DB rows (MC/BN/Mosca bitwise; xgb/bert ≤1e-6).
8. **API contract tests:** FastAPI `TestClient` against a seeded SQLite; JSON schema snapshots for every endpoint (dashboard devs code against these snapshots).
9. **Performance smoke:** 10k synthetic assets < 5 min **on the heuristic path**, RSS < 4 GB; separate BERT throughput check ≤ 10 min per 1k unique contexts (CI job, non-blocking warn). The two are never asserted jointly (FR6).

### 8.2 How fixtures get built

- `tests/fixtures/make_fixtures.py --seed 7` deterministically generates: (a) `assets_small.json` — 25 hand-designed `CryptoAsset`s covering every algorithm family, exposure, and edge case (missing key_size, unknown algorithm, PQC-safe, cert-only); (b) `assets_10k.json` for perf tests; (c) golden outputs `expected_scores.json` regenerated only by explicit `--bless` (diffs reviewed in PR).
- **Demo-lab snapshot fixture:** one committed JSON dump of a real `qubit scan` over `demo-lab/` (≈300 assets). This is the integration fixture that keeps scanner→risk contract honest; regenerated at each scanner release.
- Sensitivity corpus: `sensitivity/datagen.py` is itself the fixture builder; the 600-example human-verified set is committed (it is small, hand-made, and the paper's eval artifact).
- Timeline golden curves: `curves_golden.json` for the default params hash (seed 42, 10k trials) — snapshot test catches accidental model changes.

### 8.3 Paper-experiment harness (`qubit risk eval`)

Reproducible scripts (seeded, params-hashed) emitting the paper's tables/figures: timeline sensitivity analysis (tornado plot over priors), survey-weight sweep, classifier ablation (heuristic vs BERT vs LLM-zero-shot), regressor-vs-human Spearman, conformal calibration plot. Lives in-repo so reviewers can rerun everything.

---

## 9. Milestones (frame cadence) — acceptance criteria & effort

Effort assumes the risk-engine lead at ~60% of their time on this package, second member reviewing + owning the human-labeling sessions. 1 person-week (pw) = ~35 focused hours (realistic undergrad final-year pace alongside coursework).

### M1 — walking skeleton (by First Review, ~Sep 2026) — **3 pw**

Scope: the frame's "heuristic risk score" slice, plus timeline v0 so the review demo already shows a CRQC curve.

- Heuristic sensitivity classifier (full ruleset engine + 30 starter rules) wired into pipeline.
- Timeline v0: full surface-code math + MC loop, hardware priors, **no survey blending yet**; anchor calibration tests passing.
- Static risk score v0: lookup `(attack, key_size, sensitivity tier, exposure)` → score table + Mosca margin with default Y table.
- `qubit risk assess/timeline/mosca/explain` CLI; `GET /timeline`, `GET /assets`, `POST /assess` endpoints; curves render on the minimal dashboard page.
- Resource-estimate YAML values re-derived from the three cited papers (documented in-file).

*Acceptance:* scan of demo-lab → every asset has sensitivity + score + Mosca margin in DB; `GET /api/v1/risk/timeline?algorithm=RSA-2048` returns a curve whose anchor tests pass in CI; `qubit risk explain` shows rule trace; coverage ≥70% on `qubit-risk`.

### M2 — feature complete baseline (Nov 2026 review; spillover lands in the December break per the portfolio schedule) — **5 pw**

- Survey blending (@24h event matching). (0.75 pw)
- pgmpy BN (5-node, §6.2.1) + closed-form fallback + factor explanations. (1.25 pw)
- Sensitivity corpus built (templates + weak labels + disagreement adjudication + 600 human-verified) and DistilBERT fine-tuned with gating; **ship/no-ship decision Oct 15** per §6.3.4 gate. (2 pw — the labeling sessions are the long pole; scheduled as two fixed 4 h sessions/member in early Oct)
- XGBoost primary path: label synthesis pipeline, `reg:squarederror` training, split-conformal CI, TreeSHAP, `train xgb` command. (0.5 pw — the simple primary path is cheap; that is exactly why the multi-quantile version was demoted to stretch)
- Full degradation ladder + failure-mode tests; run bookkeeping/resume; API complete incl. summary/mosca. (0.5 pw)

**Deferred out of the M2 window into the December break (early M3), pre-scheduled — not "cut under pressure":** `/simulate` what-if endpoint + sliders (also the API registry's first cut-line), CQR stretch, any BERT re-training iteration beyond the Oct 15 decision.

*Acceptance:* end-to-end demo — scan → classified sensitivities (BERT or gated heuristic per the Oct 15 decision) → BN factors visible → scores with CIs → ranked queue consumed by `qubit-migrate`; conformal coverage test green; determinism test green; classifier F1 gate recorded; 10k-asset heuristic-path batch < 5 min.

### M3 — hardened product + paper experiments (Dec 2026 break + Jan–Mar 2027) — **2 pw baseline + deferred M2 items**

- `qubit risk eval` harness + all paper figures reproducible from one make target. (1 pw)
- Human-ranking study (40 assets, 3 raters, Bradley-Terry) + baseline comparisons. (0.5 pw)
- Model cards, params documentation, priors tuning after guide review, docs pages, packaging polish. (0.5 pw)

*Acceptance:* CI fully green incl. coverage & calibration gates; Spearman-vs-human result recorded (whatever it is — it's a paper number); every figure in the paper regenerable by script; docker image runs assess offline.

**Total: ~10 pw** from the **portfolio-reconciled ~44 pw team budget owned by 06-engineering-plan** (this package is the paper's core novelty and is funded accordingly; the earlier 19 pw draft over-claimed the M2 window — 10 pw of work cannot fit a ~9-week in-semester window alongside five other subsystems, which is why the M2 scope above is thinner and two items are pre-scheduled into the break).

---

## 10. Risks & mitigations + cut-lines

### Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| R1 Sensitivity training data too weak → BERT ≤ heuristic | Medium-high | Paper claim weakens | Ship gate (§6.3.4); heuristic tier is always the floor; a negative result comparing heuristic/BERT/LLM-zero-shot is *itself publishable content* — frame it as an ablation either way |
| R2 Reviewers attack expert-elicited CPDs / priors as arbitrary | High | Paper rejection risk | Every number sourced + YAML-versioned; sensitivity analysis (tornado plots) shows which priors matter; survey-weight sweep shows conclusions robust to w ∈ [0.3, 0.7] |
| R3 Circularity critique of XGBoost teacher labels | Medium | Paper | Framed explicitly as distillation+fusion (§6.4.1); external human-ranking validation is the real eval; BN-only ablation included |
| R4 transformers v5 / pgmpy 1.x API drift vs online tutorials | Medium | Dev time loss | Versions pinned; the two known breaking renames documented in this design; smoke import test in CI |
| R5 MC model dismissed as toy physics | Medium | Paper | Anchor tests reproduce three published resource points within ×2; first-order model clearly scoped; η captures architecture uncertainty honestly |
| R6 Laptop can't fine-tune BERT | Low | Schedule | Colab free tier suffices (<1 h); checkpoint hosted on HF Hub; assess-time is CPU-only regardless |
| R7 Teammate dependency: `migration.effort_estimate` (Y) not ready by M2 | Medium | Mosca quality | Default Y lookup table ships in M1 and is always the fallback |
| R8 Two-person bandwidth collapse near reviews | High | Everything | Cut-lines below are pre-agreed and ordered; each leaves a coherent demo story |

### Cut-lines (drop in this order under time pressure)

- **C1** ONNX/optimum inference optimization — never start it; CPU torch is fine at our scale. *(zero story loss)*
- **C2** Conformalized Quantile Regression (adaptive CIs) → keep plain split-conformal constant-width CIs. *(CIs still statistically valid; one paper subsection shrinks)*
- **C3** DistilBERT fine-tune → ship heuristic tier + local-LLM zero-shot as the "ML" comparison point. *(story becomes "transparent rules with LLM assist"; still a classifier ablation for the paper)*
- **C4** pgmpy BN → keep only the closed-form integral (same probability), keep the BN *diagram* as a paper figure of the factorization. *(dashboard loses the factor panel; math unchanged)*
- **C5** Survey blending → hardware-only MC with wider priors. *(lose the GRI anchor; curves still defensible via anchor tests)*
- **C6** `/simulate` what-if endpoint + dashboard sliders. *(demo loses one flourish)*

**Never cut:** the MC timeline with anchor tests, heuristic sensitivity + shelf-life priors, the [0,1] score with *some* honest CI, Mosca margins, DB annotation + timeline API — that quintet is the product story ("we rank your assets by probability of being decrypted before they stop mattering, and we show our math").
