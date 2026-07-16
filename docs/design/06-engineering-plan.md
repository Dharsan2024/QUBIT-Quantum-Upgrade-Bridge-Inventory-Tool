# QUBIT — 06 Engineering Plan: Repo, CI/CD, Testing, Evaluation, Timeline, Team Split

Status: v1 design (2026-07-15). Conforms to `00-architecture-frame.md` (binding). Owners: both students; Student A is "Release Engineer", Student B is "Evaluation Engineer" (see §12).

This document is the meta-subsystem: everything that turns QUBIT from a prototype into a shippable product and a publishable paper — repo bootstrap, CI/CD, testing, the paper's evaluation harness, security/ethics guardrails, the 9-month timeline, and the two-person work split.

---

## 1. Purpose & requirements

### 1.1 Functional requirements

| ID | Requirement |
|---|---|
| ENG-F1 | One-command dev setup: `git clone && uv sync && uv run poe check` works on Linux/WSL2/macOS in < 10 min (excluding docker pulls). |
| ENG-F2 | CI on every PR: lint (ruff), format check, type check (mypy), unit tests with ≥70% coverage on core packages (`qubit-core`, `qubit-scanner`, `qubit-risk`), dashboard typecheck+tests, license check, secret scan. |
| ENG-F3 | Nightly/label-gated integration CI: dockerized TLS endpoints, demo-lab end-to-end scan, golden CBOM tests. |
| ENG-F4 | Tagged release `vX.Y.Z` automatically: builds all workspace wheels, publishes to PyPI (trusted publishing), builds+pushes `qubit-api`, `qubit-dashboard`, `qubit-demo-lab` images to GHCR, generates changelog. |
| ENG-F5 | Reproducible evaluation: `uv run experiments/run_all.py --seed 42` regenerates every number/figure in the paper from pinned corpora; results land as CSV + PNG in `experiments/results/`. |
| ENG-F6 | Test-fixture corpora with machine-readable ground truth (partial `CryptoAsset` records) built from CryptoAPI-Bench (MIT) + a hand-written polyglot QUBIT-Corpus. |
| ENG-F7 | Network scanning is deny-by-default outside RFC1918/loopback and requires explicit authorization acknowledgement; all scans logged. |
| ENG-F8 | Docs site (`mkdocs-material`) auto-deployed to GitHub Pages on merge to `main`; README quickstart verified in CI (`docs-smoke` job runs the README commands). |
| ENG-F9 | Week-by-week plan mapped to university gates (First Review ~Sep 2026, Second ~Nov 2026, Phase-2 reviews Jan–Mar 2027, defense Apr 2027) with explicit critical path and cut-lines. |

### 1.2 Non-functional requirements

- **PR CI wall time ≤ 10 min** (unit path); integration path ≤ 30 min nightly. Cache uv, node, and docker layers aggressively.
- **Determinism**: all randomized components (Monte Carlo, XGBoost, LLM sampling) accept a seed; LLM tests run against recorded fixtures by default.
- **Offline-capable dev**: no test requires internet except explicitly marked `@pytest.mark.online` (excluded from CI gates).
- **License hygiene**: only permissive-licensed runtime deps (MIT/BSD/Apache-2.0/PSF); copyleft tools (baseline scanners) are *executed*, never vendored or linked.
- **Windows-friendly dev**: both students are on Windows → primary dev environment is WSL2 + Docker Desktop; repo must not contain files whose names differ only by case; all task automation via `poethepoet` (cross-platform), no Makefile-only workflows.
- **Two-person maintainability**: every PR reviewed by the other student (CODEOWNERS-enforced); no component understood by only one person after M2.

---

## 2. Component breakdown

| Component | Location | Responsibility | Owner |
|---|---|---|---|
| Repo scaffold | repo root | uv workspace, pyproject configs, pre-commit, editorconfig, task runner | A |
| CI pipelines | `.github/workflows/` | `ci.yml`, `integration.yml`, `release.yml`, `docs.yml`, `nightly.yml` | A |
| Release engineering | `.github/workflows/release.yml`, `scripts/bump_version.py` | lockstep versioning, PyPI + GHCR publish, changelog | A |
| Test harness | `packages/*/tests/`, `tests/` (cross-package) | unit/integration/golden/LLM-contract tests, shared fixtures | both |
| Fixture corpora | `tests/fixtures/corpus/`, `scripts/build_corpus.py` | vendored CryptoAPI-Bench subset + QUBIT-Corpus + ground-truth manifests | B |
| Baseline runners | `tools/baselines/` | Dockerfiles + adapters to run CogniCrypt(CryptoAnalysis)/CryptoGuard JARs for the paper | B |
| Evaluation harness | `tools/qubit-eval/` (dev-only workspace member, not published) | metrics engine: P/R/F1, calibration, patch success, handshake overhead | B |
| Experiments | `experiments/` | one directory per paper experiment, `run_all.py` orchestrator | B |
| Demo lab CI | `demo-lab/` + `integration.yml` | compose scenario boots in CI, 4-phase demo smoke-tested | A |
| Docs | `docs/`, `mkdocs.yml` | user guide, dev guide, demo runbook, design docs (this series) | both |
| Ethics guardrails | spec here; implemented in `qubit-scanner`/`qubit-cli` | scan authorization, rate limits, audit log | A |

Frame conformance: `tools/`, `experiments/`, `scripts/`, `.github/`, `tests/` are additive top-level directories; the binding `packages/`, `dashboard/`, `demo-lab/`, `docs/` layout is unchanged (see §14 Frame deviations).

---

## 3. Exact tech stack (verified July 2026)

All permissive-licensed and pip/npm-installable unless noted. Versions are current stable as of 2026-07-15; pin with `>=X,<X+1` style constraints in `pyproject.toml` and exact pins in `uv.lock`.

| Tool | Version | License | Role |
|---|---|---|---|
| uv | 0.11.x (≥0.11.28) | MIT/Apache-2.0 | workspace, lockfile, task exec, build backend front-end |
| Python | 3.12 & 3.13 (CI matrix) | PSF | runtime per frame |
| ruff | ≥0.15 | MIT | lint + format (replaces black/isort/flake8) |
| mypy | ≥2.3 | MIT | type checking (strict on `qubit-core`) |
| pytest | ≥9.1 | MIT | test runner |
| pytest-cov / coverage.py | ≥6 / ≥7.6 | MIT / Apache-2.0 | coverage gate |
| pytest-xdist | ≥3.6 | MIT | parallel unit tests |
| hypothesis | ≥6.115 | MPL-2.0 (file-level, acceptable as test-only dep) | property tests for parsers/canonicalizer |
| testcontainers (`testcontainers` on PyPI) | ≥4.14 | Apache-2.0 | dockerized TLS endpoints in integration tests |
| trustme | ≥1.2 | MIT/Apache-2.0 | ephemeral classical test CAs/certs |
| cyclonedx-python-lib | ≥11.11 | Apache-2.0 | CBOM model/serialize/validate (supports Python 3.9–3.14; spec 1.6/1.7 models — golden tests also validate against the ECMA-424 JSON schema directly) |
| jsonschema | ≥4.23 | MIT | CBOM schema validation in golden tests |
| poethepoet | ≥0.30 | MIT | cross-platform task runner (`uv run poe check`) |
| pre-commit | ≥4 | MIT | git hooks |
| gitleaks | ≥8.21 (binary in CI) | MIT | secret scanning (with fixture-key allowlist) |
| pip-licenses | ≥5 | MIT | license inventory gate |
| git-cliff | ≥2.6 | MIT/Apache-2.0 | changelog from conventional commits |
| mkdocs-material | ≥9.5 | MIT | docs site |
| mkdocstrings[python] | ≥0.27 | ISC | API reference from docstrings |
| httpx | ≥0.28 | BSD-3 | API integration tests |
| respx | ≥0.22 | BSD-3 | mock Ollama/HTTP in LLM contract tests |
| pandas + matplotlib | ≥2.2 / ≥3.9 | BSD-3 / PSF-based | experiment result tables/figures |
| Node.js / npm | 22 LTS | MIT | dashboard toolchain |
| vitest + @testing-library/react | ≥3 / ≥16 | MIT | dashboard unit tests |
| Playwright (`@playwright/test`) | ≥1.49 | Apache-2.0 | dashboard e2e smoke (M3, cut-line eligible) |
| GitHub Actions | `actions/checkout@v5`, `astral-sh/setup-uv@v8.1.0` (immutable full-version tags only — v8+ publishes no moving major tags), `actions/setup-node@v4`, `docker/build-push-action@v6`, `pypa/gh-action-pypi-publish@release/v1` | — | CI/CD |
| OpenSSL | ≥3.5 (in test/demo images) | Apache-2.0 | native ML-KEM/ML-DSA + default `X25519MLKEM768` hybrid keyshare — used for hybrid TLS integration tests |
| liboqs / oqs-provider | latest release | MIT | non-standardized PQC algs + OpenSSL <3.5 compatibility (note: oqs-provider disables ML-KEM/ML-DSA when loaded with OpenSSL ≥3.5 — tests must account for this) |

Benchmark/baseline assets (evaluation only, never redistributed in wheels):

| Asset | Source | License | Use |
|---|---|---|---|
| CryptoAPI-Bench | github.com/CryptoAPI-Bench/CryptoAPI-Bench (pinned SHA) | MIT — verified | vendor a curated subset + ground truth into `tests/fixtures/corpus/cryptoapi-bench/`; full set used in experiments |
| MASC | github.com/Secure-Platforms-Lab-W-M/MASC | license unverified → treat as run-only: generate mutants at experiment time in a container, do **not** vendor outputs into the repo | robustness experiment (cut-line eligible) |
| CogniCrypt/CryptoAnalysis, CryptoGuard | upstream JAR releases | EPL/GPL-family (copyleft) → run as external tools inside `tools/baselines/` docker images; never linked or redistributed | paper baselines |

Key sources: [uv workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/), [setup-uv releases](https://github.com/astral-sh/setup-uv/releases), [cyclonedx-python-lib](https://pypi.org/project/cyclonedx-python-lib/), [CycloneDX 1.7 release](https://cyclonedx.org/news/cyclonedx-v1.7-released/), [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench), [MASC](https://github.com/Secure-Platforms-Lab-W-M/MASC-Artifact), [OpenSSL 3.5 notes](https://openssl-library.org/news/openssl-3.5-notes/), [oqs-provider](https://github.com/open-quantum-safe/oqs-provider).

### 3.1 Repo bootstrap — concrete configs

Root `pyproject.toml`:

```toml
[project]
name = "qubit-workspace"
version = "0.0.0"          # placeholder; real versions live in each package, kept lockstep
requires-python = ">=3.12"

[tool.uv.workspace]
members = ["packages/*", "tools/qubit-eval"]

[tool.uv.sources]
qubit-core = { workspace = true }
qubit-scanner = { workspace = true }
qubit-risk = { workspace = true }
qubit-migrate = { workspace = true }
qubit-bridge = { workspace = true }
qubit-api = { workspace = true }
qubit-cli = { workspace = true }

[dependency-groups]
dev = [
  "pytest>=9.1", "pytest-cov>=6", "pytest-xdist>=3.6", "hypothesis>=6.115",
  "mypy>=2.3", "ruff>=0.15", "pre-commit>=4", "poethepoet>=0.30",
  "testcontainers>=4.14", "trustme>=1.2", "httpx>=0.28", "respx>=0.22",
  "jsonschema>=4.23", "pip-licenses>=5",
]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "S", "PTH", "RUF"]
ignore = ["S101"]                       # assert in tests
per-file-ignores = { "tests/**" = ["S", "SIM"], "demo-lab/**" = ["S"] }  # demo-lab is deliberately vulnerable

[tool.mypy]
python_version = "3.12"
strict = false
packages = []                            # configured per-package; qubit-core sets strict = true

[tool.pytest.ini_options]
addopts = "-ra -n auto --strict-markers"
markers = [
  "integration: needs docker",
  "llm: needs live Ollama",
  "online: needs internet",
  "slow: >30s",
]
testpaths = ["packages", "tests"]

[tool.coverage.run]
source = ["qubit_core", "qubit_scanner", "qubit_risk"]   # coverage gate scope per frame
branch = true

[tool.poe.tasks]
fmt = "ruff format ."
lint = "ruff check ."
type = "mypy packages/qubit-core packages/qubit-scanner packages/qubit-risk packages/qubit-api packages/qubit-cli"
unit = "pytest -m 'not integration and not llm and not online'"
integ = "pytest -m integration"
check = ["fmt", "lint", "type", "unit"]
corpus = "python scripts/build_corpus.py"
goldens = "pytest tests/golden --update-goldens"
```

Each package `packages/qubit-<name>/pyproject.toml` uses `hatchling` as build backend, `version = "0.1.0"` (lockstep, bumped by `scripts/bump_version.py`), depends on `qubit-core` via workspace source.

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.0
    hooks: [{id: ruff, args: [--fix]}, {id: ruff-format}]
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks: [{id: check-yaml}, {id: check-merge-conflict}, {id: end-of-file-fixer},
            {id: detect-private-key, exclude: '^tests/fixtures/|^demo-lab/'}]
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.0
    hooks: [{id: gitleaks}]
```

`.gitleaks.toml` allowlist (fixtures contain deliberate keys):

```toml
[allowlist]
paths = ['''tests/fixtures/.*''', '''demo-lab/.*\.(pem|key|jks)''']
description = "Deliberately vulnerable fixtures and demo-lab keys — not real secrets"
```

Bootstrap sequence (Week 1, scripted as `scripts/bootstrap.sh`): init repo → root pyproject + workspace members with empty `src/qubit_<name>/__init__.py` → `uv lock` → pre-commit install → push `ci.yml` → branch protection on `main` (require CI + 1 review) → reserve PyPI names (`qubit-core`, `qubit-scanner`, …) by publishing 0.0.1a0 stubs; if any name is taken, fall back to the `qubit-pqc-*` prefix for **all** packages (decide once, Week 1 — this is why we reserve early).

---

## 4. Data models / schemas

All evaluation records reference the shared `CryptoAsset` (frame §"Shared CryptoAsset schema") — expected findings are expressed as *partial CryptoAssets* so scanner output can be compared field-for-field without a translation layer. Models live in `tools/qubit-eval/src/qubit_eval/models.py` as Pydantic v2; ground-truth manifests are YAML files beside the corpus.

### 4.1 GroundTruthCase (corpus manifest entry)

```yaml
# tests/fixtures/corpus/cryptoapi-bench/manifest.yaml (one entry)
- case_id: cab-brokencrypto-01
  source: cryptoapi-bench            # cryptoapi-bench | masc | qubit-corpus
  source_ref: "src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java"
  language: java                     # java | python | go | c | config
  secure: false                      # true = negative case (tests false positives)
  misuse_category: broken-cipher     # taxonomy in §4.2
  cwe: CWE-327
  expected_asset:                    # PARTIAL CryptoAsset — only fields a scanner must produce
    source_scanner: code
    asset_type: algorithm-use
    algorithm: DES                   # canonical registry name (qubit-core)
    key_size: 56
    usage_context: encryption-at-rest
    quantum_vulnerable: { vulnerable: false, attack: none }   # DES is classically broken, not HNDL
    location: { file_path: "...BrokenCryptoABICase1.java", line: 23 }
  line_tolerance: 2
  notes: "cipher name via interprocedural string flow"
```

```python
class GroundTruthCase(BaseModel):
    case_id: str
    source: Literal["cryptoapi-bench", "masc", "qubit-corpus"]
    source_ref: str
    language: Literal["java", "python", "go", "c", "config"]
    secure: bool
    misuse_category: MisuseCategory
    cwe: str | None = None
    expected_asset: PartialCryptoAsset | None    # None when secure=True
    line_tolerance: int = 2
    notes: str = ""

class CorpusManifest(BaseModel):
    corpus_id: str                 # e.g. "cryptoapi-bench@<git-sha>"
    root: Path
    cases: list[GroundTruthCase]
    license: str                   # "MIT" — recorded for compliance audit
```

### 4.2 Misuse taxonomy → CryptoAsset mapping

`MisuseCategory` enum (kept deliberately small; maps CryptoAPI-Bench's 16 vulnerability types and our PQC-specific classes onto scanner-checkable facts): `broken-cipher`, `broken-hash`, `weak-key-size`, `static-key-iv-salt`, `weak-prng`, `bad-tls-config`, `quantum-vulnerable-kex`, `quantum-vulnerable-signature`, `hardcoded-credential`. Each category declares which `CryptoAsset` fields participate in matching (e.g. `broken-hash` matches on `algorithm` + `usage_context: hash`; `quantum-vulnerable-kex` matches on `algorithm` + `quantum_vulnerable.attack == shor`).

### 4.3 EvalRun / MatchResult (scanner benchmark)

```python
class MatchResult(BaseModel):
    case_id: str
    status: Literal["tp", "fp", "fn", "tn"]
    asset_id: UUID | None          # matched CryptoAsset.id from the scan
    matched_on: list[str]          # fields that matched, e.g. ["algorithm", "location.line"]
    mismatch: dict[str, tuple[Any, Any]] = {}   # field -> (expected, actual) for near-misses

class EvalRun(BaseModel):
    run_id: str                    # "{tool}-{corpus_id}-{timestamp}"
    tool: str                      # "qubit" | "qubit-ast-only" | "qubit-llm" | "cryptoguard" | "cognicrypt"
    tool_version: str
    corpus_id: str
    seed: int
    started_at: datetime
    wall_time_s: float
    results: list[MatchResult]
    metrics: EvalMetrics           # computed, not stored independently

class EvalMetrics(BaseModel):
    tp: int; fp: int; fn: int; tn: int
    precision: float; recall: float; f1: float
    per_category: dict[MisuseCategory, "EvalMetrics"]
```

### 4.4 PatchTrial (LLM migration success rate)

```python
class PatchTrial(BaseModel):
    trial_id: str
    asset_id: UUID                     # FK -> CryptoAsset.id in registry DB
    model: str                         # e.g. "qwen2.5-coder:7b"
    prompt_version: str                # prompt templates are versioned files
    prompt_hash: str                   # sha256 of rendered prompt
    attempt: int                       # pass@k bookkeeping
    diff_path: Path
    diff_applies: bool
    compiles: bool                     # py_compile / javac / gcc as per language
    tests_pass: bool | None            # target project test suite, if any
    rescan_clean: bool                 # re-scan no longer reports the asset (frame data-flow: "re-scan proves remediation")
    banned_primitive_absent: bool      # regex gate, §6.4
    wall_time_s: float
    verdict: Literal["success", "partial", "failure"]   # success = applies ∧ compiles ∧ rescan_clean ∧ banned_absent
```

### 4.5 HandshakeSample (hybrid TLS overhead)

```python
class HandshakeSample(BaseModel):
    group: Literal["x25519", "secp256r1", "X25519MLKEM768", "SecP256r1MLKEM768"]
    openssl_version: str
    rtt_ms: int                        # injected via `tc netem` (0, 20, 100)
    handshake_ms: float
    client_hello_bytes: int
    server_flight_bytes: int
    iterations: int                    # ≥200 per cell
```

### 4.6 Golden CBOM fixture

`tests/golden/cbom/<scenario>/`: `input/` (mini project or recorded scan DB), `expected.cbom.json` (canonicalized, volatile fields stripped — §6.2), `meta.yaml` (`scenario_id`, `spec_version: "1.7"`, `updated_by`, `qubit_version`).

---

## 5. Public interfaces

### 5.1 CLI (extends the `qubit` Typer app; eval commands ship only in the dev workspace, exposed as `qubit-eval`)

```
qubit scan <path|host> [--out cbom.json]        # product (frame req #1) — owned by scanner doc
qubit-eval scanner  --corpus tests/fixtures/corpus/cryptoapi-bench \
                    --tool qubit|cryptoguard|cognicrypt --out experiments/results/
qubit-eval patches  --db qubit.db --model qwen2.5-coder:7b --k 3 --out ...
qubit-eval handshake --groups x25519,X25519MLKEM768 --rtt 0,20,100 --iters 200 --out ...
qubit-eval calibrate --db qubit.db --labels experiments/labels/sensitivity.csv --out ...
qubit-eval report   --results experiments/results/ --out experiments/results/summary.md
```

### 5.2 Python API (`qubit_eval`)

```python
class ScannerAdapter(Protocol):
    name: str
    version: str
    def scan(self, target: Path) -> list[CryptoAsset]: ...
    # QubitAdapter wraps qubit-scanner's public API;
    # CryptoGuardAdapter / CogniCryptAdapter run docker images in tools/baselines/
    # and parse their native reports into partial CryptoAssets.

def run_scanner_eval(corpus: CorpusManifest, adapter: ScannerAdapter, *,
                     out_dir: Path, seed: int = 42) -> EvalRun: ...
def match_findings(case: GroundTruthCase, found: list[CryptoAsset]) -> MatchResult: ...
def verify_patch(asset: CryptoAsset, diff_text: str, workdir: Path,
                 language: str) -> PatchTrial: ...
def canonicalize_cbom(doc: dict, *, strip: frozenset[str] = VOLATILE_FIELDS) -> dict: ...
def measure_handshakes(group: str, endpoint: str, iterations: int) -> list[HandshakeSample]: ...
```

### 5.3 REST endpoints

This subsystem exposes **no** REST endpoints. It *consumes* `qubit-api` in integration tests using doc 05's normative registry: `POST /api/v1/projects/{pid}/scans`, `GET /api/v1/scans/{sid}/assets?…`, `GET /api/v1/scans/{sid}/cbom` (integration tests here are the contract's enforcement).

### 5.4 CI interface (workflow contract)

| Workflow | Trigger | Jobs |
|---|---|---|
| `ci.yml` | PR + push to `main` | lint → type → unit (py3.12/3.13 matrix) → coverage gate → dashboard (tsc, vitest, build) → licenses → gitleaks → docker build (no push) |
| `integration.yml` | nightly cron + PR label `run-integration` + pre-release | testcontainers TLS matrix, demo-lab e2e, golden CBOM, API contract tests |
| `release.yml` | tag `v*` | build wheels (`uv build --all-packages`) → publish PyPI (OIDC trusted publishing, no stored token) → docker buildx → GHCR push (`ghcr.io/<org>/qubit-api:X.Y.Z` etc.) → git-cliff release notes → GitHub Release |
| `docs.yml` | push to `main` (paths: `docs/**`) | mkdocs build → GH Pages deploy |

`ci.yml` core excerpt (real, drop-in):

```yaml
name: ci
on: {pull_request: {}, push: {branches: [main]}}
jobs:
  test:
    runs-on: ubuntu-latest
    strategy: {matrix: {python: ["3.12", "3.13"]}}
    steps:
      - uses: actions/checkout@v5
      - uses: astral-sh/setup-uv@v8.1.0         # immutable tag; Renovate bumps it
        with: {python-version: "${{ matrix.python }}", enable-cache: true}
      - run: uv sync --all-packages --group dev
      - run: uv run ruff check . && uv run ruff format --check .
      - run: uv run poe type
      - run: uv run pytest -m "not integration and not llm and not online"
             --cov --cov-report=xml --cov-fail-under=70
  licenses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: astral-sh/setup-uv@v8.1.0
      - run: uv sync --all-packages
      - run: uv run pip-licenses --allow-only="MIT;BSD;Apache;Apache 2.0;Apache Software License;PSF;ISC;MPL"
```

Versioning policy: SemVer with lockstep versions across all workspace packages (one version number, one tag, one changelog — the only sane option for a 2-person team). `0.1.0` at M1, `0.2.x`–`0.4.x` through M2, `0.9.0` release-candidate at paper submission, `1.0.0` at final defense. Conventional commits enforced softly (PR title lint), changelog via git-cliff.

---

## 6. Key algorithms & flows

### 6.1 Finding ↔ ground-truth matching (the paper's core scoring routine)

```
match_findings(case, found_assets):
  if case.secure:                          # negative case
      hits = [a for a in found_assets if same_file(a, case) and a.algorithm == expected-ish]
      return "fp" if hits else "tn"
  candidates = [a for a in found_assets
                if a.location.file_path endswith case.expected_asset.location.file_path
                and fields_match(a, case.expected_asset, case.misuse_category)   # §4.2 field sets
                and abs(a.location.line - case.expected_asset.location.line) <= case.line_tolerance]
  if not candidates: return "fn"
  best = min(candidates, key=line_distance)
  consume(best)                            # greedy 1:1 — an asset can satisfy only one case
  return "tp"
# after all cases: every unconsumed asset in a manifest-covered file whose
# misuse_category ∈ taxonomy counts as "fp"; assets outside covered files are ignored
# (baselines report many non-crypto findings; we score only the crypto task).
precision = tp/(tp+fp); recall = tp/(tp+fn); f1 = harmonic mean
```

Design choices that reviewers will probe, decided now: (1) greedy 1:1 matching with line tolerance ±2 (CryptoAPI-Bench cases are single-finding files, so ambiguity is rare); (2) category-specific field sets prevent "right line, wrong reason" from counting as TP; (3) baselines are scored through the *same* function via adapters — no per-tool special-casing beyond report parsing.

### 6.2 Golden CBOM canonicalization

```
canonicalize_cbom(doc):
  1. validate against CycloneDX 1.7 JSON schema (jsonschema) — fail test on invalid
  2. strip volatile fields: serialNumber, metadata.timestamp, all bom-ref UUIDs
     (replace with deterministic refs: sha256(component.name + evidence)[:12])
  3. sort: components by (type, name, evidence), arrays with defined order kept
  4. dump JSON with sort_keys=True, indent=2, ensure_ascii=False
compare: unified diff of canonical forms; test failure prints the diff;
`pytest tests/golden --update-goldens` rewrites expected files (reviewed in PR diff).
```

### 6.3 CI pipeline DAG (PR path)

`checkout → uv sync (cached) → [ruff ∥ mypy ∥ gitleaks ∥ licenses] → pytest-unit (matrix) → coverage gate → [dashboard build ∥ docker build --no-push] → status`. Anything > 10 min gets demoted to `integration.yml`. Docker layer for liboqs/OpenSSL 3.5 is built weekly by `nightly.yml` and pushed as `ghcr.io/<org>/qubit-pqc-base:weekly` so PR builds never compile C.

### 6.4 Patch verification loop (feeds both the product's `migration.status` and the paper's success metric)

```
verify_patch(asset, diff, workdir, language):
  1. git apply --check → diff_applies
  2. apply; run compile gate:  python: py_compile + ruff check --select F
                               java:   javac -cp fixtures/deps
                               config: nginx -t inside nginx:1.27 container
  3. banned-primitive gate: regex family per misuse_category, e.g. for
     quantum-vulnerable-kex: /\b(RSA|ECDH|X25519(?!MLKEM))\b/ must NOT match the
     patched hunk unless inside a hybrid construct (X25519MLKEM768 allowed)
  4. re-scan patched tree with qubit-scanner → rescan_clean = asset no longer reported
  5. if target has tests (demo-lab apps do): run them → tests_pass
  6. verdict = success iff 1∧2∧3∧4 (∧5 when defined); write PatchTrial row
Orchestrator uses the same function: verdict success ⇒ migration.status = "patched";
a later live re-scan flips it to "verified" (frame data-flow).
```

### 6.5 Handshake-overhead measurement

```
for group in {x25519, X25519MLKEM768} × rtt in {0, 20, 100}ms:
  server = docker: nginx:openssl3.5 with -groups <group>, tc netem delay rtt
  for i in 1..200: t0; openssl s_client -groups <group> -brief </dev/null; t1
  record handshake_ms (s_client -brief timing), byte counts from pcap (tshark fields)
report: median + p95 deltas, bytes overhead table → paper Table "hybrid cost"
```

### 6.6 Release flow

`poe release 0.2.0` → `scripts/bump_version.py 0.2.0` (rewrites every package version + inter-package pins, updates `uv.lock`) → PR → merge → `git tag v0.2.0 && git push --tags` → `release.yml` does the rest (§5.4). Rollback = delete tag before PyPI publish job approval (environment protection rule: PyPI publish requires manual approval by the *other* student).

---

## 7. Failure modes & handling

| Failure | Detection | Handling |
|---|---|---|
| Flaky integration tests (docker timing, port clashes) | retry telemetry in CI summary | testcontainers dynamic ports; `pytest-rerunfailures` max 2 for `@integration` only; flake budget: >5% rerun rate opens an issue automatically |
| liboqs/OpenSSL compile breaks CI | weekly base-image build fails | PR CI never compiles C (prebuilt `qubit-pqc-base` image); base image failures don't block PRs |
| Ollama unavailable / nondeterministic in CI | `@llm` tests skipped when `OLLAMA_HOST` unset | default CI path uses recorded responses (respx fixtures); live LLM runs are nightly, non-blocking, temperature=0, seed pinned |
| PyPI name collision at reservation | Week-1 stub publish fails | switch whole family to `qubit-pqc-*` prefix (single decision point, §3.1) |
| CryptoAPI-Bench upstream disappears/changes | pinned SHA mismatch in `build_corpus.py` | MIT license permits vendoring: curated subset is committed to the repo with LICENSE + provenance; experiments also keep a full mirror tarball in a GitHub Release asset |
| MASC license turns out non-permissive | manual check at M3 start | already run-only in a container; worst case: drop MASC experiment (cut-line C7) |
| Baseline tools won't run on modern JDK | `tools/baselines/` image build | pin JDK 8/11 inside baseline images; baselines run only in experiments, never in product CI |
| Coverage gate blocks urgent work | PR fails `--cov-fail-under` | gate scoped to 3 core packages only; `qubit-migrate`/`qubit-bridge` (docker/LLM-heavy) measured but not gated until M3 |
| Golden CBOM churn on every schema tweak | mass golden failures | canonicalizer strips volatile fields; goldens regenerate with one command and are human-reviewed in the PR diff |
| Secret scanner false-positives on fixture keys | gitleaks hits | `.gitleaks.toml` path allowlist (§3.1); real-secret hits block merge |
| GitHub Actions minutes exhausted (free tier) | usage alert at 70% | public repo = free unlimited for standard runners; keep repo public from day 1 (it's an open-source deliverable anyway) |
| Windows dev friction (paths, docker) | onboarding checklist | canonical dev env = WSL2; `docs/dev/windows.md` runbook; CI is the arbiter, not laptops |
| Student time shock (placement season Aug–Dec 2026) | weekly velocity check vs §11 plan | cut-lines (§10) pre-ordered; M2 scope shrinks before M1 or M3 quality does |

---

## 8. Testing strategy

Test pyramid: **unit (fast, hermetic, PR-gating)** → **golden (CBOM, prompt renders)** → **integration (docker, nightly/label)** → **e2e demo smoke (compose, nightly)** → **evaluation experiments (manual/M3, §9)**. Live-LLM and online tests never gate merges.

### 8.1 Fixture corpora — how they get built

`scripts/build_corpus.py` (idempotent, runs in CI weekly to detect drift):

1. **CryptoAPI-Bench subset** (Java): clone pinned SHA → copy ~60 of the 181 single-file cases spanning all 16 vulnerability categories (basic + interprocedural + path-sensitive) into `tests/fixtures/corpus/cryptoapi-bench/` with upstream `LICENSE` (MIT) and a `PROVENANCE.md` (SHA, date, mapping) → generate `manifest.yaml` entries from a hand-audited CSV (one-time labeling effort: ~2 days, Student B; the upstream `CryptoAPI-Bench_details.xlsx` seeds the labels, we re-verify lines and map to canonical algorithm names).
2. **QUBIT-Corpus** (hand-written, ours, MIT): the polyglot gap CryptoAPI-Bench doesn't cover — ~40 Python cases (`hashlib.md5`, `Crypto.Cipher.DES`, `cryptography` RSA-1024/2048 keygen, `ssl` bad contexts, PyJWT `HS256`/`none`), ~15 Go (`crypto/rsa`, `crypto/des`, `crypto/tls` configs), ~10 C/OpenSSL, ~15 config cases (nginx `ssl_ciphers`, Apache, `sshd_config`, JKS keystores generated by `trustme`+`keytool`), each with manifest entry incl. `quantum_vulnerable` ground truth — this is what makes the scanner's *HNDL* claim (not just misuse) testable. Every case file ≤ 40 lines, one finding per file, secure twins for ~30% of cases (false-positive control).
3. **MASC mutants** (experiments only): run MASC in a container at M3 to generate evasive variants (lowercase `"des"`, string-builder ciphers) → scored like any corpus, results not committed, only CSVs.

Unit tests for scanners consume the corpus via a session-scoped fixture:

```python
@pytest.fixture(scope="session")
def corpus() -> CorpusManifest:
    return CorpusManifest.load(FIXTURES / "corpus")

@pytest.mark.parametrize("case", corpus_cases("python"), ids=lambda c: c.case_id)
def test_python_scanner_detects(case, corpus):
    assets = PythonAstScanner().scan(corpus.root / case.source_ref)
    assert match_findings(case, assets).status == "tp"
```

Scanner unit quality bar tracked in CI as a **trend, not a gate** until M2 (gate at M2: recall ≥ 0.85, precision ≥ 0.85 on QUBIT-Corpus Python+Java).

### 8.2 Integration tests: dockerized TLS endpoints

`tests/integration/tls/` uses testcontainers to launch a matrix of real endpoints the network scanner must classify:

| Container | Config | Expected CryptoAsset (abridged) |
|---|---|---|
| `nginx:1.27` + trustme RSA-2048 cert, TLS1.2-only, `ECDHE-RSA-AES128-GCM-SHA256` | classical legacy | `protocol_detail.version: TLSv1.2`, `algorithm: RSA-2048`, `quantum_vulnerable: {true, shor}` |
| `nginx` on `qubit-pqc-base` (OpenSSL ≥3.5), TLS1.3, groups `X25519MLKEM768` | hybrid PQC | `algorithm: X25519MLKEM768`, `quantum_vulnerable: {false, none}` |
| `openssl s_server` TLS1.3 `X25519` only | classical modern | `usage_context: kex`, vulnerable/shor |
| old `openssl:1.1` image, TLS1.0 + 3DES suite | worst case | `bad-tls-config` + `algorithm: 3DES` |

Note (verified): OpenSSL ≥ 3.5 ships ML-KEM natively and prefers `X25519MLKEM768` by default; oqs-provider disables its own ML-KEM/ML-DSA under OpenSSL ≥ 3.5, so hybrid endpoints use *stock* OpenSSL 3.5 and oqs-provider is only in the image for non-standardized algorithms. Assertions compare scanner output to expected partial assets with the §6.1 matcher. Demo-lab e2e: `docker compose up` → `qubit scan` → assert asset counts, CBOM validates, dashboard `/api/v1/assets` returns them.

### 8.3 Golden-file CBOM tests

Three scenarios frozen as goldens: (1) QUBIT-Corpus mini-project scan, (2) network scan of the TLS matrix (from a recorded scan DB, not live), (3) post-migration re-scan (proves `migration.status` round-trips). Flow per §6.2. Golden updates require the PR to explain *why* in the description (template checkbox).

### 8.4 LLM-output validation tests

Two layers:

- **Contract tests (PR-gating, no LLM):** respx-mocked Ollama returns recorded responses from `tests/fixtures/llm/{model}/{prompt_hash}.json`; tests assert the transformer's *post-processing* — diff extraction from fenced blocks, refusal handling, malformed-diff repair, `verify_patch` gates (§6.4). Recording tool: `poe record-llm --model qwen2.5-coder:7b` run locally, fixtures committed.
- **Live quality runs (nightly, non-blocking):** real Ollama on a self-hosted runner (Student A's desktop with a consumer GPU, registered as GitHub self-hosted runner, `llm` label) executes the patch loop on 10 demo-lab assets; posts pass@1/pass@3 to a tracking issue. Regression >10 points pings both students.

Property tests (hypothesis): CBOM canonicalizer idempotence (`canon(canon(x)) == canon(x)`), manifest round-trip, matcher symmetry on shuffled asset lists.

### 8.5 Dashboard tests

vitest + testing-library for components (risk table sorting, timeline chart props); one Playwright smoke (`loads inventory page against mocked API`) at M3. TypeScript `tsc --noEmit` gates PRs from day 1.

---

## 9. Milestones (frame cadence) with acceptance criteria & effort

Effort assumes ~15 h/person/week during semester, ~30 h/week during breaks; 1 person-week (pw) = 35 h. **Total realistic budget ≈ 44 pw across both students for 9 months (≈ 22 pw/student).** Figures below are the **engineering-plan share**; the remainder is subsystem implementation owned by docs 01–05.

### 9.0 Portfolio capacity reconciliation (this doc is the authority)

The per-subsystem milestone tables (docs 01–05) quote **baseline** person-weeks — the never-cut core only, with each doc's M3/stretch items excluded. They reconcile to the 44 pw budget as follows; the **week-by-week plan (§11) and the per-student ≤ 22 pw cap are the binding constraints**, not any single doc's sub-total:

| Subsystem (doc) | Baseline pw | Primary owner |
|---|---|---|
| Discovery & inventory (01) | 9 | A |
| HNDL risk engine (02) | 10 | B |
| Migration orchestrator (03) | 11 | B |
| Hybrid bridge + demo-lab (04) | 10 | A (shared in demo weeks) |
| Platform: API/DB/dashboard/CLI (05) | 13 | shared (A: core-db, scan/bridge CLI, API infra; B: risk/migrate CLI, dashboard) |
| Engineering plan (06, this doc) | 15 | both |
| **Sum of baselines** | **~68** | — |

**68 baseline pw > 44 available pw is the real, declared tension of a 2-person final-year project** — it is resolved three ways, not hidden: (1) much of docs 05/06's "work" is the *integration surface* of docs 01–04 (the same code counted from two angles — e.g. doc 06's W3–4 "scanner MVP" and doc 01's M1 scanner are one effort), so the true independent sum is ~50–52 pw; (2) the shared cut-line ladder (§10, C1–C8) plus each doc's pre-declared M3/stretch deferrals remove ~8–10 pw of committed scope, landing the **committed** total at ≈ 44 pw; (3) placement season and exams (§11 W19–20) are absorbed by front-loading M1 into the July–August break. If velocity slips, cut-lines fire in order — the never-cut cores (below) always fit in 44 pw.

**Never-cut cores that MUST fit 44 pw** (≈ 40 pw combined, leaving ~4 pw slack): Python+Java+Go code scanner + active TLS + CBOM export (01); MC timeline + heuristic sensitivity + score/CI + Mosca + BN (02); template + Python-LLM transforms + validation stage-5 + state machine + nginx IaC (03); nginx-hybrid + probe/verify + vulnapp-python + same-port before/after capture (04); core DB + API + JobRunner + never-cut dashboard pages + `qubit scan` (05); repo/CI + corpus + one baseline + E1/E3/E4 + docs (06).

### M1 — Walking skeleton (by First Review, ~mid-Sep 2026) — eng share ≈ 4.5 pw

Acceptance criteria:
1. Repo bootstrapped per §3.1; `uv sync && uv run poe check` green on both laptops + CI; branch protection live.
2. `ci.yml` gating PRs (ruff, mypy, unit, coverage ≥50% interim, licenses, gitleaks); PR wall time ≤ 10 min.
3. Corpus v1: CryptoAPI-Bench subset (≥40 Java cases) + ≥25 Python QUBIT-Corpus cases with manifests; scanner unit tests parametrized over it.
4. Golden CBOM scenario #1 passing; CBOM validates against CycloneDX 1.7 schema in CI.
5. `docker compose up` boots api + dashboard stub + demo-lab v0 (`vulnapp-python`, per demo-lab/SPEC.md).
6. PyPI names reserved; `v0.1.0` tag exercises `release.yml` end-to-end (TestPyPI first, then PyPI).
7. First Review demo runs from the demo runbook (`docs/demo/first-review.md`), not from memory.

### M2 — Feature complete (end Phase 1, ~late Nov 2026) — eng share ≈ 4 pw

1. `integration.yml` nightly green: TLS endpoint matrix (all 4 containers), demo-lab e2e, golden scenarios #2–3, API contract tests.
2. LLM contract tests + recorded fixtures in PR gate; nightly live-LLM job posting pass@k.
3. Coverage ≥70% on the three core packages (frame requirement) — now gating.
4. Scanner quality gate on QUBIT-Corpus: P ≥ 0.85 / R ≥ 0.85 (Python+Java).
5. Ethics guardrails live: non-RFC1918 scan refuses without `--authorized` + allowlist file (§13); audit log written.
6. Second Review demo: full 4-phase flow (capture → scan/CBOM → risk dashboard → patch + hybrid TLS re-scan) runs on one laptop via compose in <15 min.

### M3 — Hardened product + paper experiments (Jan–Mar 2027) — eng share ≈ 6.5 pw

1. All four experiment suites (§below) reproducible via `experiments/run_all.py`; results CSVs + figures committed; numbers in the paper traceable to run IDs.
2. Baselines (CryptoGuard, CogniCrypt/CryptoAnalysis) running in `tools/baselines/` containers, scored by the same matcher; comparison table generated.
3. `v0.9.0` on PyPI + GHCR; `pip install qubit-cli && qubit scan .` works on a clean machine; docs site live with quickstart, user guide, demo runbook, API reference.
4. Paper submitted (Annexure-1/SCOPUS target); artifact README maps every claim → experiment dir.
5. `v1.0.0` + defense rehearsal recorded as backup video (demo-failure insurance).

**Paper experiment suites (owned here, defined for doc 01–05 subsystems):**

| Exp | Question | Metric | Dataset | Baseline |
|---|---|---|---|---|
| E1 scanner accuracy | Does hybrid AST+LLM beat rule-based SAST? | P/R/F1 per category | CryptoAPI-Bench (181), QUBIT-Corpus (~80), MASC mutants (robustness) | CryptoGuard, CogniCrypt; ablation: qubit-ast-only vs qubit+LLM |
| E2 risk calibration | Are risk scores meaningful probabilities? | Brier score, reliability diagram (10 bins), sensitivity-classifier F1 | 150 hand-labeled assets (both students label independently, Cohen's κ reported) + Monte Carlo sensitivity analysis over Webber-et-al. hardware priors | uncalibrated heuristic scorer |
| E3 patch success | Can a local LLM migrate code safely? | pass@1/pass@3 on §6.4 verdict, per language/model (7B vs 14B) | demo-lab assets + 30 corpus cases with compile harnesses | none (novel); report failure taxonomy |
| E4 hybrid overhead | What does the bridge cost? | handshake ms (median/p95), bytes, vs RTT | §6.5 matrix | classical X25519 |

---

## 10. Risks & mitigations + cut-lines

| Risk | L×I | Mitigation |
|---|---|---|
| Placement season (Aug–Dec) halves velocity | H×H | front-load M1 into July–Aug break; cut-lines pre-agreed; weekly velocity review vs §11 |
| LLM patches too unreliable for E3 story | M×H | verdict gates make *safety* the claim (never merges a bad patch), success rate is a finding either way; constrain to template-guided diffs for top-5 misuse patterns |
| Baselines unrunnable on benchmark | M×M | known-good: both were evaluated on CryptoAPI-Bench in the literature; pin old JDK images; fall back to reporting literature numbers with citation + our qubit-only numbers |
| Paper rejected before defense | M×M | submit by early Mar to a venue with fast turnaround from the live Annexure-1 list; university accepts "communicated" status; keep arXiv preprint |
| GPU-less CI for LLM | H×L | recorded fixtures gate; self-hosted runner for nightly; if runner dies, live runs become manual weekly |
| Schema churn breaks everything | M×H | `CryptoAsset` frozen at M1 except additive fields; goldens + contract tests make breakage loud; Alembic migrations from day 1 |
| Scope creep from research-plan extras (QUBO, GNN, drones…) | H×M | anything not in frame's non-negotiables needs a cut-line slot below before it's started |

**Cut-lines — drop in this order under time pressure (product story preserved down to C8):**

- C1: D-Wave/PyQUBO QUBO scheduler (already optional) — priority queue stays greedy Risk×Effort.
- C2: GNN on dependency graph → plain NetworkX topological sort.
- C3: XGBoost regressor → deterministic Mosca-margin formula + Bayesian net only (E2 still works).
- C4: DistilBERT sensitivity classifier → keyword heuristics + local-LLM labeling.
- C5: Go and C scanner languages → ship Python + Java + configs.
- C6: Terraform/Ansible IaC generator → nginx config patch only.
- C7: MASC robustness experiment; Playwright e2e; PostgreSQL option.
- C8: Dashboard patch-review UI → CLI diff review (`qubit migrate review`).
- **Never cut:** end-to-end 4-phase demo, CBOM export, hybrid TLS (X25519MLKEM768) live demo, E1 benchmark vs at least one baseline, `pip install` + `docker compose up` paths.

---

## 11. Week-by-week timeline (Zeroth done; W1 = Mon 2026-07-20)

★ = critical path. Gates: **FR** First Review ~W9, **SR** Second Review ~W18, **P2R1/P2R2** Phase-2 reviews ~W27/W32, **Defense** ~W38–40.

| Wk (dates) | Student A (Discovery & Infra) | Student B (Intelligence & Eval) |
|---|---|---|
| W1 7/20 | ★ Repo bootstrap, uv workspace, CI skeleton, PyPI reservation | ★ `qubit-core`: CryptoAsset Pydantic+SQLAlchemy, algorithm registry |
| W2 7/27 | ★ pre-commit, gitleaks, docker base image (`qubit-pqc-base`) | ★ registry DB + Alembic; corpus manifest schema |
| W3 8/03 | ★ tree-sitter Python scanner MVP | build_corpus.py + CryptoAPI-Bench audit/labels |
| W4 8/10 | ★ Java scanner MVP | QUBIT-Corpus Python cases + scanner unit harness |
| W5 8/17 | CBOM export (cyclonedx-python-lib) + golden #1 | heuristic risk scorer v0 (rule table) |
| W6 8/24 | `qubit scan` CLI end-to-end ★ | FastAPI skeleton: /scans, /assets, /cbom |
| W7 8/31 | demo-lab v0 (`vulnapp-python` Flask app, per demo-lab/SPEC.md) + compose | dashboard: inventory table page |
| W8 9/07 | ★ integration of the slice; release v0.1.0 dry-run | FR deck + demo runbook |
| W9 9/14 | **FR** — buffer, feedback fixes | **FR** — buffer |
| W10 9/21 | config scanner (nginx/apache/sshd regex+parser) | ★ Monte Carlo CRQC timeline (Webber params, SciPy) |
| W11 9/28 | cert/keystore scanner (x509, JKS) | ★ Bayesian net (pgmpy) + Mosca margin |
| W12 10/05 | ★ network TLS scanner + authorization guardrails (§13) | sensitivity classifier v0 (keywords) + labeling sprint (150 assets) |
| W13 10/12 | TLS integration test matrix (testcontainers) | XGBoost regressor + calibration harness |
| W14 10/19 | ★ demo-lab v1 (Java+Python apps, legacy TLS) | ★ LLM transformer prototype (Ollama, prompt templates) |
| W15 10/26 | ★ hybrid bridge: nginx + OpenSSL 3.5 X25519MLKEM768 | verify_patch loop + LLM contract fixtures |
| W16 11/02 | orchestrator queue + re-scan verification ★ | risk dashboard pages (timeline curves, queue) |
| W17 11/09 | coverage push to 70%; golden #2–3 | DistilBERT fine-tune iteration (ship/no-ship already decided **Oct 15**, ~W13, per doc 02 §6.3.4; C4 cut if it missed the gate) |
| W18 11/16 | **SR** — full 4-phase demo ★ | **SR** — E1 dry-run on corpus |
| W19–20 11/23–12/06 | *end-sem exams — frozen except CI babysitting* | *exams* |
| W21 12/07 | hardening: error paths, docker compose polish | baseline containers (CryptoGuard, CryptoAnalysis) ★ |
| W22 12/14 | docs site v1 (quickstart, user guide) | E1 full run: qubit vs baselines vs ablation ★ |
| W23 12/21 | v0.5.0 release; README + demo video draft | E2 calibration runs + figures |
| W24 12/28 | IaC patch generator (or C6 cut) | E3 patch success runs (pass@k, 2 models) ★ |
| W25 1/04 | E4 handshake harness + runs | paper: intro/related work draft |
| W26 1/11 | nightly stabilization; self-hosted LLM runner | paper: methodology draft |
| W27 1/18 | **P2R1** — product freeze for eval | **P2R1** — results tables v1 |
| W28–29 1/25–2/07 | bugfix from eval findings; artifact README | ★ paper: results + figures final |
| W30–31 2/08–2/21 | v0.9.0 → PyPI + GHCR ★; docs freeze | paper internal review w/ guide; plagiarism check <10% |
| W32 2/22 | **P2R2** | ★ **paper submission** (Annexure-1 venue) |
| W33–34 3/01–3/14 | thesis/report chapters (product) | thesis chapters (research) |
| W35 3/15 | v1.0.0; demo rehearsal #1 + backup video ★ | viva Q&A prep doc |
| W36–37 3/22–4/04 | rehearsal #2; contingency buffer | contingency buffer |
| W38–40 Apr | **Final defense** | **Final defense** |

Critical path: repo/CI (W1–2) → Python+Java scanner (W3–4) → e2e slice (W6–8) → FR → network scanner (W12) → LLM transformer + verify loop (W14–15) → hybrid bridge (W15) → SR demo (W18) → baselines + E1/E3 (W21–24) → paper submission (W32) → v1.0 + rehearsals (W35). Slack lives in W9, W19–20 (exams are also schedule risk absorbers), W28–29, W36–37.

---

## 12. Two-person work split & integration points

| | **Student A — Dharsan (Discovery & Infrastructure)** | **Student B — Akshay (Intelligence & Evaluation)** |
|---|---|---|
| Owns | qubit-scanner (all four), qubit-bridge, demo-lab, CI/CD + releases, docker/base images, ethics guardrails, **dashboard: scaffold + Inventory + Scans/Jobs + CBOM pages** | qubit-risk (MC, Bayes, classifier, regressor), qubit-migrate (LLM, queue), qubit-eval + experiments, paper first-draft, **dashboard: Risk posture + CRQC timeline + Migration-review pages** |
| Shared | qubit-core (schema changes need both approvals), qubit-api & qubit-cli (A: scan/bridge endpoints; B: risk/migrate endpoints), the dashboard shell/router/API-client, docs, paper revisions | same |
| Load | ≈ 22 pw: scanner 9 + bridge/demo 6 + dashboard-display 3 + CI/infra 4 | ≈ 22 pw: risk 10 + migrate 8 + dashboard-analytics 2 + eval 2 (paper writing overlaps break weeks) |

**Load-balance rationale:** the dashboard is **split by page domain** rather than owned wholesale — A builds the data-display pages (Inventory, Scans, CBOM — a natural extension of owning the scanner/CBOM output), B builds the analytics pages that visualise its own engines (Risk posture, CRQC timeline, Migration-review). Both build against doc 05's normative REST registry + fixtures (§8.2 fixture-first), so neither blocks on the other's backend. This keeps each student near the 22 pw cap without one person owning both the hardest engines and all the front-end.

Rules: CODEOWNERS routes reviews (`packages/qubit-scanner/ @dharsan`, `dashboard/ @dharsan`, `packages/qubit-risk/ @akshay`, `packages/qubit-core/ @dharsan @akshay`); every PR needs the other student's approval; weekly 1-h sync with guide; a component's owner writes its tests, the *other* student writes its integration test (forces interface honesty).

Integration contracts (frozen at the listed week): **I1** (W6): scanner→registry writes valid CryptoAssets, B's API reads them. **I2** (W13): risk engine annotates `risk`/`sensitivity`/`shelf_life_years` in-place; A's CBOM export carries them. **I3** (W16): orchestrator emits diffs; A's re-scan flips `migration.status` to `verified`; bridge exposes hybrid endpoint the network scanner classifies as safe. **I4** (W22): eval harness scores A's scanner through the same adapter API as baselines.

---

## 13. Security, ethics & compliance

- **Scan authorization (implemented in qubit-scanner/qubit-cli; specified here):** network scans of targets outside `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, and `::1` are refused unless (a) target matches an entry in `~/.config/qubit/scan-allowlist.txt` **and** (b) `--authorized` flag is passed. The CLI prints the legal warning and requires typing the target hostname to confirm on first use. No SYN/stealth scanning ever — TCP connect + TLS handshake enumeration only; default rate limit 10 connections/s/host; `--rate` capped at 50. Every network scan appends a JSON line to `~/.local/state/qubit/scan-audit.log` (target, time, user, args).
- **CI never scans the public internet** (`@online` excluded); all integration targets are containers we own.
- **Responsible defaults:** no exploitation, no cipher downgrade attacks against third parties; demo HNDL capture is performed only inside the demo-lab compose network. University/lab network scans require written guide approval (kept in `docs/ethics/authorizations/`).
- **Privacy:** local LLM only (frame); telemetry: none; scan artifacts stay on the user's machine.
- **License compliance:** `pip-licenses` allowlist gate in CI (§5.4); vendored fixtures carry upstream LICENSE + PROVENANCE; copyleft baselines run-only; repo is MIT with `LICENSE`, `NOTICE` (CryptoAPI-Bench attribution), and SPDX headers via ruff-format-compatible template.
- **Supply chain:** actions pinned to immutable tags (setup-uv v8 policy) or full SHAs; Renovate bot for bumps; `uv.lock` committed; PyPI trusted publishing (OIDC, zero long-lived tokens); GHCR images signed with cosign keyless (M3, nice-to-have).
- **Paper ethics:** plagiarism <10% (iThenticate via guide before submission); both students label E2 data independently with κ reported; all human-authored ground truth published with the artifact.

---

## 14. Documentation plan & Frame deviations

**Docs site** (mkdocs-material, GH Pages): Quickstart (install → scan → CBOM in 5 min) · User guide per subsystem (scan, risk, migrate, bridge, dashboard) · Demo runbook (4-phase, exact commands, expected outputs, screenshots) · Dev guide (WSL2 setup, workspace, testing, release) · API reference (mkdocstrings) + REST OpenAPI (FastAPI-generated) · Design docs 00–06 (this series) · Ethics page (§13 user-facing).

**README** contract (CI-smoked): badges (CI, PyPI, GHCR, docs, license) → 30-sec pitch + architecture diagram → `pip install qubit-cli` + `qubit scan .` → `docker compose up` demo → link to paper/preprint.

**Paper outline** (IEEE two-column, targets from live Annexure-1 list; ~10 pages): 1 Intro (HNDL, Mosca) · 2 Related work (CrySL/CogniCrypt/CryptoGuard, LLM-based detection, commercial PQC discovery, CBOM) · 3 System design (frame architecture) · 4 HNDL risk model (MC over Webber-et-al. hardware priors + Bayes + Mosca margin) · 5 LLM-assisted migration + verification gates · 6 Evaluation = E1–E4 (§9) · 7 Discussion/limitations (LLM nondeterminism, benchmark scope) · 8 Conclusion. Artifact appendix maps claims → `experiments/exp_N/`.

**Frame deviations:** none to the binding stack, layout, schema, or milestones. Additive extensions only: (1) top-level `tools/`, `experiments/`, `scripts/`, `tests/`, `.github/` directories; (2) dev-only workspace member `tools/qubit-eval` that is never published to PyPI; (3) refinement: hybrid TLS test/demo endpoints use stock OpenSSL ≥3.5 native `X25519MLKEM768` (oqs-provider self-disables ML-KEM/ML-DSA on ≥3.5 — it remains in the image for non-standardized algorithms), consistent with the frame's "liboqs + oqs-provider (OpenSSL 3.x)" line; (4) coverage gate applied to the three core packages exactly as framed, other packages measured-not-gated until M3.
