# QUBIT — Project Status Report

**Report date:** 2026-08-09 · **Grounded at commit:** `b4c070c` (branch `main`)
**Author:** QUBIT team (Dharsan L, Akshay Kumar S) · BE-CSE Cybersecurity final-year project
**Deadline (revised 2026-08-09):** **end of September 2026** — a hardened working *product* by Sep 30;
the research paper is deferred to after the deadline (see [BUILD_PLAN §5](../BUILD_PLAN.md)).
**Scope of this report:** how much is built, how production-ready it is, and what remains — measured
against the repo as it stands, not the plan's aspirations.

> **Honesty note.** Every number in this report was measured from the repository at `b4c070c`, not
> estimated. Where a capability is partial or a test is environment-dependent, this report says so
> plainly. The project's standing rule — *no vanity metrics* — applies to its own status report first.

---

## 1. Headline verdict

QUBIT is a **production-*grade*** codebase that is **not yet production-*hardened***.

- **Production-grade** means: the code is real (not mock/stub), typed, tested, CI-gated, and the flagship
  end-to-end story works — a classical TLS service is discovered, its HNDL risk is quantified with a real
  Monte-Carlo CRQC model, an LLM/template patch is generated and *safety-validated in a docker sandbox*,
  and the same service is re-proved negotiating the hybrid PQC group X25519MLKEM768 on a packet capture.
  A third party can add a detection rule as pure YAML and watch it flow through the pipeline.
- **Not production-hardened** means: authentication is a single dev token (real token+scope lifecycle is
  designed but not built), there is no packaging/observability story yet, the dashboard is functional but
  not polished, the ML tiers are opt-in, and one integration test only passes with docker host-networking
  configured (§4).

Against the revised **Sep 30, 2026** deadline (product-first; paper deferred), it is **on track**: Phase 0,
M1, and M2 are complete, so the working product already exists — the remaining ~7-week sprint only
*hardens* it (real auth, packaging, `docker compose up`, extended modules E1–E5, demo-readiness).

---

## 2. Measured scale (at `b4c070c`)

| Metric | Value | How measured |
|---|---|---|
| Python source (non-test) | **~12,451 LOC** across 116 files, 7 packages | `find packages -name '*.py' -not -path '*/tests/*'` |
| Dashboard TypeScript/TSX | **~2,545 LOC** | `find dashboard/src -name '*.ts*'` |
| Test functions | **196** (expand to **272** collected cases via parametrization) | `pytest --collect-only` |
| Test result | **271 passed · 1 skipped · 1 failed** (the fail is a docker-networking env issue, §4) | `uv run pytest packages -q` |
| Packages | 7 (`qubit-{core,scanner,risk,migrate,bridge,api,cli}`) | monorepo layout |
| Lint / types | **ruff clean, mypy clean** (per-package config, qubit-core strict) | frame CI gate |
| CI | **live** (`.github/workflows/ci.yml`: ruff + format + per-pkg mypy + pytest + dashboard build) | repo |

---

## 3. Completion by subsystem

Status legend: **built** = shipped + tested · **partial** = works but not fully surfaced/hardened ·
**planned** = designed, not yet built.

| Subsystem | Status | What's done | What's left |
|---|---|---|---|
| `qubit-core` (schema, DB, CBOM, registry, fingerprint) | **built** | Frozen `CryptoAsset` Pydantic v2 + SQLAlchemy ORM; CycloneDX 1.7 export; POSIX-normalized fingerprint; algorithm registry | CBOM *import* (M3 cut-line); Postgres path (cut-line) |
| `qubit-scanner` (discovery) | **built** | Code AST (tree-sitter, segfault-pinned `<0.26` with regression test), config, active TLS enumeration + PQC-group probe, cert/key, evidence redaction; network-scan authorization guardrail + audit log | more language rule-packs (breadth, ongoing) |
| `qubit-risk` (HNDL risk) | **built** (ML tiers opt-in) | Monte-Carlo CRQC timeline + expert-survey blend; closed-form P_HNDL + pgmpy Bayesian net (agree <0.02); XGBoost distillation regressor + split-conformal CI + TreeSHAP; DistilBERT sensitivity tier documented as an honest **negative result** → ship heuristic-only | run the external-validation study with **real human rankings** (currently synthetic); XGBoost needs its dep installed in eval env |
| `qubit-migrate` (orchestrator) | **built** | Dependency graph + SCC order; risk÷effort WSJF queue; Ollama LLM transformer + repair loop + prompt-injection/path hardening; deterministic template codemods; **5-stage docker-sandbox validation**; FSM + review inbox | surface the graph (**E3**); recommendation read model (**E1**); agility policy (**E2**); governance gates (**E4**); KB consolidation (**E5**) — all doc 08 |
| `qubit-bridge` (hybrid PQC proof) | **built** | X25519MLKEM768 probe/verify against the nginx-hybrid demo bridge; `--canned` mode | `/bridge/measurements` bench chart (M3); the live e2e test needs docker host-networking (§4) |
| `qubit-api` (REST spine) | **built** (auth partial) | Projects/scans/assets CRUD + filters; risk + migration workflow endpoints + apply guardrails (`is_relative_to`); JobRunner + SSE + **crash recovery** (`recover_orphaned` sweep, kill-9 tested); Pydantic v2 `ConfigDict` | **real token auth (tokens + scopes)** — currently single dev token; `/risk/simulate` what-if; the E1–E5 endpoints (doc 08) |
| `qubit-cli` (`qubit`) | **built** | `scan/risk/plan/migrate/cbom/project/jobs/db/serve`; `demo run --all` chaining the software loop + bridge; `scan-network`; `qubit risk eval`; UTF-8 console reconfigure | `--server` client mode (cut-line) |
| `dashboard/` (React) | **partial** | Glassmorphism design system + shell; Inventory, Risk, Timeline (Mosca overlay), Migrations/diff review, CBOM, Scans/Jobs wired to real API + SSE | polish; deferred M2→M3 UI (sparklines, treemap, CBOM tree, trends/scan-diff); E1–E4 surfaces (doc 08) |

---

## 4. Test-suite honesty (the 1 failure + 1 skip)

`uv run pytest packages -q` at `b4c070c`: **271 passed, 1 skipped, 1 failed.**

- **Skipped (1):** `test_regressor.py` skips because `xgboost` is not importable in the current
  environment. The regressor code and its tests are real; the dep is simply not installed in this eval
  environment. Installing `xgboost` un-skips it.
- **Failed (1):** `qubit-bridge/tests/test_e2e.py::test_nginx_hybrid_tls_probe`. This is **not a code
  regression** — the nginx-hybrid container starts correctly (it generates its cert and serves), but the
  probe (which runs inside its *own* docker container) cannot reach `host.docker.internal` within the
  10 s timeout under this machine's WSL2 docker networking. It is a real integration test that needs
  docker host-networking configured; it is currently **not** marked `@pytest.mark.integration`, which is
  why it runs in the default suite. **Recommended fix (tracked):** mark it `integration` (or gate it on a
  reachability pre-check) so the default gate reflects unit/e2e-logic health, and run it explicitly in the
  integration CI job where host-networking is provisioned.

Reporting these rather than rounding to "272 pass" is the point — the failure is environmental, and the
report says exactly why.

---

## 5. Milestone completion

| Milestone | Completion | Evidence |
|---|---|---|
| **Phase 0 — Foundation** | **100%** | uv monorepo, CI, frozen `CryptoAsset`, registry, fingerprint — all present and gating |
| **M1 — Walking skeleton** | **100%** | scan → DB + CBOM → dashboard → template patch → verified; `test_m2_acceptance.py` covers the through-line |
| **M2 — Feature-complete baseline** | **100%** | full software loop + bridge; `qubit demo run --all` chains it; kill-9 crash recovery tested (`test_crash_recovery.py`); 4-phase demo executable |
| **Phase 3 — Hardening sprint** (2026-08-09 → **2026-09-30 deadline**; product-first, paper deferred) | **~35% (in progress)** | **done:** external-validation study scaffolding + `qubit risk eval` CLI, CI + gitleaks/pre-commit, network-scan authorization guardrail, coverage boost to ~73.7%. **remaining for Sep 30:** real token auth, extended modules E1–E5 (doc 08), packaging + `docker compose up` on a clean machine, test-hygiene (mark bridge e2e `integration`, add `xgboost`), demo-readiness. **deferred post-deadline:** the paper, formal experiment suites, real-human-ranking validation, `/risk/simulate` |
| **Paper + defence track** | deferred (post Sep-30 deadline) | paper, thesis chapters, viva prep — resume after the product ships |

---

## 6. Literature-module coverage (survey Table → QUBIT status)

Mirrors [BUILD_PLAN §4.1](../BUILD_PLAN.md) and [doc 08 §1](../design/08-extended-modules.md); repeated here as the
report's coverage verdict.

- **Built + tested (8):** M1 discovery, M2 CBOM, M3 quantum-risk, M4 HNDL, M8 remediation, M9 patch
  validation, M10 hybrid runtime proof, M12 prioritization.
- **Exists internally, not surfaced (→ E1–E5, doc 08):** M5 dependency graph (**E3**), M6 governance
  (**E4**), M7 crypto agility (**E2**), per-asset recommendation (**E1**), migration KB (**E5**).
- **Deliberate non-goal (1):** M11 embedded/ARM PQC implementation — QUBIT is a software-migration
  platform, not a hardware crypto-implementation project (doc 08 §3).

**Coverage verdict:** QUBIT already delivers two-thirds of the surveyed field as shipped code, and the
remaining third is *surfacing* work over capabilities it already computes — not new research. This is the
concrete basis for the paper's "unified platform" positioning.

---

## 7. Production-readiness assessment

| Dimension | Rating | Detail |
|---|---|---|
| Correctness of core pipeline | **strong** | end-to-end through-line works and is acceptance-tested; risk math cross-validated (Bayesian net vs closed-form <0.02) |
| Safety of automated changes | **strong** | a bad patch cannot merge — 5-stage docker-sandbox validation + mandatory human review + path-traversal-guarded apply |
| Test coverage & CI | **good** | ~73.7% on core packages, CI gating ruff+mypy+pytest+dashboard build; one integration test needs env config (§4) |
| Reproducibility | **good** | engine versions + params recorded per run (frame N8); pinned Ollama image; LFS-tracked model |
| Authentication / multi-user | **weak (dev-grade)** | single dev token; real token+scope lifecycle designed (doc 05 §6.6) but not built |
| Observability / ops | **absent** | no structured logging/metrics/tracing story yet; no packaging beyond source run |
| Dashboard UX | **functional, unpolished** | real data + SSE wired; deferred analytics UI + polish outstanding |
| ML robustness | **honest-partial** | XGBoost regressor real + conformal-calibrated; sensitivity DistilBERT shipped as a documented negative result (heuristic-only in the product path) |

**Bottom line:** safe and correct on the path that matters; needs auth, packaging/observability, and UI
polish before it is something an external org could self-host in production.

---

## 8. Improvements needed (prioritized)

1. **Real authentication** — token + scope lifecycle (`qubit serve token`, `ro`/`rw`, hashed store),
   replacing the single dev token. *Highest security-hardening leverage.*
2. **`/risk/simulate` what-if endpoint** — user-driven Monte-Carlo params for the dashboard sliders
   (doc 02 `SimulateRequest`); paper-relevant sensitivity analysis.
3. **Extended modules E1–E5** (doc 08) — surface the recommendation, agility policy, dependency graph,
   governance gates, and migration KB. All additive, all reuse existing code; closes the literature
   coverage gap.
4. **Run the external-validation study with real human rankings** — the Bradley-Terry + Spearman-ρ
   pipeline exists and currently runs on synthetic rankings; the paper needs the real-ranking ρ.
5. **Fix the e2e test classification (§4)** — mark the bridge probe test `integration` (or add a
   reachability pre-check) so the default gate reflects logic health.
6. **Packaging + observability** — `pip install qubit-cli` from a clean clone, `docker compose up` full
   stack verified on a fresh machine, and a minimal structured-logging/metrics story.
7. **Dashboard polish + deferred UI** — sparklines, risk treemap, CBOM JSON-tree viewer, trends +
   scan-diff pages, timeline PNG export.
8. **Install `xgboost` in CI eval env** so the regressor test runs in the default gate rather than skips.

Items 1–4 are the substance of remaining M3; 5–8 are hardening/polish that can absorb into M3/M4 under
the plan's cut-lines. None require redesign — the frozen schema and the normative REST registry hold.

---

## 9. Cross-references

- Extended-module designs (E1–E5) + literature coverage map: [08-extended-modules.md](../design/08-extended-modules.md)
- Master plan + module-coverage table + E1–E5 scope: [BUILD_PLAN.md](../BUILD_PLAN.md)
- Binding frame (schema, stack, milestone cadence): [00-architecture-frame.md](../design/00-architecture-frame.md)
- Capacity + week-by-week timeline: [06-engineering-plan.md](../design/06-engineering-plan.md)
- This week's progress: [WEEKLY_REPORT.md](WEEKLY_REPORT.md)
