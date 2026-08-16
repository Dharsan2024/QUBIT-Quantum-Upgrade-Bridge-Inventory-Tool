# QUBIT — Project Status Report

**Report date:** 2026-08-15 · **Grounded at commit:** `4984bb5` (branch `main`)
*(Supersedes the 2026-08-09 / `b4c070c` edition. Several verdicts below were downgraded-to-done in the
interim: auth, packaging, test hygiene, and E1–E5 all shipped.)*
**Author:** QUBIT team (Dharsan L, Akshay Kumar S) · BE-CSE Cybersecurity final-year project
**Deadline (revised 2026-08-09):** **end of September 2026** — a hardened working *product* by Sep 30;
the research paper is deferred to after the deadline (see [BUILD_PLAN §5](../BUILD_PLAN.md)).
**Scope of this report:** how much is built, how production-ready it is, and what remains — measured
against the repo as it stands, not the plan's aspirations.

> **Honesty note.** Every number in this report was measured from the repository at `4984bb5`, not
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
- **Not production-hardened** means: there is no observability story (no structured logging, metrics or
  tracing), the CLI is not published to PyPI, the dashboard is functional but not polished, the ML tiers
  are opt-in, and three known non-blocking defects are open (§4).

Since the 2026-08-09 edition, four of the items that made up the "not hardened" verdict have closed:
**real token auth is built** (DB-backed sha256-hashed tokens, `ro`/`rw` scopes, revocation, global
method-based enforcement, `qubit serve token create|list|revoke`), **`docker compose up` is verified from
a clean slate** (~9 s to an authenticated stack), **the test suite has zero skips and zero failures**, and
**extended modules E1–E5 have all landed**.

Against the revised **Sep 30, 2026** deadline (product-first; paper deferred), it is **on track**: Phase 0,
M1, and M2 are complete and the Phase-3 hardening sprint is most of the way through its committed scope.

---

## 2. Measured scale (at `4984bb5`)

| Metric | Value | How measured |
|---|---|---|
| Python source (non-test) | **~15,360 LOC** across 135 files, 7 packages | `find packages -name '*.py' -not -path '*/tests/*'` |
| Python tests | **~5,362 LOC** across 48 files | `find packages -name 'test_*.py'` |
| Dashboard TypeScript/TSX | **~4,588 LOC** across 27 files | `find dashboard/src -name '*.ts*'` |
| Test result | **752 passed · 0 failed · 0 skipped** | `uv run pytest packages -q` |
| Coverage (3 core packages) | **82%** (gate: ≥70%) | `pytest --cov=qubit_core --cov=qubit_scanner --cov=qubit_risk` |
| Detection rules | **145** across 6 languages (python 39, go 29, java 21, js 23, ts 23, c 10) | `RuleCatalog.load()` |
| Canonical algorithms | **115** | `len(qubit_core.algorithms.ALGORITHMS)` |
| Alembic migrations | **4** (applied automatically at startup) | `alembic/versions/` |
| Packages | 7 (`qubit-{core,scanner,risk,migrate,bridge,api,cli}`) + `dashboard` | monorepo layout |
| Lint / format / types | **ruff clean, ruff-format clean, mypy clean** except 2 known pre-existing errors (§4) | frame CI gate |
| CI | **live** (`.github/workflows/ci.yml`: ruff + format + per-pkg mypy + pytest + dashboard build) | repo |

---

## 3. Completion by subsystem

Status legend: **built** = shipped + tested · **partial** = works but not fully surfaced/hardened ·
**planned** = designed, not yet built.

| Subsystem | Status | What's done | What's left |
|---|---|---|---|
| `qubit-core` (schema, DB, CBOM, registry, fingerprint) | **built** | Frozen `CryptoAsset` Pydantic v2 + SQLAlchemy ORM; CycloneDX 1.7 export; POSIX-normalized fingerprint; algorithm registry | CBOM *import* (M3 cut-line); Postgres path (cut-line) |
| `qubit-scanner` (discovery) | **built** | **Five real sources:** code AST (tree-sitter, segfault-pinned `<0.26` with regression test; 145 rules across Python/Go/Java/JS/TS/C, covering key use as well as key generation), config (**nginx, Apache, OpenSSH**), active TLS enumeration **+ a real raw-ClientHello PQC-group probe** (was a mock until 2026-08-15; now proven against a live OpenSSL 3.5 server), cert/key, **dependency/SCA manifests** (5 formats, version-aware capability gates), and an opt-in **HashiCorp Vault transit/PKI connector**. Evidence redaction; network-scan authorization guardrail + audit log | more language rule-packs and more curated SCA packages (breadth, ongoing) |
| `qubit-risk` (HNDL risk) | **built** (ML tiers opt-in) | Monte-Carlo CRQC timeline + expert-survey blend; closed-form P_HNDL + pgmpy Bayesian net (agree <0.02); XGBoost distillation regressor + split-conformal CI + TreeSHAP (**now runs in the default gate** — `xgboost` is in the `dev` group); DistilBERT sensitivity tier documented as an honest **negative result** → ship heuristic-only; **CNSA 2.0 milestone evaluator** (`cnsa2.py` + versioned params) | run the external-validation study with **real human rankings** (currently synthetic); expose CNSA 2.0 over REST (deliberately Python-only for now) |
| `qubit-migrate` (orchestrator) | **built** | Dependency graph + SCC order; risk÷effort WSJF queue; Ollama LLM transformer + repair loop + preservation guard + prompt-injection/path hardening; deterministic template codemods; **5-stage docker-sandbox validation**; FSM + review inbox. **9 transform rules** spanning config (nginx/Apache/OpenSSH), dependency manifests and code across 6 languages — matched on provenance, filename and suffix so a config codemod is never pointed at source. Rules mark a codemod `codemod_authoritative` where the correct output is a constant, so an LLM cannot displace the deterministic hybrid-PQC edit. **E1–E5 all landed:** migration KB (`migration_kb.yaml`, now incl. JWT `token`-context entries), agility policy, per-asset recommendation, graph API, governance gates | LLM-side rewrites for Go/Java/JS key exchange and signatures are still Python-only (breadth, ongoing) |
| `qubit-bridge` (hybrid PQC proof) | **built** | X25519MLKEM768 probe/verify against the nginx-hybrid demo bridge; `--canned` mode | `/bridge/measurements` bench chart (M3); the live e2e test needs docker host-networking (§4) |
| `qubit-api` (REST spine) | **built** | Projects/scans/assets CRUD + filters; risk + migration workflow endpoints + apply guardrails (`is_relative_to`); JobRunner + SSE + **crash recovery** (`recover_orphaned` sweep, kill-9 tested); Pydantic v2 `ConfigDict`; **real bearer-token auth** — DB-backed sha256-hashed tokens, `ro`/`rw` scopes enforced globally by HTTP method, revocation-aware, `GET /auth/whoami`, with the dev token surviving only as a self-disabling bootstrap | `/risk/simulate` what-if; 2 known defects (§4) |
| `qubit-cli` (`qubit`) | **built** | `scan/risk/migrate/cbom/project/db/serve/rules/bridge` (`plan` is `qubit migrate plan`); `demo run --all` chaining the software loop + bridge; `scan-network`; **`scan-vault`**; `serve token create\|list\|revoke`; `qubit risk eval`; UTF-8 console reconfigure | `--server` client mode (cut-line); PyPI publication (deferred) |
| `dashboard/` (React) | **partial** | Glassmorphism design system + shell; Inventory, Risk, Timeline (Mosca overlay), Migrations/diff review, CBOM, Scans/Jobs wired to real API + SSE | polish; deferred M2→M3 UI (sparklines, treemap, CBOM tree, trends/scan-diff); E1–E4 surfaces (doc 08) |

---

## 4. Test-suite honesty + known open defects

`uv run pytest packages -q` at `92f72fa`: **752 passed, 0 failed, 0 skipped.**

Both blemishes from the previous edition are closed:
- The **bridge e2e failure** is resolved — the test is now marked `@pytest.mark.integration` (so the
  default gate reflects logic health) and it **passes** when run explicitly with Docker available.
- The **`xgboost` skip** is resolved — `xgboost` and `scikit-learn` are now in the root `dev` dependency
  group, so the regressor test genuinely runs (including live training + a split-conformal coverage
  assertion) instead of skipping. This mattered: the project's zero-skip rule had been one silent skip
  short of true.

**Three integration tests require Docker** (`@pytest.mark.integration`, run via `uv run poe integ`):
the bridge hybrid-TLS probe, the raw-ClientHello PQC probe against `qubit-nginx-hybrid`, and the Vault
connector against a real `hashicorp/vault` dev server. All three pass. Without a Docker daemon they
skip cleanly rather than fail.

**Known open defects (3) — all pre-existing, none blocking, all tracked in
[BUILD_PLAN §Phase 3](../BUILD_PLAN.md):**
1. `qubit_api/services.py::run_scan()` stores the caller's requested `scanners` list on the scan row but
   calls `scan_paths(...)` **without** it — so the API's scanner selection is recorded and then silently
   ignored, and every API scan runs the default set. Related: the frozen `SourceScanner` enum has no
   `dependency` member, so the API cannot name the SCA source even though it runs by default.
2. `qubit_migrate/graph/order.py` has 2 mypy `union-attr` errors (`RiskAnnotation | None` → `.score`),
   confirmed pre-existing by reproducing them with all other changes stashed. These are the only 2 errors
   across 103 typed source files.
3. `POST /projects/{id}/scans` reports `status: "running"` even though M1 execution is synchronous, so an
   immediately-following asset read returns 0 before settling on the true count (reproduced on both an
   existing and a virgin database). Harmless for the dashboard, which polls, but misleading for any client
   that reads straight through.

Reporting these rather than rounding to "all green" is the point.

---

## 5. Milestone completion

| Milestone | Completion | Evidence |
|---|---|---|
| **Phase 0 — Foundation** | **100%** | uv monorepo, CI, frozen `CryptoAsset`, registry, fingerprint — all present and gating |
| **M1 — Walking skeleton** | **100%** | scan → DB + CBOM → dashboard → template patch → verified; `test_m2_acceptance.py` covers the through-line |
| **M2 — Feature-complete baseline** | **100%** | full software loop + bridge; `qubit demo run --all` chains it; kill-9 crash recovery tested (`test_crash_recovery.py`); 4-phase demo executable |
| **Phase 3 — Hardening sprint** (2026-08-09 → **2026-09-30 deadline**; product-first, paper deferred) | **~80% (in progress)** | **done:** external-validation scaffolding + `qubit risk eval`; CI + gitleaks/pre-commit; network-scan authorization guardrail; **real token auth** (tokens + `ro`/`rw` scopes + revocation); **extended modules E1–E5**; **`docker compose up` verified from a clean slate** (~9 s to an authenticated stack, full create→scan→CBOM flow); **test hygiene** (bridge e2e marked `integration`, `xgboost` in the gate, 419 pass / 0 skip, coverage 82%); **demo rehearsed** (`qubit demo run --all` → `PASS negotiated=X25519MLKEM768`); 3 external-repo integrations (SCA scanner, Vault connector, CNSA 2.0 + real PQC probe). **remaining for Sep 30:** PyPI publication, structured-logging story, README quickstart ✅(done), backup demo video (human task), the 3 defects in §4. **deferred post-deadline:** the paper, formal experiment suites, real-human-ranking validation, `/risk/simulate` |
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
| Test coverage & CI | **strong** | **82%** on core packages, **419 pass / 0 fail / 0 skip**, CI gating ruff+format+mypy+pytest+dashboard build; 3 Docker integration tests all passing |
| Reproducibility | **good** | engine versions + params recorded per run (frame N8); pinned Ollama image; LFS-tracked model; versioned params files hashed into each run |
| Authentication / multi-user | **good** | DB-backed sha256-hashed bearer tokens, `ro`/`rw` scopes enforced globally by HTTP method, revocable, `qubit serve token` lifecycle; dev token is a self-disabling bootstrap only |
| Packaging | **partial** | `docker compose up` verified from a clean slate (~9 s to authenticated stack); `pip install qubit-cli` not yet published to PyPI |
| Observability / ops | **absent** | no structured logging/metrics/tracing story yet |
| Dashboard UX | **functional, unpolished** | real data + SSE wired; deferred analytics UI + polish outstanding |
| ML robustness | **honest-partial** | XGBoost regressor real + conformal-calibrated; sensitivity DistilBERT shipped as a documented negative result (heuristic-only in the product path) |

**Bottom line:** safe and correct on the path that matters, now with real auth and a verified
one-command deployment; needs observability, PyPI packaging, and UI polish before an external org could
comfortably self-host it in production.

---

## 8. Improvements needed (prioritized, as of `d89eb66`)

1. **Fix the 3 known defects (§4)** — the ignored `scanners` list is the most consequential, since it
   makes an API parameter silently inert.
2. **Observability** — a minimal structured-logging story (request IDs through the API and JobRunner, and
   scan/risk/migrate run correlation). Currently entirely absent, and the last remaining "absent" rating.
3. **PyPI publication** — `pip install qubit-cli` from a clean clone. Deferred by plan, but it is the
   README's most visible unmet promise.
4. **Backup demo video** — demo-failure insurance for the committee. *Human task, cannot be automated.*
5. **`/risk/simulate` what-if endpoint** — user-driven Monte-Carlo params for the dashboard sliders
   (doc 02 `SimulateRequest`); paper-relevant sensitivity analysis.
6. **Run the external-validation study with real human rankings** — the Bradley-Terry + Spearman-ρ
   pipeline exists and currently runs on synthetic rankings; the paper needs the real-ranking ρ.
7. **Surface CNSA 2.0 over REST + the dashboard** — the evaluator is Python-only by deliberate scoping;
   a thin `GET /scans/{id}/cnsa2` wrapper is a small addition.
8. **Dashboard polish + deferred UI** — sparklines, risk treemap, CBOM JSON-tree viewer, trends +
   scan-diff pages, timeline PNG export.
9. **Breadth** — more detection rule-packs and more curated SCA packages. Pure data work, no code changes.

Items 1–4 are what stands between the current state and the Sep-30 acceptance bar; 5–9 are polish and
paper-track work that can absorb into the plan's cut-lines. None require redesign — the frozen schema and
the normative REST registry hold.

---

## 9. Cross-references

- Extended-module designs (E1–E5) + literature coverage map: [08-extended-modules.md](../design/08-extended-modules.md)
- Master plan + module-coverage table + E1–E5 scope: [BUILD_PLAN.md](../BUILD_PLAN.md)
- Binding frame (schema, stack, milestone cadence): [00-architecture-frame.md](../design/00-architecture-frame.md)
- Capacity + week-by-week timeline: [06-engineering-plan.md](../design/06-engineering-plan.md)
- This week's progress: [WEEKLY_REPORT.md](WEEKLY_REPORT.md)
