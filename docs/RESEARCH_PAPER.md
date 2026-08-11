# QUBIT: A Unified Platform for Harvest-Now-Decrypt-Later Risk Modeling and Automated Post-Quantum Cryptographic Migration

**A research-paper manuscript (draft).**
Authors: Dharsan L (43614012), Akshay Kumar S (43614004)
Guide: Dr. P. Shanmuga Prabha · BE-CSE (Cybersecurity), Batch 2023–2027
Artifact commit: `7de4756` · Grounded metrics measured from the repository, not estimated.

> **Honesty note for the authors (delete before submission).** Every quantitative claim below is
> tagged as **[measured]** (from the running system/tests), **[modeled]** (a deliberate statistical
> simulation, scientifically the correct approach for an event that has not occurred), or
> **[future work]** (designed, not yet evaluated with external baselines). Do not present modeled or
> future-work numbers as measured empirical results in the viva. The evaluation suites (§7) are the
> honest gap: the harness exists but the external-baseline study has not been run.

---

## Abstract

The migration of the world's deployed cryptography to post-quantum (PQC) standards is a decade-scale
undertaking, made urgent by the **Harvest-Now-Decrypt-Later (HNDL)** threat: an adversary records
encrypted data today and decrypts it once a Cryptographically-Relevant Quantum Computer (CRQC)
exists. Existing tooling addresses fragments of the problem — cryptographic discovery, or a
Cryptographic Bill of Materials (CBOM), or code transformation — but no single system connects
*discovery → risk quantification → automated, verified remediation → runtime proof*. We present
**QUBIT**, an offline, open-source platform that unifies this pipeline. QUBIT (1) discovers an
organization's cryptographic assets *and its broader HNDL exposure surface* (hardcoded secrets,
keys, tokens, and PII) via AST- and pattern-based scanning; (2) quantifies each asset's HNDL risk by
fusing a Monte-Carlo simulation of CRQC arrival (from published hardware resource estimates) with a
data-shelf-life model, per **Mosca's inequality**; (3) generates and *safety-validates* code patches
to NIST PQC algorithms (ML-KEM, ML-DSA) using a local LLM with deterministic template fallbacks, in
a sandbox where a failing patch can never merge; and (4) proves the migration on the wire by
standing up a hybrid classical+PQC TLS terminator (X25519MLKEM768) and re-capturing the handshake.
The system is realized as a 7-package Python monorepo (~14.1k LOC) with a React/TypeScript dashboard
(~2.9k LOC) and a native desktop application, exercised by 331 automated tests. QUBIT's contribution
is the **synthesis**: a continuous, calibrated HNDL score computed over a programmatically-discovered
inventory, wired to a verification-gated remediation loop and an on-wire proof — packaged so that a
practitioner can run the whole loop offline on a laptop.

**Keywords:** post-quantum cryptography, harvest-now-decrypt-later, cryptographic inventory, CBOM,
Mosca inequality, automated migration, ML-KEM, ML-DSA, crypto-agility.

---

## 1. Introduction

### 1.1 Motivation

NIST finalized the first PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) in 2024,
and standards bodies now recommend beginning migration immediately. The driving urgency is not that a
CRQC exists today — it does not — but the **HNDL** adversary model: data with a long secrecy
shelf-life (health records, financial data, state secrets, long-lived credentials) that is encrypted
with quantum-vulnerable algorithms and transmitted or stored today can be *harvested now and
decrypted later*. The decision of what to migrate first is therefore a **risk-prioritization**
problem governed by **Mosca's inequality**: if `X` (data shelf-life) + `Y` (migration time) > `Z`
(time until a CRQC arrives), the data is already effectively compromised.

### 1.2 The gap

Practitioners face a fragmented toolchain. Cryptographic *discovery* tools find algorithm usages but
do not quantify risk. *CBOM* generators produce compliance artifacts but do not remediate.
*Code-transformation* research demonstrates LLM-assisted rewriting but without a safety gate or a
runtime proof. No open system connects all four stages into one calibrated, reproducible loop, and
none frames the problem around the *full HNDL exposure surface* rather than crypto algorithms alone.

### 1.3 Contributions

1. **A unified, offline pipeline** — discovery → HNDL risk → verified remediation → on-wire proof —
   in a single reproducible artifact (§4–§6).
2. **An HNDL exposure-surface model** that broadens discovery beyond crypto algorithms to the
   secrets, keys, tokens, and PII an HNDL adversary actually harvests, each annotated with an
   exploit narrative (§4.2). *[measured — implemented and tested]*
3. **A fused, calibrated HNDL risk score**: a Monte-Carlo CRQC-arrival simulation (surface-code
   resource model, expert-survey blend) combined with a Bayesian/closed-form data-exposure model and
   an XGBoost distillation regressor with split-conformal confidence intervals (§5). *[modeled]*
4. **A safety-gated migration loop**: local-LLM + deterministic template patch generation, validated
   in a sandbox (apply → parse → compile → re-scan) so an unsafe patch cannot be accepted (§6).
   *[measured — pipeline runs; patch-quality study is future work]*
5. **A runtime proof of migration**: a hybrid TLS terminator negotiating X25519MLKEM768, verified by
   handshake capture on the same service/port before and after (§6.3). *[measured]*

---

## 2. Threat Model and Background

**Adversary.** A passive HNDL adversary with (a) the ability to record ciphertext in transit or
exfiltrate encrypted data at rest today, and (b) access to a CRQC at some future time `Z`. Shor's
algorithm breaks RSA/ECC (asymmetric) once a CRQC of sufficient logical-qubit count and low error
rate exists; Grover's algorithm halves the effective security of symmetric primitives (mitigated by
doubling key sizes). QUBIT does **not** assume an active attacker or model implementation-level
side-channels.

**Mosca's inequality.** For each asset, QUBIT estimates the *Mosca margin* `Z − (X + Y)` (years). A
negative margin means the data's secrecy requirement outlives the crypto — it is already HNDL-
compromised. This margin is the backbone of prioritization.

**CRQC arrival is modeled, not measured.** No CRQC exists, so `Z` cannot be observed. QUBIT models it
as a probability distribution via Monte-Carlo simulation over published hardware resource estimates
(Webber et al.; Gidney & Ekerå), blended with an expert-survey log-normal CDF (Global Risk Institute
quantum-threat timeline). This is the scientifically correct treatment of an unrealized event and is
labeled as a simulation throughout the system and this paper.

---

## 3. System Overview

QUBIT is a `uv`-managed Python 3.12 monorepo of seven packages, plus a React 18/TypeScript dashboard
and a Tauri native desktop app. Modules communicate only through a shared, frozen `CryptoAsset`
schema, a SQLite/Postgres database, and a normative REST API — no private cross-package imports.

| Package | Responsibility |
|---|---|
| `qubit-core` | Binding `CryptoAsset` Pydantic + SQLAlchemy schema, algorithm registry, fingerprinting, CycloneDX 1.7 CBOM export |
| `qubit-scanner` | Discovery: code (tree-sitter AST), config, network TLS, cert/key, **and the HNDL secret/PII pass** |
| `qubit-risk` | HNDL risk engine: Monte-Carlo CRQC timeline, Bayesian net, XGBoost regressor, Mosca margin |
| `qubit-migrate` | Dependency graph, priority queue, local-LLM + template transforms, sandbox validation, state machine |
| `qubit-bridge` | Hybrid PQC TLS terminator, probe/verify/capture |
| `qubit-api` | FastAPI REST spine, job runner, SSE, token auth |
| `qubit-cli` | `qubit` command tree incl. the one-command `qubit run` |

**Scale (measured at `7de4756`):** ~14,149 lines of Python (non-test) across 7 packages;
~2,915 lines of dashboard TypeScript; **331 automated tests**; ruff + mypy clean; CI on GitHub
Actions. Fully offline — a local LLM (Ollama), no cloud calls, no telemetry, MIT-licensed.

---

## 4. Discovery: The HNDL Exposure Surface

### 4.1 Cryptographic discovery

The code scanner parses source with **tree-sitter** and matches a YAML rule catalog (Python, Java,
Go) against the AST, emitting a `Detection` per finding that is normalized against a canonical
algorithm registry (name, family, key size, quantum-vulnerability verdict, PQC replacement). Config
files (nginx TLS), certificates/keys, and live TLS endpoints (active handshake enumeration with PQC-
group probing) are scanned by dedicated modules. Every asset carries redacted evidence
(±5 lines + `file:line`) and a stable cross-scan **fingerprint** (POSIX-normalized, casefolded) so
posture trends and remediation deltas are queryable.

### 4.2 Broadening to the HNDL exposure surface *(contribution)*

A crypto-only view understates HNDL risk: the threat is not merely *weak algorithms* but everything
weak/eventually-decryptable crypto protects. QUBIT therefore adds a **secret/PII detection pass**
(`qubit_scanner.secrets`) — a high-precision regex scan over source and config text — detecting:

- **Secrets:** AWS/GitHub/Slack/Google/Stripe keys, JSON Web Tokens, PEM private-key blocks,
  hardcoded passwords/API keys.
- **Sensitive data (PII):** email addresses, credit-card numbers, US SSNs.

Placeholders and example values are filtered to preserve precision (a noisy secret scanner is worse
than none). Each finding is classified with the additive `AssetType.secret` / `sensitive_data` and
annotated with a **per-finding HNDL exploit narrative**: what the adversary harvests now and how it
is exploited after a CRQC arrives (e.g. a long-lived credential grants direct replay access with no
crypto-break needed; long-shelf-life PII is exactly what HNDL targets). *[measured — implemented,
five dedicated tests, verified end-to-end through the desktop app.]*

### 4.3 Output artifact

The database is the source of truth; the exportable compliance artifact is a **CycloneDX 1.7
Cryptographic Bill of Materials** validated against the ECMA-424 schema.

---

## 5. Risk Quantification

QUBIT computes a per-asset HNDL risk in `[0, 1]` with a calibrated confidence interval.

1. **CRQC-arrival timeline (`Z`).** A Monte-Carlo simulation (default 10k+ trials) over a surface-
   code resource model of when a CRQC capable of running Shor against a given key size arrives,
   producing a CDF `P(CRQC ≤ year)`. This is optionally **blended** with an expert-survey log-normal
   CDF via a Bradley-Terry-adjacent consensus. Anchor-tested against Webber/Gidney figures. *[modeled]*
2. **Data exposure (`X`, harvest/decrypt probability).** A closed-form `P_HNDL` integral
   (Gauss-Legendre) that agrees with an independent 5-node **Bayesian network** (pgmpy) to within
   <0.02 — a cross-validation of the two formulations. *[modeled, internally cross-validated]*
3. **Mosca margin.** `Z_median − (X_shelf_life + Y_migration)` per asset, negative ⇒ already
   compromised.
4. **Calibrated score.** An **XGBoost** distillation regressor over a 34-dimensional feature vector
   (frozen order), wrapped in **split-conformal** prediction for a distribution-free CI, with
   TreeSHAP feature attributions surfaced in the UI. *[modeled]*

**Honest negative result.** A DistilBERT sensitivity classifier trained on synthetic snippets
achieved near-perfect held-out accuracy but only ~2.8% agreement on real code (template
memorization, not transfer). It is documented as a negative result and the product ships the
transparent heuristic classifier instead — an explicit choice to not over-claim.

---

## 6. Automated, Verified Migration

### 6.1 Ordering

A directed dependency graph over discovered assets (key-generation before use, shared certificates
migrate together, library upgrades first) is condensed over strongly-connected components into atomic
*migration units* and topologically ordered; work is scheduled by **risk ÷ effort** (WSJF) within the
ready frontier.

### 6.2 Generation and the safety gate *(contribution)*

Patches are generated either by a **local LLM** (Ollama, `qwen2.5-coder`) using structured-output
edits — QUBIT computes the unified diff itself, never trusting LLM line numbers — or by
**deterministic `libcst`/template transforms** that require no GPU. Every candidate passes a
sandboxed pipeline (`apply → parse → compile → re-scan proves the legacy asset is gone and a PQC
asset is present`) inside a network-disabled Docker container; **a patch that fails any stage cannot
be accepted**, and human approval is mandatory. This makes *safety* the claim, independent of LLM
success rate. *[measured — verified live: an RSA-2048 → ML-KEM-768 hybrid patch was LLM-generated and
passed parse/compile/re-scan validation, reaching `proposed` status.]*

### 6.3 Runtime proof

`qubit-bridge` stands up a hybrid TLS terminator on the same port a classical service used, and
`qubit bridge verify` confirms the negotiated group is **X25519MLKEM768** (TLS 1.3). *[measured —
verified: `bridge verify --expect X25519MLKEM768` returns PASS against the live hybrid nginx.]*

---

## 7. Evaluation (Design + Honest Status)

The evaluation is designed as four suites; the harness exists, but the **external-baseline study has
not yet been run** — this is the primary honest gap before submission.

| Suite | Question | Method | Status |
|---|---|---|---|
| E1 Discovery | Precision/recall/F1 vs. baselines (CryptoGuard, CogniCrypt) | Labeled corpus + ablation | *[future work]* |
| E2 Risk calibration | Are the CIs well-calibrated? Does ranking match expert consensus? | Split-conformal coverage; Spearman ρ vs. human rankings | Harness built; needs **real human rankings** *[future work]* |
| E3 Patch quality | LLM patch pass@k, template success rate | Sandbox validation over a rule/fixture set | *[future work]* |
| E4 Handshake overhead | Hybrid vs. classical handshake cost | pcap-timestamp + `tc netem` | *[future work]* |

**What *is* measured today:** the system's functional correctness — 331 automated tests pass (ruff +
mypy clean); the end-to-end loop runs live (scan → risk → migrate → hybrid re-capture); the Bayesian
net agrees with the closed-form integral to <0.02; split-conformal produced ~90.5% coverage on the
synthetic validation set. These are integration/consistency results, **not** the comparative
empirical evaluation E1–E4 will provide.

---

## 8. Implementation Notes

- **Offline & reproducible:** local Ollama, pinned dependencies, engine versions recorded per run.
- **Deployment:** `docker compose up`, `pip install qubit-cli`, and a native **Tauri** desktop app
  (Windows) that runs the engine locally — so it can scan host filesystem paths and clone git repos —
  with a macOS-style interface.
- **Safety of the tool itself:** network-scan authorization guardrails (RFC1918/allowlist + audit
  log); diff-apply confined to registered project roots (`is_relative_to` traversal guard);
  hashed-token API auth.

---

## 9. Limitations and Threats to Validity

1. **The evaluation gap (§7).** Comparative P/R/F1, calibration, and pass@k against external
   baselines are not yet measured. Present them as planned, not achieved.
2. **CRQC timeline is a model.** All `Z`-derived numbers are simulation outputs conditioned on
   published hardware estimates; they are not forecasts to be trusted as fact.
3. **Detection recall is bounded** by the rule catalog and regex patterns; the secret/PII pass trades
   recall for precision and will miss obfuscated secrets.
4. **LLM patch success is variable** and hardware-dependent; the honest claim is *safety* (the gate),
   not a headline success rate.
5. **Single-machine scope.** Auth is a dev-grade token; multi-tenant hardening, packaging, and
   observability are future work.

---

## 10. Conclusion

QUBIT demonstrates that the fragmented PQC-migration toolchain can be unified into one offline,
reproducible loop that a practitioner runs on a laptop: it discovers the full HNDL exposure surface,
quantifies risk with a calibrated CRQC-arrival model under Mosca's inequality, generates and
*safety-validates* PQC patches, and proves the migration on the wire. The synthesis — not any single
stage — is the contribution. The clear next step is the external-baseline evaluation (E1–E4) that
converts the system's demonstrated functionality into comparative empirical evidence.

---

## Appendix A — Reproducibility

- Artifact: the QUBIT monorepo at commit `7de4756`; MIT-licensed; offline.
- One-command demo: `uv run qubit run <path|git-url>` (scan → risk → migrate) or
  `qubit demo run --all` (adds the hybrid-bridge loop).
- Gate: `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q`.
- Design specification: `docs/design/00`–`08` (architecture, discovery, risk, migration, bridge,
  platform, engineering plan, ecosystem fact-check, extended modules).

## Appendix B — Suggested venues

Annexure-I / SCOPUS-indexed security or software-engineering venues. Frame the submission around the
synthesis and the HNDL exposure-surface model; complete E1–E4 first so the evaluation section carries
comparative numbers.

## Appendix C — Figure list to generate for the camera-ready

1. Architecture diagram (the 7 packages + data flow) — from §3.
2. The CRQC-arrival CDF with P05/P50/P95 markers — screenshot from the CRQC Timeline page.
3. A risk-scored inventory table incl. HNDL secret/PII findings — from the Inventory page.
4. A before/after re-scan proving an asset was remediated — from `qubit run`.
5. The hybrid handshake capture (classical vs. X25519MLKEM768) — from the bridge.
