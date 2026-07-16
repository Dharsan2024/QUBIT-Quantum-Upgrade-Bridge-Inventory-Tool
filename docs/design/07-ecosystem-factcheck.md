# 07 — PQC Ecosystem Fact-Check (July 2026)

Research snapshot of the post-quantum cryptography tooling ecosystem relevant to QUBIT.
All facts web-verified 2026-07-15. Version numbers and dates are exact where the source
stated them; approximations are flagged.

---

## 1. NIST PQC Standards Status

| Standard | Algorithm | Status | Date |
|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | **Final** | Published 2024-08-13 |
| FIPS 204 | ML-DSA (Dilithium) | **Final** | Published 2024-08-13 |
| FIPS 205 | SLH-DSA (SPHINCS+) | **Final** | Published 2024-08-13 |
| FIPS 206 | FN-DSA (Falcon) | **Draft in approval** — Initial Public Draft submitted for approval 2025-08-28; final expected late 2026 / early 2027 | In review |
| (HQC FIPS, number TBD) | HQC | **Selected 2025-03-11** (NIST IR 8545, 4th-round winner). Draft FIPS expected 2026 (not yet published as of the NIST PQC project page update of 2026-06-16); final expected 2027 | Pending |

- HQC is the code-based (non-lattice) backup KEM to ML-KEM.
- Implication for QUBIT: ML-KEM/ML-DSA/SLH-DSA are safe migration targets today; HQC and FN-DSA should be modeled as "coming 2027" alternatives, not current targets.

Sources: [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization), [NIST HQC announcement](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption), [Federal Register FIPS 203/204/205](https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based), [DigiCert on FIPS 206](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist)

## 2. liboqs / oqs-provider / native OpenSSL

- **liboqs 0.16.0** released **2026-07-09** (0.16.0-rc1 2026-06-24; 0.15.0 was 2025-11-14). 0.16.0: mldsa-native becomes default ML-DSA backend, HQC updated to the 2025 spec and enabled by default, SPHINCS+ removed in favor of SLH-DSA, MQOM added; 0.15.0 removed Dilithium, integrated pq-code-package SLH-DSA.
- **oqs-provider 0.11.0** (released 2025-12, tracks liboqs 0.15.0) is the latest. Critically, oqs-provider now **auto-disables any algorithm that OpenSSL >= 3.5 implements natively** (ML-KEM, ML-DSA, SLH-DSA and standardized hybrids) and its README explicitly positions it as "a vehicle to enable testing of experimental PQ crypto," with no intention of duplicating production-quality PQC in OpenSSL's default provider.
- **OpenSSL 3.5.0 (LTS, released 2025-04-08, supported to 2030)** ships **native ML-KEM, ML-DSA, SLH-DSA** and enables **X25519MLKEM768 as a default TLS key-share**. OpenSSL 3.6 (Oct 2025) added LMS verification; composite-certificate verification remains a 2026 gap.
- **liboqs-python 0.15.0** (PyPI upload 2026-05-15, Python >= 3.10, MIT) — actively maintained by Open Quantum Safe / PQCA.
- **Verdict: oqs-provider is no longer needed for standard hybrid TLS.** OpenSSL 3.5+ does it natively and by default. oqs-provider remains useful only for non-standardized/experimental algorithms (e.g., FrodoKEM, HQC-in-TLS, exotic hybrids). QUBIT recommendations should target native OpenSSL 3.5+.

Sources: [liboqs releases](https://github.com/open-quantum-safe/liboqs/releases), [oqs-provider](https://github.com/open-quantum-safe/oqs-provider), [OpenSSL 3.5 notes](https://openssl-library.org/news/openssl-3.5-notes/), [liboqs-python PyPI](https://pypi.org/project/liboqs-python/), [OpenSSL 3.6 / LMS](https://linuxiac.com/openssl-3-6-released-with-new-fips-lms-signatures/)

## 3. Hybrid TLS: X25519MLKEM768

- **IETF status:** `draft-ietf-tls-ecdhe-mlkem` — Standards Track, at **draft -05 (updated 2026-05-26)**; not yet an RFC. Defines X25519MLKEM768 (group 0x11EC), SecP256r1MLKEM768, SecP384r1MLKEM1024. The generic framework `draft-ietf-tls-hybrid-design` is at -16.
- **Interoperating today (default-on):**
  - OpenSSL 3.5+ (default key-share), BoringSSL (ML-KEM since Sept 2024), Go crypto/tls (default since **Go 1.24**).
  - Chrome: default since **Chrome 131** (desktop; replaced draft X25519Kyber768Draft00 codepoint 0x6399). Firefox: default since ~132 (both default-on as of Aug 2025). Safari: PQC only from **iOS 26 / macOS Tahoe 26** (fall 2025).
  - nginx: works when built against OpenSSL 3.5+ (config: `ssl_ecdh_curve`); NGINX Plus R33 supports final ML-KEM-768 (manual enable). Cloudflare, Akamai, AWS terminate it at the edge.
- Implication: hybrid X25519MLKEM768 is the de-facto production baseline QUBIT should test for; it is deployable end-to-end without oqs-provider.

Sources: [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/), [Chrome Platform Status](https://chromestatus.com/feature/5257822742249472), [Cloudflare PQC support](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/), [F5 Labs state of PQC](https://www.f5.com/labs/articles/the-state-of-pqc-on-the-web)

## 4. CycloneDX 1.7 CBOM

- **CycloneDX v1.7 released October 2025**; adopted as **ECMA-424 2nd Edition, December 2025**. Last of the 1.x line, backward compatible to 1.4. CBOM upgrades in 1.7: standardized cryptographic algorithm-family list, comprehensive elliptic-curve list, expanded crypto transparency for PQC-readiness assessment. (CBOM itself first landed in 1.6, June 2024.)
- **cyclonedx-python-lib**: latest **11.11.0 (2026-06-17)**. Spec 1.7 support added in **11.4.0 (2025-10-23)**; 11.11.0 added 1.7 crypto-primitive/protocol enum cases. Crypto model (`cyclonedx.model.crypto`) present since 8.x — Python CBOM generation is fully viable.
- **CBOMkit**: migrated from IBM to the **PQCA `cbomkit` org**; latest **v2.2.0 (2026-02-05)**. Scans Java (JCA, BouncyCastle), Python (pyca/cryptography), Go (stdlib crypto + x/crypto) via the sonar-cryptography engine.
- **sonar-cryptography** (CBOMkit-hyperion): active under cbomkit org; **v1.4.8 (2025-11-06)** added ML-KEM/ML-DSA detection; C/C++ support via sonar-cxx in progress (issue #374, targeting ~90% of OpenSSL 3.6 crypto assets).
- **cdxgen**: **v12.1.4 (March 2026)**; `cbom` alias generates CBOMs (requires spec >= 1.6); crypto detection for Java and Python projects plus JS/TS via lightweight constant propagation through node:crypto/WebCrypto/JWT call sites, keystores, certificates.

Sources: [CycloneDX 1.7 release](https://cyclonedx.org/news/cyclonedx-v1.7-released/), [ECMA-424](https://ecma-international.org/publications-and-standards/standards/ecma-424/), [cyclonedx-python-lib changelog](https://github.com/CycloneDX/cyclonedx-python-lib/blob/main/CHANGELOG.md), [cbomkit](https://github.com/cbomkit/cbomkit), [sonar-cryptography](https://github.com/cbomkit/sonar-cryptography), [cdxgen](https://github.com/cdxgen/cdxgen)

## 5. Competitor / Adjacent Tools and QUBIT's Gap

**Open source**
- **CBOMkit (PQCA)** — CBOM generation/visualization/compliance for Java/Python/Go. Static detection only; no risk model, no remediation.
- **cryptobom-forge (Santander)** — builds CBOMs from CodeQL multi-repo variant-analysis output; niche, CodeQL-dependent, low activity.
- **cdxgen** — CBOM as a side feature of SBOM generation; JS/TS/Java/Python; no PQC risk scoring.
- **pqcscan (Anvil Secure, July 2025 — new since 2025)** — single-purpose scanner listing PQC algorithms supported by SSH/TLS servers; network-side, not code-side.
- **CryptoScan / QRAMM toolkit (CSNP)** — code/config/dependency crypto discovery with CycloneDX CBOM export and quantum-risk flags.
- **CipherIQ cbom-generator (new)** — crypto asset discovery + PQC readiness scanner with CBOM output.

**Commercial**
- **SandboxAQ AQtive Guard** — market leader; 3-modal discovery (network analyzer, application/runtime hooks, filesystem/binary scanner) + lifecycle management. **Dec 2025: 5-year agreement with U.S. Department of War CIO** for automated crypto discovery and PQC migration. HQC co-submitter.
- **QuSecure QuProtect** — quantum-safe orchestration/overlay for networks; crypto-agility control plane.
- **Keyfactor** — certificate lifecycle + PKI (EJBCA, Command) with PQC readiness (drives BouncyCastle development).
- **ISARA** — Radiate toolkit (ML-KEM/ML-DSA, hybrid certificates) still marketed in 2026; pivoted heavily to advisory/readiness services.
- Others: InfoSec Global AgileSec, Quantum Xchange, PQShield (IP/silicon), Utimaco/Thales/Entrust (HSM-side PQC).

**Gap QUBIT fills:** no open tool combines (a) source-level crypto discovery to CycloneDX 1.7 CBOM, (b) **probabilistic risk quantification** (Bayesian network + Monte Carlo over expert CRQC timelines — competitors output static severity labels), and (c) **local-LLM-assisted code transformation** to PQC APIs that keeps source private (competitors either stop at inventory or require cloud services). Commercial platforms (AQtive Guard) do discovery+management but are closed, enterprise-priced, and do not rewrite application code.

Sources: [pqcscan](https://www.helpnetsecurity.com/2025/07/14/pqcscan-open-source-post-quantum-cryptography-scanner/), [PQCA CBOMkit](https://pqca.org/blog/2025/pqca-announces-cbomkit-advanced-tools-for-generating-and-analyzing-cryptographic-bills-of-materials/), [cryptobom-forge](https://github.com/Santandersecurityresearch/cryptobom-forge), [SandboxAQ](https://www.sandboxaq.com/learn/pqc-platform), [Encryption Consulting vendor survey](https://www.encryptionconsulting.com/cryptographic-inventory-vendors/), [The Quantum Insider 2026 list](https://thequantuminsider.com/2026/03/25/25-companies-building-the-quantum-cryptography-communications-markets/)

## 6. tree-sitter Python Bindings

- **py-tree-sitter (`tree-sitter` on PyPI): 0.26.0, uploaded 2026-06-30** — actively maintained, prebuilt wheels for all major platforms, no library dependencies.
- **`tree-sitter-languages` (grantjenks) is unmaintained/abandoned.** The maintained replacement is **`tree-sitter-language-pack`: v1.12.2 (2026-07-02)** — 306+ precompiled grammars, Python 3.10–3.14 wheels (project now under kreuzberg-dev/Goldziher lineage).
- Implication: QUBIT should pin `tree-sitter>=0.26` + `tree-sitter-language-pack`, and must NOT depend on `tree-sitter-languages`.

Sources: [tree-sitter PyPI](https://pypi.org/project/tree-sitter/), [tree-sitter-language-pack PyPI](https://pypi.org/project/tree-sitter-language-pack/), [py-tree-sitter-languages (unmaintained)](https://github.com/grantjenks/py-tree-sitter-languages)

## 7. pgmpy and XGBoost

- **pgmpy: v1.1.2** (2026-04-30, per PyPI — corrected during design review; this section originally said 1.0.x) — **actively maintained**, suitable as QUBIT's Bayesian-network engine. Class name is `DiscreteBayesianNetwork` since 1.0 (old `BayesianNetwork`/`BayesianModel` removed).
- **XGBoost: 3.2.0 released 2026-02-09; 3.3.0 current since 2026-06-17** (corrected during design review; this section originally said ~3.1.1). Pin `>=3.2,<4`. Breaking-change awareness needed if QUBIT code was written against 1.x/2.x APIs.

Sources: [pgmpy changelog](https://data.safetycli.com/packages/pypi/pgmpy/changelog), [XGBoost releases](https://github.com/dmlc/xgboost/releases), [XGBoost docs](https://xgboost.readthedocs.io/en/latest/)

## 8. Ollama-runnable Code Models (consumer hardware, mid-2026)

| Model | Params | Quantized size / VRAM | Notes |
|---|---|---|---|
| **Qwen3-Coder 30B-A3B** (`qwen3-coder:30b`) | 30B MoE, 3.3B active | 19 GB Q4 (fits 16–24 GB VRAM; q8 32 GB) | Current best local coder; 256K native context — key for whole-file transforms |
| Qwen3-Coder-Next | small MoE (~3B active) | runs on ~16 GB | Ranked #1 budget agentic coder in 2026 roundups |
| Qwen2.5-Coder 32B | 32B dense | ~20 GB Q4 → 24 GB VRAM | Near-GPT-4o on Aider benchmark; dense accuracy option |
| Qwen2.5-Coder 14B | 14B | ~9 GB Q4 → 12 GB VRAM | Sweet spot for mid-range GPUs |
| Qwen2.5-Coder 7B | 7B | ~4.7 GB Q4 → 8 GB VRAM | Minimum viable for QUBIT transforms |
| Qwen3-Coder 480B | 480B MoE, 35B active | 290 GB — needs >=250 GB unified memory | Not consumer hardware |

- Rule of thumb from 2026 guides: 8 GB VRAM → 7B; 12 GB → 14B; 16 GB+ → Qwen3-Coder-30B (MoE); 24 GB → 32B dense. Q4_K_M ≈ 55% VRAM reduction, <1% benchmark loss.
- Implication: QUBIT's local transformation engine should default to `qwen3-coder:30b` when >=16 GB VRAM is available, falling back to `qwen2.5-coder:7b` at 8 GB.

Sources: [ollama qwen3-coder](https://ollama.com/library/qwen3-coder), [Local AI Master VRAM table](https://localaimaster.com/blog/ollama-model-ram-vram-table), [Best Ollama coding models 2026](https://localaimaster.com/models/best-local-ai-coding-models)

## 9. CRQC Timeline Priors (Monte Carlo inputs)

- **Global Risk Institute / evolutionQ "Quantum Threat Timeline Report 2025"** — 7th annual edition, **published 2026-03-09** (Mosca & Piani), surveying **26 international experts**.
- Headline numbers (probability a CRQC breaks RSA-2048 in 24h):
  - **10 years: averaged estimate 28–49% ("quite possible") — the highest 10-year figure in the report's history**
  - **15 years: 51–70% ("likely")**; 18/26 respondents (69%) put P >= 50% at 15 years
  - **20 years: 92% of respondents put P >= 50%**; nearly half said "extremely likely" (>99%)
  - Experts explicitly assess the timeline as having **accelerated** vs. prior editions.
- These distributions (per-horizon probability bands across 26 experts) are directly usable as QUBIT's Monte Carlo priors; the report's cumulative-probability-by-year curves should be digitized from the PDF.

Sources: [GRI Quantum Threat Timeline 2025](https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/), [PostQuantum.com analysis](https://postquantum.com/security-pqc/quantum-threat-timeline-report-2025/)

## 10. Java and Python PQC Libraries

- **BouncyCastle Java**: ML-KEM, ML-DSA, SLH-DSA supported since **1.79 (Nov 2024)** per FIPS 203/204/205; **1.82 (Sept 2025)** added ML-DSA in TLS 1.3 drafts + ML-KEM key-validation optimizations; current release **1.84** (alongside LTS 2.73.11). FIPS-certified line (BC-FJA) covers PQC via the FIPS BCJSSE provider. QUBIT's Java transform target: `KeyPairGenerator.getInstance("ML-KEM", "BC")` era APIs, BC >= 1.79 (prefer >= 1.84).
- **Python beyond liboqs-python**:
  - **pyca/cryptography >= 48** now ships **ML-KEM and ML-DSA natively** (Rust bindings; Trail of Bits, funded by Sovereign Tech Agency; announced 2026-06-30). SLH-DSA in progress. This is the mainstream path — "one pip install away" for the 11th-most-downloaded PyPI package — and should be QUBIT's recommended Python migration target over liboqs-python.
  - liboqs-python 0.15.0 remains the research/broad-algorithm option (HQC, FrodoKEM, etc.).
  - Pure-Python `kyber-py`/`dilithium-py` exist but are explicitly not production-grade.
- Policy context: **2026-06-22 White House order** accelerating U.S. government PQC transition — strengthens QUBIT's market timing.

Sources: [BouncyCastle 1.79](https://www.bouncycastle.org/resources/latest-nist-pqc-standards-and-more-bouncy-castle-java-1-79/), [BouncyCastle 1.84](https://www.bouncycastle.org/resources/new-releases-bouncy-castle-java-1-84-and-bouncy-castle-java-lts-2-73-11/), [Trail of Bits: PQC in Python](https://blog.trailofbits.com/2026/06/30/shipping-post-quantum-cryptography-to-python/), [pyca tracking issue #14690](https://github.com/pyca/cryptography/issues/14690)

---

## Caveats
- oqs-provider 0.11.0 release date reported inconsistently across sources (Dec 2024 vs Dec 2025); the release notes' statement that it syncs with liboqs 0.15.0 (Nov 2025) supports **Dec 2025**.
- HQC draft FIPS: NIST page (updated 2026-06-16) still lists no draft — treat "draft 2026, final 2027" as expectation, not fact.
- XGBoost patch version (3.1.1 vs 3.1.3) varies by source; pin ">=3.1,<4" and verify at build time.
