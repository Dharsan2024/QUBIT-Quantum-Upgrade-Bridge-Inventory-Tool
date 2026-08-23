# How Much Cryptography Did Every Detector Miss? Measured Inventory and Verified Migration for Harvest-Now-Decrypt-Later Risk

**A research-paper manuscript (draft).**
Authors: Dharsan L (43614012), Akshay Kumar S (43614004)
Guide: Dr. P. Shanmuga Prabha · BE-CSE (Cybersecurity), Batch 2023–2027
Artifact: the QUBIT monorepo. All figures below are reproducible from the scripts named beside them.

> **Honesty note for the authors (delete before submission).** Every quantitative claim is tagged
> **[measured]** (produced by a script in this repository, on real inputs), **[modeled]** (a
> deliberate simulation — the correct treatment of an event that has not occurred), or
> **[future work]**. Two further rules, both of which this draft follows and neither of which is
> optional in the viva: an *in-sample* figure is always labelled as one, and **§10 Related Work
> states methodological differences, not other papers' numbers** — no figure is attributed to a
> cited work unless it has been read and checked against the source.

---

## Abstract

Migrating the world's deployed cryptography to post-quantum standards is a decade-scale programme
made urgent by the **Harvest-Now-Decrypt-Later (HNDL)** adversary, who records ciphertext today and
decrypts it once a Cryptographically-Relevant Quantum Computer (CRQC) exists. Every step of that
programme begins with an inventory, and every published cryptographic-inventory tool reports recall
against a corpus it can see. **None estimates what all of them missed.**

We present **QUBIT**, an offline platform that closes the loop from discovery through calibrated
HNDL risk to sandbox-verified remediation and an on-wire proof of migration — and, more importantly,
an evaluation designed so that its own conclusions can be checked. Four independently written
detectors (QUBIT's tree-sitter AST engine, two pattern engines, and Semgrep's dataflow rules,
selected by Semgrep's own CWE metadata) are run over a **26-repository corpus drawn from a stated
sampling frame with a fixed seed and pinned commits**. Overlap between them yields a
capture–recapture estimate of the cryptography *no detector found*, with the estimator's bias
direction established by simulation rather than assumed away.

Three results follow, and two are unflattering to the tool we wrote. First, **detector agreement is
not evidence of correctness**: on a hand-labelled sample of 601 findings released with the paper,
64% of one pattern detector's exclusive findings do not contain the named algorithm at all — `DES`
inside `DESC`, `CODES`, `OVERRIDES`. Second, **the screening instrument that produced our own
headline was wrong**: scored against those labels it reached Cohen's κ = 0.279, because a digit
after an algorithm name defeated its word-boundary test and `SHA` could not match `sha256`. Third,
**our own secret/PII pass was the least precise detector in the study** at 20.5% [14.9%, 27.7%], a
claim of "high precision" that five unit tests on invented input had protected from measurement for
the project's entire history.

The contribution is therefore not another migration framework. It is a **measurement methodology for
cryptographic inventory** — population estimation across detectors, use-versus-mention adjudication
under a pre-registered protocol, released labels, and validation of the benchmark's own instruments
— together with a working system that the methodology was used to improve.

**Keywords:** post-quantum cryptography, cryptographic inventory, capture–recapture, benchmark
validity, harvest-now-decrypt-later, CBOM, Mosca inequality, ML-KEM, ML-DSA.

---

## 1. Introduction

### 1.1 Motivation

NIST finalised the first PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) in 2024.
The urgency is not that a CRQC exists — it does not — but the **HNDL** model: data with a long
secrecy shelf-life, encrypted with quantum-vulnerable algorithms today, can be harvested now and
decrypted later. What to migrate first is therefore a risk-prioritisation problem governed by
**Mosca's inequality**: if `X` (shelf-life) + `Y` (migration time) > `Z` (time to CRQC), the data is
already effectively compromised.

Every migration programme begins by answering *what cryptography do we have?* — and that answer is
produced by a detector whose recall nobody knows.

### 1.2 The gap this paper addresses

The tooling literature is crowded with discovery tools, CBOM generators and LLM code-transformation
demonstrations. Its evaluations share a structure: run the tool on a corpus, count what it found,
report recall against a reference — a labelled benchmark, or another tool.

That structure has a ceiling built into it. **It cannot see anything the reference also missed**, and
two tools missing the same construct is indistinguishable from neither tool being wrong. Because
detectors are written from the same public library documentation, their errors are positively
correlated, and the direction of the resulting bias is knowable: reported recall is optimistic.

A second problem is subtler and, we will show, larger. A detector that matches text cannot separate
an algorithm *used* from an algorithm *mentioned*. A project that maintains a ban list of weak
algorithms is reported as using them. This is not a rounding error on the corpora that matter most
during a PQC migration — security tooling, protocol libraries, anything whose vocabulary is
cryptography.

### 1.3 Contributions

1. **Population estimation for cryptographic inventory.** Chapman and log-linear M_th
   capture–recapture estimators over four independent detectors, giving a bound on the cryptography
   *no detector found*. The estimators' bias is measured by simulation against a known population
   rather than asserted (`benchmarks/oracles/population.py`). **[measured]**
2. **Use versus mention, adjudicated and released.** A pre-registered protocol, a blind stratified
   sample, **601 hand labels published as data**, and per-detector precision on the exclusive
   stratum with Wilson intervals and a bootstrap over repositories
   (`benchmarks/adjudication/`). **[measured]**
3. **Validation of the benchmark's own instruments** — the finding we did not expect to have to
   make, and the one we would most want a reader to take away (§7.3). **[measured]**
4. **A corpus with a sampling frame**: 26 GitHub repositories, 13 language strata, fixed seed,
   pinned commits, an inclusion criterion fixed before the run, and excluded repositories reported
   with their counts (`benchmarks/corpus/`). **[measured]**
5. **A working offline system** — discovery → HNDL risk → sandbox-verified patch → hybrid-TLS proof
   — whose defects the above found and whose repairs are regression-locked (§4–§6, §7.5).

---

## 2. Threat Model and Background

**Adversary.** A passive HNDL adversary who can (a) record ciphertext in transit or exfiltrate
encrypted data at rest today, and (b) access a CRQC at some future time `Z`. Shor's algorithm breaks
RSA/ECC once a CRQC of sufficient logical-qubit count and error rate exists; Grover's halves the
effective security of symmetric primitives. QUBIT does **not** model an active attacker or
implementation-level side channels.

**Mosca's inequality.** Per asset, QUBIT estimates the *Mosca margin* `Z − (X + Y)` in years. A
negative margin means the secrecy requirement outlives the cryptography.

**CRQC arrival is modeled, not measured.** No CRQC exists, so `Z` is a distribution, not a date:
Monte-Carlo simulation over published surface-code resource estimates (Webber et al.; Gidney &
Ekerå), optionally blended with an expert-survey log-normal CDF. This is labelled a simulation
everywhere it appears, in the system and in this paper.

---

## 3. System Overview

A `uv`-managed Python 3.12 monorepo of seven packages, a React/TypeScript dashboard, and a Tauri
native desktop application. Modules communicate only through a frozen `CryptoAsset` schema, a
SQLite/Postgres database, and a normative REST API.

| Package | Responsibility |
|---|---|
| `qubit-core` | `CryptoAsset` schema, algorithm registry, fingerprinting, CycloneDX 1.7 CBOM export |
| `qubit-scanner` | Discovery: code (tree-sitter AST), config, network TLS, certificates/keys, dependency manifests, and the HNDL secret/PII pass |
| `qubit-risk` | Monte-Carlo CRQC timeline, Bayesian network, conformalised regressor, Mosca margin, CNSA 2.0 milestones |
| `qubit-migrate` | Dependency graph, WSJF queue, local-LLM and deterministic transforms, sandbox validation, task state machine |
| `qubit-bridge` | Hybrid PQC TLS terminator; probe, verify, capture |
| `qubit-api` | FastAPI spine, job runner, SSE |
| `qubit-cli` | `qubit` command tree including one-command `qubit run` |

**Scale [measured]:** ~25.1k lines of Python across 7 packages (excluding tests), ~12.6k lines of
tests, ~6.9k lines of dashboard TypeScript, ~4.0k lines of evaluation harness. Ruff and mypy clean.
Fully offline: a local LLM via Ollama, no cloud calls, no telemetry.

---

## 4. Discovery: The HNDL Exposure Surface

### 4.1 Cryptographic discovery

Source is parsed with **tree-sitter** and matched against a YAML rule catalogue, emitting a
`Detection` per finding normalised against a canonical algorithm registry (family, key size,
quantum-vulnerability verdict, PQC replacement). Config files, certificates and keys, live TLS
endpoints, and dependency manifests have dedicated modules. Every asset carries redacted evidence
(±5 lines, `file:line`) and a stable cross-scan fingerprint so remediation deltas are queryable.

### 4.2 Broadening to the HNDL exposure surface

A crypto-only inventory understates HNDL risk: the threat is not weak algorithms but everything they
protect. A secret/PII pass detects provider credentials, JWTs, PEM private-key blocks, hardcoded
passwords, and PII, each annotated with a per-finding exploit narrative — what the adversary
harvests now and how it is used after a CRQC arrives.

**This subsystem's precision is measured in §7.4, and it was the worst result in the paper.**

### 4.3 Output artifact

The database is the source of truth; the exportable artifact is a **CycloneDX 1.7 Cryptographic Bill
of Materials**, validated against the ECMA-424 schema.

---

## 5. Risk Quantification

A per-asset HNDL risk in `[0, 1]` with a calibrated interval.

1. **CRQC arrival (`Z`).** Monte-Carlo simulation over a surface-code resource model, producing
   `P(CRQC ≤ year)`, optionally blended with an expert-survey CDF. Anchor-tested against published
   figures. **[modeled]**
2. **Data exposure (`X`).** A closed-form `P_HNDL` integral (Gauss–Legendre) that agrees with an
   independent 5-node Bayesian network to within <0.02 — two formulations cross-validating each
   other. **[modeled, internally cross-validated]**
3. **Mosca margin.** `Z_median − (X_shelf_life + Y_migration)`, negative ⇒ already compromised.
4. **Calibrated score.** A gradient-boosted distillation regressor over a frozen 34-dimensional
   feature vector, wrapped in **split-conformal** prediction for a distribution-free interval, with
   TreeSHAP attributions surfaced in the UI. **[modeled]**

**Honest negative result.** A DistilBERT sensitivity classifier trained on synthetic snippets reached
near-perfect held-out accuracy and ~2.8% agreement on real code — template memorisation, not
transfer. It is reported as a negative result and the product ships the transparent heuristic
classifier instead.

---

## 6. Automated, Verified Migration

### 6.1 Ordering

A directed dependency graph over discovered assets is condensed over strongly-connected components
into atomic *migration units*, topologically ordered, and scheduled by **risk ÷ effort** within the
ready frontier.

### 6.2 Generation and the safety gate

Patches come from a **local LLM** (Ollama) using structured edits — QUBIT computes the unified diff
itself and never trusts model line numbers — or from **deterministic template transforms** that need
no GPU. Every candidate passes a sandboxed `apply → parse → compile → re-scan` pipeline inside a
network-disabled container; a patch that fails any stage cannot be accepted, and human approval is
mandatory. **Safety is the claim, independent of model success rate.**

### 6.3 Runtime proof

`qubit-bridge` stands up a hybrid TLS terminator on the port a classical service used, and
`qubit bridge verify` confirms the negotiated group is **X25519MLKEM768** on a real handshake.
**[measured]**

---

## 7. Evaluation

Everything in this section is produced by scripts in `benchmarks/`. Where a figure is in-sample, it
says so.

### 7.1 Design

**Detectors.** Four, behind one interface, with QUBIT given no special status in the code — the
population estimator cannot tell which of its inputs is the tool under test.

| detector | kind | rule selection | provenance |
|---|---|---|---|
| `qubit` | tree-sitter AST | its own rule pack | this repository, via the public CLI |
| `pqaudit` | 178 regexes | whole pattern file | PQCWorld/pqaudit (MIT) |
| `semgrep` | AST + dataflow | **Semgrep's own CWE metadata** (326/327/328/347/916) | semgrep/semgrep, pinned by digest |
| `cryptoscan` | pattern tables | whole tool | csnp/cryptoscan (MIT), pinned commit |

Semgrep's rules are selected by Semgrep, not by us. Filtering by keyword over rule IDs would put the
author of one detector in charge of deciding what counts as cryptography.

**Corpus.** 26 GitHub repositories over 13 primary-language strata, drawn from a 750-repository frame
with seed `20260821`, commits pinned in a lockfile. The **inclusion criterion was fixed before the
run**: a repository enters the analysis only if ≥2 detectors report ≥1 finding, because a repository
nobody fires on carries no information about relative recall. Excluded repositories are listed with
their counts so the criterion can be checked rather than trusted.

**Unit.** A *site* — `(file, algorithm family)`, not a line. Twelve QUBIT rules deduplicate per file
by design; a line-level comparison against a regex that fires on every line scored 9.5% the first
time this was tried and measured nothing but that design decision.

**Vocabulary.** Comparison is restricted to families ≥2 detectors can name. On `go-jose`, 109 of
QUBIT's findings were the family `JSON WEB TOKEN`, which no other detector can express; every one
landed in "found by QUBIT alone" and depressed everyone else's recall. Restricting the vocabulary cut
QUBIT from 144 sites to 75 and raised agreement with cryptoscan from 27.8% to 51.9%. **Most of
QUBIT's apparent lead was vocabulary**, and `--all-families` reproduces the flattering version.

### 7.2 What no detector found

For two detectors with capture sets `n₁`, `n₂` and overlap `m`, the Chapman estimator gives
`N̂ = (n₁+1)(n₂+1)/(m+1) − 1`. With three or more, heterogeneity is modelled directly as a log-linear
M_th model fitted as a Poisson GLM.

The independence assumption is **false in a direction we can name**: all four detectors were written
from public documentation of the same libraries, so captures are positively correlated, `m` is
inflated, `N̂` is an underestimate, and any recall computed from it is an **upper bound**.

We measure how badly rather than asserting it. Simulating 1,000 sites split into an easy and a hard
half, against a known true `N`: **[measured]**

| estimator | estimate (true N = 1000) |
|---|---|
| 2-source Chapman | 593 |
| 3-source, independence | 630 |
| 3-source, one interaction | 640 |
| 3-source, two interactions | 653 |

Every estimator lands far low; modelling correlation moves the right way without closing the gap. The
claim is therefore deliberately narrow: **recall measured against a union of detectors is optimistic,
and this is a lower bound on by how much.** `test_population.py` fails if the module ever starts
claiming more. A regression test also pins the refusal to report a diverged GLM fit rather than
overflowing on it — 602 of 4,000 random sparse capture tables diverge.

### 7.3 The benchmark's own instrument was wrong

Adjudicating 26 repositories by hand is infeasible, so a screening classifier assigns every finding
one of four classes — `code`, `string-literal`, `comment`, `substring` — and the corpus-level
use-versus-mention result rests entirely on it. **It had never been validated.**

601 findings were drawn from the corpus, stripped of every trace of which tool produced them,
labelled one at a time against the source under a protocol fixed in advance, and released as data.
Scored against those labels: **[measured]**

|  | before | after |
|---|---|---|
| raw agreement | 56.8% | 84.8% |
| **Cohen's κ** | **0.279** | **0.762** (in-sample) |

κ = 0.279 is *fair* on the conventional scale and useless in practice. **One defect caused 107 of the
601**: the word-boundary test accepted a break only at punctuation or a camelCase hump, so a digit
after the name read as the word continuing.

```
mac := hmac.New(sha256.New, []byte(secret))     family SHA   → "coincidence of letters"
return await argon2.hash(password)              family ARGON2 → "coincidence of letters"
```

`SHA` could not match `sha256` — the most common spelling of the most common primitive in the corpus
was invisible to the instrument scoring it. A second defect (categories recognised only by a colon)
accounted for 35 more.

Two further defects surfaced from reading the same output. `SKIP_DIRS`, a list of vendored
directories present since the first commit, was **enforced nowhere**: gatsbyjs/gatsby vendors a 5 MB
bundled `yarn-1.21.0.js`, and 24 of the 28 exclusive findings sampled from that repository came out
of it — true about yarn, and not a fact about gatsby. And the adjudication and the comparison were
running over *different file populations*, so their numbers could not honestly be tabulated together.

**This is the paper's methodological finding.** The project's working thesis is that detection rules
cannot validate themselves, because a rule that fails to match something also fails to notice that it
should have. The same holds one level up: **a screening instrument built by the people it flatters is
subject to exactly the same failure, and it took released labels to see it.** Reporting κ = 0.279
costs us the earlier headline and is the reason the current one can be believed.

The largest surviving disagreement, 29 of 448, is principled rather than a bug: a quoted algorithm
name passed as an argument. `createHash('sha256')` is scored `string-literal`, because the
classifier's only rule is whether the name survives outside quotes, and that rule cannot separate a
call argument from a ban-list entry. Resolving it is the job of the AST detector under test.

### 7.4 What the exclusive findings are

Findings **one detector reported and no other did** — where precision and recall both live.
**[measured]**

| detector | n | use | mention | absent | use rate (Wilson) | bootstrap over repos |
|---|---:|---:|---:|---:|---|---|
| `qubit` | 23 | 23 | 0 | 0 | 100.0% [85.7%, 100%] | 8 repos, degenerate |
| `semgrep` | 2 | 2 | 0 | 0 | 100.0% [34.2%, 100%] | 2 repos, degenerate |
| `cryptoscan` | 107 | 51 | 53 | 3 | 47.7% [38.4%, 57.0%] | [26.5%, 69.2%] |
| `pqaudit` | 317 | 57 | 57 | 203 | **18.0%** [14.1%, 22.6%] | [8.9%, 31.0%] |

**64% of `pqaudit`'s exclusive findings do not contain the named algorithm at all.**

```
ORDER BY scheduled_time DESC          reported as 3DES
id: CODES.BadResponse,                reported as 3DES
static OVERRIDES_CWD_A: &str = ...    reported as 3DES
GOOGLE_SLIDES = "google-slides",      reported as 3DES
```

199 of the 601 sampled findings are that single pattern. This is what a recall benchmark scored
against a regex oracle actually measures.

**QUBIT's row must be read narrowly.** It is precision on the *exclusive* stratum only, at n = 23
across 8 repositories; the bootstrap interval is degenerate (every resample is 100%) and carries no
information, so the Wilson interval is the honest one. What the table supports is a comparison of
kind, not a headline number: **when an AST detector is the only one to fire, it is usually looking at
real cryptography; when a pattern detector is, usually it is not.**

Intervals are **Wilson**, not normal-approximation — at n = 23 the normal approximation puts the
upper bound above 100%. The bootstrap resamples **repositories, not findings**, because findings
within a repository are strongly dependent: eleven of the 601 are the same email address in one
checked-in fixture file. Resampling findings would produce intervals several times too narrow, and
that is the error that would have made these numbers look better than the evidence supports.

### 7.5 Turning the measurement on ourselves

Of 151 labelled findings from QUBIT's own HNDL secret/PII pass: **[measured]**

| | count | share |
|---|---:|---|
| a real secret or a real address | 31 | **20.5%** [14.9%, 27.7%] |
| a placeholder, fixture or example | 73 | 48.3% |
| **not an instance of the category at all** | **47** | **31.1%** |

```
'icon@2x.png', // Retina image naming              PII-EMAIL
'package@1.0.0.tgz', // NPM package versioning     PII-EMAIL
git@github.com:multica-ai/multica.git              PII-EMAIL
0.4365079365079365                                 PII-CREDIT-CARD   (a doctest float)
Password = "password",                             SECRET-HARDCODED-PW  (an enum member)
```

Sixteen digits after a decimal point begin with 4 and match the Visa pattern exactly; a word boundary
does not help, because `.` *is* one. This subsystem was documented as trading recall for precision,
and five unit tests on invented input had protected that claim from measurement for the project's
entire history.

After filtering, re-measured against the same labels: **all 47 outright false positives removed, all
31 genuine findings retained**, precision 20.5% → 34.8% *(in-sample: the filters were derived from
these labels)*. Every case is regression-locked in
`packages/qubit-scanner/tests/test_secrets_precision.py` using real corpus lines. The 58 surviving
mentions are test fixtures with plausible values, which needs a policy decision about what an
inventory should show rather than a detection fix; it is left open.

### 7.6 Migration

The transform pipeline accepts **89/105** on a polyglot fixture corpus. Of the 16 remaining, 2 are
files already compliant — a distinction the system previously could not express, and which made a
plan report finished work as broken until a `resolution` field separated *nothing left to migrate*
from *could not migrate*. Four are correctly diagnosed multi-finding cases needing a codemod. The
remaining ~10 are genuine limits of a 7B local model. **[measured]**

Migration evaluation on *real repository files*, with a build check rather than a re-scan check,
remains **[future work]** and is the largest gap in this section.

---

## 8. Implementation Notes

- **Offline and reproducible.** Local Ollama, pinned dependencies, every baseline detector pinned by
  image digest or commit, engine versions recorded per run. The benchmark harness runs Semgrep with
  `--metrics=off` and ships in no release: a benchmark that posted match counts to a vendor while
  measuring an offline guarantee would be a poor joke.
- **Deployment.** `docker compose up`, `pip install qubit-cli`, or a native **Tauri** desktop
  application that runs the engine locally so it can scan host paths and clone repositories.
- **Safety of the tool itself.** Network-scan authorisation guardrails (RFC1918/allowlist plus an
  audit log), diff application confined to registered project roots with a traversal guard, hashed
  API tokens.

---

## 9. Threats to Validity

1. **One annotator, and it is a language model.** The 601 labels were produced by an LLM reading a
   blinded worksheet under a protocol fixed in advance, supervised by the author. Three mitigations:
   the annotator cannot see which detector produced a finding; every label ships as data with a
   recorded reason, so a reviewer can disagree with any one and recompute; and the reported quantity
   is *agreement between two independently constructed annotators*, not ground truth. **An expert
   human pass on a subset, with κ against these labels, is the obvious strengthening and is not
   claimed.**
2. **In-sample figures.** κ = 0.762 and the 34.8% HNDL precision were obtained after repairs derived
   from these same labels. They measure that specific defects were fixed, not accuracy on unseen
   code. `pool.py` draws a fresh sample when one is wanted.
3. **Exclusive-stratum precision is not overall precision.** QUBIT's 23/23 is a small sample on the
   stratum most favourable to an AST detector.
4. **The population estimate is a floor.** Positive correlation between detectors is established, its
   direction is known, and its magnitude is bounded only by simulation.
5. **CRQC timelines are simulations**, conditioned on published hardware estimates. They are not
   forecasts.
6. **Detection recall is bounded by the rule catalogue.** The corpus exposes real holes — a C/C++
   gap, and near-zero JavaScript detection on one repository where a pattern detector found 117 sites
   — which are reported rather than trimmed away.
7. **The corpus is GitHub, and public.** Enterprise cryptography lives in code we cannot sample.

---

## 10. Related Work

Positioned by **method**, not by numbers: figures attributed to prior work must be read from the
sources before submission, and none are quoted here.

- **Static detection of cryptographic misuse** (CryptoGuard, CogniCrypt and successors) established
  the field's evaluation template: precision and recall against a labelled benchmark plus manual
  review of a set of real projects. The template's ceiling is the one described in §1.2 — it cannot
  observe what the reference also missed — and to our knowledge no work in this line reports an
  estimate of the undetected population.
- **CBOM generation** (CycloneDX 1.7 / ECMA-424 tooling, CBOMkit, cdxgen, cryptobom-forge) produces
  the compliance artifact and does not quantify risk or remediate. QUBIT emits the same artifact and
  treats it as an output, not a result.
- **PQC migration frameworks and maturity models** are largely conceptual; measurement is where that
  literature is thin.
- **Capture–recapture in software engineering** has been used since Eick et al. to estimate residual
  defects from overlapping inspections. Our contribution is the transfer — *detectors as inspectors*
  — together with a simulation that bounds the estimator's bias for this application rather than
  inheriting the assumption of independence.
- **Pooled assessment** is standard practice in information retrieval, where the incompleteness of
  judgements is treated as a first-class problem. Cryptographic inventory has the same structure and
  has not adopted the practice; §7.3–7.4 are an attempt to import it.

**What we could not find anywhere in this literature**, and what this paper therefore offers: an
estimate of what every detector missed; a released set of blind labels for cryptographic findings;
and a validation of the evaluation's own screening instrument.

---

## 11. Conclusion

QUBIT works: it discovers cryptographic assets and the wider HNDL exposure surface, quantifies risk
under Mosca's inequality with an explicitly simulated CRQC timeline, generates and sandbox-verifies
PQC patches, and proves the migration on a real hybrid TLS handshake — offline, on a laptop.

But the result we would defend hardest is the one that cost us. Pointing four independent detectors
at a seeded corpus and then *reading the disagreements* found seven detection defects in our own
rules, a benchmark instrument with κ = 0.279, a vendored-directory filter that had never been
enforced, and a secret scanner whose documented precision was an intention rather than a
measurement. None of it came from the test suite, which passed throughout.

**An inventory tool's recall is not knowable from the tool.** What is knowable is how much two
detectors disagree, what the disagreements actually are when someone reads them, and how far the
estimator that combines them can be trusted. That is a smaller claim than the field usually makes,
and it is one a reader can check: the corpus, the labels, the estimators, their simulated bias, and
the scripts are all in the artifact.

---

## Appendix A — Reproducibility

```bash
# corpus
uv run python benchmarks/corpus/build.py clone      # pinned commits from corpus.lock.json
uv run python benchmarks/corpus/sweep.py            # four detectors over 26 repositories

# adjudication
uv run python benchmarks/adjudication/pool.py       # blind stratified sample
uv run python benchmarks/adjudication/score.py      # confusion matrix, kappa, intervals
uv run python benchmarks/adjudication/recheck.py    # did the repairs hold

# estimators, and the simulation that bounds their bias
uv run pytest benchmarks/oracles/test_population.py -q

# the system
uv run qubit run <path|git-url>                     # scan → risk → migrate
uv run ruff check packages && uv run mypy packages/*/src && uv run pytest packages -q
```

Baselines are pinned by image digest or commit; the corpus lockfile records every repository's SHA.
Design specification: `docs/design/00`–`08`. Evaluation plan and its exit criteria:
`docs/EVALUATION_PLAN.md`. Adjudication protocol and labels: `benchmarks/adjudication/`.

## Appendix B — Figures for the camera-ready

1. Architecture: the seven packages and the data flow (§3).
2. The CRQC-arrival CDF with P05/P50/P95 markers.
3. The capture table and the population estimate for one repository, with caveats attached.
4. The confusion matrix of §7.3, before and after — the paper's methodological figure.
5. A before/after re-scan proving an asset was remediated, and the hybrid handshake capture.
