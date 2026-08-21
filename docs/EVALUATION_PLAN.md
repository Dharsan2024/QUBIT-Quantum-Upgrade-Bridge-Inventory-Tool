# Evaluation plan — closing the gap between a working tool and a publishable result

**Status:** active. Written 2026-08-21, after the first recall benchmark produced numbers that were
real but not yet defensible.

## Why this document exists

QUBIT works. It scans 19 languages, migrates cryptography, models HNDL risk, and ships as a desktop
application. None of that, by itself, is a result. A reviewer at a Q1 venue asks a different
question than a project examiner does: *how do you know?*

The first pass at answering that — `benchmarks/recall/`, measured against `pqaudit` — produced this:

| corpus | recall vs oracle | oracle-only |
|---|---|---|
| golang-jwt/jwt | 94.1% | 1 |
| go-jose | 78.9% | 12 |
| cryptoscan samples | 22.3% | 94 |
| oqs-provider (C) | 0.0% | 30 |

That spread — 0% to 94% on four real repositories — is the most interesting number this project has
produced, and it is currently unpublishable for six specific reasons. This plan closes them in
order, and each phase has an exit criterion that is a number, not an opinion.

### The six gaps

| # | Gap | Today | Exit criterion |
|---|---|---|---|
| G1 | **No ground truth.** The "oracle" is another tool with its own false positives. | ~20 findings adjudicated ad hoc | ≥500 findings adjudicated under a written protocol, labels released |
| G2 | **One baseline.** Only `pqaudit`, a regex engine. | 1 detector | ≥3 independent detectors, ≥1 AST-based |
| G3 | **n = 4**, and one corpus is a detector's own pattern tables. | 4 repos | ≥25 repos, documented sampling frame |
| G4 | **No precision.** 99 QUBIT-only findings on go-jose are unadjudicated. | recall only | precision + recall + F1, per stratum |
| G5 | **Toy migration corpus.** 87/105 on 15-line synthetic files. | synthetic | real repository files, with a build/behaviour check |
| G6 | **No statistics.** Point estimates, n=4. | bare percentages | Wilson intervals, bootstrap, and a population estimate |

## The idea that makes this a paper rather than a report

Fixing G1–G6 produces a better evaluation. It does not by itself produce a contribution. The
contribution is what the fixed evaluation lets us say that nobody currently says:

> Every published crypto-inventory tool reports recall against a corpus it can see.
> **None of them estimate what every tool missed.**

That number is estimable. Capture–recapture has been used since Eick et al. (1992) and Briand et al.
to estimate residual defects from overlapping software inspections: if two independent inspectors
find sets *A* and *B*, the size of the overlap bounds how much they jointly failed to find. Applied
to detectors rather than inspectors:

```
n₁ = |QUBIT findings|      n₂ = |oracle findings|      m = |both|

Chapman estimator:   N̂ = (n₁+1)(n₂+1)/(m+1) − 1        → true population
Recall               = n₁ / N̂                           → including what NOBODY found
```

The assumption this rests on — independent capture — is **false in the direction we can name**: both
detectors find easy cryptography and both miss hard cryptography, so captures are positively
correlated, `m` is inflated, `N̂` is an underestimate, and reported recall is therefore an
**upper bound**. That is a usable result: *published recall figures for crypto inventory are
optimistic, and here is by how much, at minimum.* With three or more detectors the heterogeneity can
be modelled directly (log-linear M_th models, fitted as a Poisson GLM in `statsmodels`), which
tightens the bound instead of just naming it.

This is why G2 (more baselines) is load-bearing and not merely "more thorough". Two detectors give a
bound. Three give an estimate.

## The thesis the evidence already supports

Independent of the estimator, the project has an uncomfortable empirical finding it can defend today:

> **Detection rules cannot validate themselves.** A rule that fails to match something also fails to
> notice that it should have, and its tests are written from the same understanding that produced
> the gap.

Evidence in hand: **every** detection defect found in this project surfaced by accident or from an
outside detector — never from the test suite, which passes 1 012 assertions over those same rules.
Seven defects in one afternoon once an independent oracle was pointed at it, including
`SWIFT-CRYPTOKIT-STRONG`, whose *title* advertised a pattern its query could not match.

That is the paper's spine. G1–G6 are what make it survive review.

---

## Phase 0 — Stabilise and bank the existing work ✅

- [x] Fix the `test_agility.py` basename collision that blocked whole-suite collection
      (`qubit_risk.agility` → `qubit_risk.camm`, since `qubit_migrate.agility` already means
      something else). The suite had not been running to completion.
- [x] Close the coverage-guard failure it exposed: `ECDH-ES` was detectable and not migratable
      (`code-jwe-kex-01`).
- [x] Full suite green: **1 577 passed, 0 failed, 0 skipped** — the two live-service tests now run
      for real against nginx-hybrid on 8443 and the seeded demo Vault, so `X25519MLKEM768` is read
      off an actual handshake rather than skipped.
- [x] `ruff` + `mypy` clean.
- [x] Committed and pushed; verified with `git ls-remote` (`6d4cc16`).

## Phase 1 — Make the oracle plural ✅

Four detectors behind one `Detector` interface, QUBIT among them with no special status. Docker
turned out to be the answer to the missing Go/Java/semgrep toolchains, with the side benefit that
every baseline is pinned by digest.

- [x] semgrep (AST + dataflow), rules selected by **semgrep's own CWE metadata**, image pinned.
- [x] cryptoscan, built from its own Dockerfile at `11f0e46`.
- [x] pqaudit, adapted from the existing harness without touching the engine.
- [x] `population.py` — Chapman and Fienberg log-linear estimators, 19 tests against simulated
      populations of known size.

**Two corrections that moved the result against QUBIT**, both found by reading output:

1. **Vocabulary.** 109 of QUBIT's go-jose findings were the family `JSON WEB TOKEN`, which no other
   detector can name, so each landed in "found by QUBIT alone" and depressed everyone else's
   recall. Restricting to families ≥2 detectors can name: 144 sites → 75, agreement with cryptoscan
   27.8% → 51.9%. Most of the apparent lead was vocabulary.
2. **File population.** 3 432 of cryptoscan's 3 794 findings on `cryptodeps` were in
   `data/crypto-database.json`, a lookup table QUBIT never opens as code — every one of them
   counted as a QUBIT miss. All detectors are now compared over the same file set.

## Phase 1.5 — Use versus mention (unplanned; the data demanded it) ✅

The largest finding so far, and it was not in the original plan. On crypto tooling, 76–96% of every
detector's exclusive findings are **mentions rather than uses**: ban lists, remediation tables,
test fixtures. A project that bans RC4 is reported as using RC4.

This cut both ways. QUBIT's own `GO-JWA-WIRE-NAME` — added the same session this harness was built
— matched any `"RS256"` string anywhere in a Go file and produced 73 mentions out of 76 exclusive
findings on `cryptodeps`. An AST detector matching a bare string literal has discarded the one
advantage it has. Fixed by requiring call-argument position, with the resulting recall loss on
`golang-jwt/jwt` recovered on precise evidence (`GO-JWA-SIGNING-METHOD`).

Full detail and numbers: `benchmarks/oracles/README.md`.

**Consequence for the corpus:** crypto tooling cannot be pooled with ordinary software. It is a
separate stratum with its own result, which is now one of the paper's findings rather than a
contaminated denominator.

---

## Phase 1 — Make the oracle plural (G2)

One regex engine is not an independent view; it is one opinion with 178 regular expressions.

**Toolchain finding:** this machine has no Go, Java, or semgrep binary, but **Docker works and can
pull images**. Every baseline below therefore runs containerised, which has the side benefit of
pinning each tool to a digest — a reviewer can reproduce the exact detector version.

| Detector | Kind | How it runs | Independence |
|---|---|---|---|
| `pqaudit` | regex, 178 patterns | already wired | PQCWorld, MIT |
| **semgrep** + community crypto rules | **AST/dataflow** | `docker run semgrep/semgrep` | different vendor, different paradigm — the important one |
| **csnp/cryptoscan** | pattern tables | `docker run golang:1.22` | already cloned in `git help/` |
| **CBOMkit-theia** *(stretch)* | CBOM generator | container | IBM, and it is the standard this field is converging on |

Each gets an adapter in `benchmarks/oracles/` behind one interface returning
`{(file, line, family, raw)}`, so adding a detector is a file and not a rewrite.

**Care required:** semgrep reports telemetry by default. `--metrics=off`, and the harness is a
development tool that never ships in the desktop application — the "your code never leaves the
machine" guarantee applies to QUBIT, and must not be quietly weakened by a benchmark that runs
inside it. The adapter documents this explicitly.

**Exit:** ≥3 detectors produce findings on the same corpus through one interface; per-detector
agreement matrix printed.

---

## Phase 2 — A corpus with a sampling frame (G3)

Four repositories chosen because they were interesting is a convenience sample, and one of them
(`cryptoscan`) is a *detector's own pattern tables*, which is why it scored 22% — QUBIT was being
scored on its ability to detect a list of algorithm names in a data file.

**Frame:** GitHub repositories, stratified by primary language across QUBIT's 19 supported
languages, filtered to those that actually use cryptography (a cheap pre-filter: any import of a
known crypto module), sampled to ≥25 with a fixed random seed and pinned commits.

- Strata proportional to QUBIT's rule coverage, so per-language recall is reportable.
- `oqs-provider` stays in deliberately: 0.0% on C is a real hole, and dropping the corpus that
  exposes it would be choosing the result.
- `cryptoscan` is **reclassified**, not deleted — reported separately as a synthetic sample set, not
  pooled with real code.
- A `clone.py` with pinned SHAs; repos are never vendored (licence hygiene, repo size).

**Exit:** ≥25 repos, ≥8 languages, pinned, reproducible from a script, sampling method written down.

---

## Phase 3 — Ground truth by pooled adjudication (G1, G4)

Hand-labelling 25 repositories is infeasible and unnecessary. The standard technique from
information retrieval is **pooling**: the union of all detectors' findings forms the pool, a
stratified sample of the pool is adjudicated by hand, and metrics are estimated from the sample with
intervals.

**Strata** (this is the design that makes ~500 labels sufficient):

| Stratum | Meaning | Sample rate |
|---|---|---|
| all detectors agree | almost certainly true | low — confirm the assumption cheaply |
| QUBIT only | **precision** lives here | high |
| oracle only | **recall** lives here | high |
| any two of three | disagreement is informative | high |

**Protocol**, written before labelling and not adjusted afterwards: each sampled finding is judged
against the source line as `TRUE` (a real cryptographic use of the named family), `FALSE` (string,
comment, benchmark name, unrelated identifier), or `AMBIGUOUS`, with the reason recorded.

**Honesty about the annotator:** there is one annotator, and he wrote one of the tools under test.
That is a threat to validity and gets stated as one. Two mitigations, both cheap and both real:
(1) labels are adjudicated **blind to which tool produced the finding** — the harness strips
provenance before presenting a line; (2) all labels ship as a JSON artifact in the repository so a
reviewer can disagree with any one of them. A second annotator on a 50-finding subset with a
reported Cohen's κ is the stretch goal.

**Exit:** ≥500 blind-adjudicated labels committed as data; inter-rater κ on a subset if achievable.

---

## Phase 4 — Metrics that survive a reviewer (G6)

- Precision, recall, F1 **with Wilson score intervals** (correct at the small counts we will have —
  normal approximation is not).
- Estimates weighted back to the pool by stratum, since sampling was stratified.
- Bootstrap over *repositories* (not findings) for the headline figure, because findings within a
  repository are not independent — this is the error that would make the numbers look better than
  they are.
- Capture–recapture population estimate, Chapman-corrected, with the positive-correlation caveat
  stated as a direction of bias, plus a log-linear fit once three detectors exist.
- Per-language and per-stratum breakdowns; **the variance is the finding**, so no single averaged
  headline number is reported without its spread.

`scipy` and `statsmodels` are already installed.

**Exit:** every reported figure carries an interval and a stated denominator.

---

## Phase 5 — Migration evaluation on real code (G5)

87/105 accepted is measured on one synthetic polyglot corpus of ~15-line files, one per algorithm.
That measures the pipeline on a fixture, not on software.

- Draw migration tasks from the Phase 2 corpus — real files, real imports, real length.
- Report accept rate **stratified by file size and language**, because that is where it will break
  and hiding it would be dishonest.
- Add a stronger success criterion than "the rescan no longer flags it": the patched file must still
  parse, and where a container toolchain exists, still build.
- Report the failure taxonomy, including the ~1-in-5 failures already known.

**Exit:** accept rate on real files, with the failure modes named and counted.

---

## Phase 6 — Make it a better application (the loop that already works)

This is the phase that improves QUBIT rather than measuring it, and it is last only because the
measurement tells it what to do. The pattern is already proven: the first recall run found seven
detection defects; closing them moved migration acceptance 74 → 87 and validation failures 6 → 0.

1. **Close every defect the expanded benchmark finds.** Expect the C/C++ hole (0.0% on
   `oqs-provider`) to be the largest single body of work.
2. **Verified PQC target shapes for the remaining 12 of 21 languages** — currently 9 are verified,
   and an unverified target shape is how a migration produces confident nonsense.
3. **Regression-lock every closed gap** with a benchmark assertion, not just a unit test — the whole
   thesis of this document is that unit tests written by the rule author do not catch this class of
   defect.
4. **Desktop release hygiene**: Tauri signing and updater configuration.

Explicitly **out of scope**: dev-token auth/RBAC, parked by the user.

**Exit:** benchmark recall re-measured after fixes, before/after reported for each language.

---

## What this does not become

Two failure modes are worth naming so they can be avoided deliberately.

**It does not become "another PQC migration framework."** The reference list for this project is
heavy on frameworks, maturity models, and CBOM standards — a crowded and largely conceptual space.
Measurement is where that literature is empty.

**The numbers do not get managed.** If expanding to 25 repositories drops headline recall from 78%
to 40%, the paper reports 40% and explains the spread. A benchmark whose author can tune the corpus
until the result is flattering measures the author, not the tool — which is the same failure this
entire document exists to correct.

## Sequencing

Phases 1–4 are the critical path and must be done in order; each depends on the previous one's
output. Phase 5 is independent of 3–4 and can proceed in parallel once Phase 2's corpus exists.
Phase 6 consumes whatever Phases 1–5 surface, continuously, rather than waiting for them to finish.
