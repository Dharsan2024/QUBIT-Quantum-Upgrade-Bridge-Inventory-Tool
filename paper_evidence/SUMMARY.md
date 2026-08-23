QUBIT discovers cryptography in a codebase, quantifies its harvest-now-decrypt-later exposure, and
rewrites it to NIST post-quantum algorithms behind a validation gate — entirely offline, with a
local model, emitting CycloneDX CBOM. Sections 1 to 8 describe that system. This section and the
ones after it describe what happened when it was measured.

## How it was measured

A corpus of 26 open-source repositories was drawn against a sampling frame with an inclusion
criterion fixed in advance: a repository enters the analysis only if at least two independent
detectors report at least one finding in it. Five detectors were run over it — QUBIT, pqaudit,
CWE-filtered semgrep, cryptoscan, and IBM's sonar-cryptography — and treated as equal capture
sources, so capture–recapture can estimate what *every* detector missed rather than scoring QUBIT
against a favoured oracle.

**801 findings were then hand-labelled** under a protocol written before the first label was
assigned, blind to which detector produced them, across two cohorts: 601 calibration, and **200
drawn afterwards from findings nobody had looked at**. Reporting them separately is what separates
a figure fitted on a sample from one that survives a fresh draw.

## What the screening classifier is worth

The classifier that decides whether a finding is a real cryptographic use is the instrument the
whole corpus-level result rests on. Measured against the hand labels, per class:

| class | calibration precision | held-out precision |
|---|---|---|
| ABSENT | 95.8% [92.2%, 97.8%] | 94.9% [87.5%, 98.0%] |
| USE | 76.6% [68.4%, 83.2%] | 79.5% [65.5%, 88.8%] |
| MENTION | 72.7% [63.7%, 80.2%] | 63.0% [44.2%, 78.5%] |

The shape is the finding: the instrument is reliable about **absence** and much weaker about the
**use-versus-mention** distinction, and that holds out of sample. Every false-positive claim in this
study rests on the first row, not the third.

## What a person thinks of the labels

A single annotator labelled 100 of the items blind, with 20 hidden repeats, and a second,
independent annotator then labelled 50 of those same items — also blind, neither seeing the
other's judgements. Whether an algorithm is present at all agrees almost perfectly in every
comparison this pack has run: **κ = 0.960 human vs model, κ = 0.957 second rater vs first.** That
is what every false-positive claim in this study rests on, and it is now confirmed independently of
any one annotator.

The use/mention split is the genuinely hard call, and the second rater changes how it reads. The
primary annotator agrees with the model at κ = 0.575 (falling to 0.381 on the exposure categories,
where the question is whether a test fixture counts as live) but with the **independent second
rater at only κ = 0.399** — and the disagreement runs the same direction in both comparisons: the
primary annotator calls `USE` where the model and the second rater both call `MENTION` more often
than the reverse. The earlier reading of this ("the model is conservative") does not survive a
second rater: the more honest account is that the primary annotator's own USE threshold runs looser
than an independent rater's, not that the model under-calls real uses.

## What QUBIT's own exposure pass is worth

QUBIT's HNDL pass reports categories no other detector produces, so it can only be judged by hand.
Measured precision was **20.5% [14.9%, 27.7%]** on the calibration cohort. After repair, an
independent held-out draw put it at **47.1% [34.1%, 60.5%]** — a real improvement on disjoint items,
with non-overlapping intervals, and still not a number anyone should call production-ready. The
single largest source of the remaining false positives is that the pass does not distinguish a test
fixture from production code, which is the same boundary the human and the model disagree on.

## What was measured this pass

* **Cryptographic detection against published, independent ground truth** (CryptoAPI-Bench):
  recall on the in-scope weak-algorithm category rose from 16.1% to 51.8% after a constant-folding
  fix, with the residual failure mode (field-sensitive/cross-file cases) named rather than hidden.
* **Patch success rate and a migration baseline**, over all 26 corpus repositories, both arms: LLM
  29.4% accepted (34 tasks), template-only 26.5% (correctly declining 14 of them as having no
  deterministic transform).
* **Timing, throughput and memory**, 5 repetitions on a verified-quiet machine.
* **Inter-rater agreement**, a real second annotator, not an intra-rater substitute.

## What this section does not contain

Stated here rather than left for a reader to notice, and set out in full in Appendix A:

* Whether the use/mention disagreement pattern holds at a larger n than 50, or which of the two
  annotators sits closer to a population "true" threshold — two points establish a direction, not
  a ground truth.
* A precision figure for QUBIT's cryptographic detection on its *own* exclusive findings in real
  repositories specifically (as opposed to against CryptoAPI-Bench): 27 hand-labelled items is too
  few for an interval worth quoting.
* A comparison of the migration pipeline against another model or a human-written patch.
