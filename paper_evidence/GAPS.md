# Limitations

What this pack does **not** establish, as of the current build. Every entry is a live limitation of
the system and the study as they stand — defects that have been found and fixed are not listed here,
because a limitations section that catalogues repaired bugs tells a reader nothing about what to
trust now.

Ordered by how much each one would change a reviewer's reading.

---

## L1. Cryptographic detection — MEASURED against independent ground truth

**Status:** substantially resolved, and the residue is named.

QUBIT is now scored against **CryptoAPI-Bench** (Afrose et al., SecDev 2019; MIT), whose labels were
produced, published and peer-reviewed by other people, and which is the benchmark CryptoGuard and
CogniCrypt report against. No label in this result came from this project. The construct mapping
was fixed in `benchmarks/groundtruth/MAPPING.md` **before** the first score.

On the weak-algorithm-identity category the mapping puts in scope (n = 68):

| | precision | recall |
|---|---|---|
| AST match on literals only | 50.0% [29.0%, 71.0%] | 16.1% [8.7%, 27.8%] |
| **with intra-file constant folding** | **72.5% [57.2%, 83.9%]** | **51.8% [39.0%, 64.3%]** |

The dimensional breakdown is the real finding (`tables/T08_ablation.csv`, `figures/F16_ablation`):
100% recall when the algorithm is a literal at the call site or reaches it through a local variable,
and **0% when it arrives through a field or from another file**. That is the capability frontier of
rule-pack crypto scanning, and it is where dataflow analysis — CryptoGuard's actual contribution —
would be required.

**What remains UNKNOWN.** This is Java-only, synthetic, and built around classical misuse. It says
nothing about the other 18 grammars, about real repositories, or about post-quantum readiness. The
26-repository corpus speaks to those, and the two results are reported side by side rather than
merged. QUBIT's precision on its **own** exclusive findings in real repositories still rests on 27
hand-labelled items, which remains too few for an interval worth quoting.

**Two disagreements are principled, not errors**, and are reported rather than adjusted away:

* RSA-2048 is classically secure and quantum-vulnerable. The benchmark calls it secure; QUBIT calls
  it vulnerable. QUBIT is right by its own construct and wrong by the benchmark's.
* 9 of the 11 in-scope false alarms are path-sensitivity cases where a `Cipher.getInstance("DES/…")`
  executes but its result is later overwritten. A misuse detector should stay quiet; an inventory
  tool that is about to rewrite that line should not. These are counted **against** QUBIT in the
  figures above rather than reclassified, because reclassifying a category after seeing that it
  costs you is precisely the error this study exists to catch.

---

## L2. Inter-rater agreement — MEASURED

**Status:** resolved. A second independent annotator (Akshay Kumar S) labelled 50 items blind,
drawn from the primary annotator's own sample and reshuffled, under the same protocol
(`benchmarks/adjudication/human.py --rater second`, `PROTOCOL.md`). Neither rater saw the other's
labels before both were complete.

801 labels were produced by a language model under a protocol fixed in advance. The primary human
annotator labelled 100 of them blind; the second annotator then labelled 50 of the primary's items,
also blind. Three independent comparisons now exist over the same underlying question:

| question | κ (human vs model) | κ (2nd human vs 1st) | n |
|---|---|---|---|
| Is the algorithm there at all? | **0.960** | **0.957** | 100 / 50 |
| Use or mention (all three classes) | 0.575 | **0.399** | 100 / 50 |
| — cryptographic findings | 0.707 | — | 64 |
| — HNDL categories | 0.381 | — | 36 |

Raw inter-rater agreement was 54.0% (κ = 0.399, bootstrap-over-repositories 95% interval
[0.253, 0.568]) on the 3-class split, and 98.0% (κ = 0.957) on presence/absence alone
(`benchmarks/adjudication/agreement.json`).

**The presence/absence boundary is reliable across every comparison this pack has now run**:
human-vs-model, human-vs-classifier, and human-vs-human all land at κ ≈ 0.96. That is what every
false-positive figure in this pack rests on, and it is now confirmed independently of any one
annotator's judgement.

**The use/mention boundary is genuinely harder, and the second rater changes the reading of it.**
The earlier draft of this limitation concluded the model's use/mention split was "conservative" —
that a human would call more findings real uses — because the primary annotator's 28 disagreements
with the model ran one way (human `USE`, model `MENTION`). The second, independent human rater
disagrees with the **primary annotator** in the identical direction: of 28 items the primary called
`USE`, the second rater called 22 of them `MENTION`. Two independent readers — the model and a human
— both landed closer to each other than either did to the primary annotator's `USE` calls. **The
more honest account is that the primary annotator's own USE threshold runs looser than an
independent rater's, not that the model under-calls real uses.** This is reported as a revision
rather than smoothed over, per the same discipline the rest of this pack has followed: reclassifying
a result after seeing that it complicates an earlier claim is exactly the error this study exists to
catch.

**What remains UNKNOWN:** whether this pattern holds at a larger n than 50, and whether a third
rater would land nearer the primary annotator or the second one — two points do not establish which
of the two, if either, is closer to a population "true" threshold for USE vs MENTION.

---

## L3. Patch success rate at corpus scale — MEASURED

**Status:** resolved. The 55% in `docs/design/03-migration-orchestrator.md` was always a risk-register
illustration, never a result, and is superseded here by an actual run.

`phase3_migration.py` ran the real validation gate over **all 26 corpus repositories**, both arms,
paired by construction (`data/migration_outcomes.csv`, `data/case_study.md`):

| arm | n | accepted | no codemod | error | failed validation |
|---|---|---|---|---|---|
| llm | 34 | 10 (29.4%) | 0 | 22 | 2 |
| template | 34 | 9 (26.5%) | 14 | 7 | 4 |

`accepted` means every stage the validator ran was passed (`applies`, `parses`, `rescan`; `compiles`/
`tests` where a toolchain existed). Where a toolchain genuinely ran — PHP, and Go/C via `mpv-player/mpv`
and `openwrt/openwrt` — compilation was really attempted and genuinely failed twice, in **both** arms,
which is the gate doing its job rather than a defect. 15 of the LLM arm's 22 errors are the verifier
rejecting the model's own rewrite after 3 attempts — the safety gate refusing a bad patch, not shipping
one silently. `no-codemod` is not a template failure: it is the arm correctly declining rules with no
deterministic transform (signatures, key exchange, MACs — most of what the LLM path exists for).

**A concrete case proves why "accepted" is not "safe to auto-apply".** `data/case_study.md` re-runs
one accepted finding and shows the LLM's real diff deleting a Go import (`crypto/x509`) still used
elsewhere in the same file — a patch that would not compile, which neither `parses` (syntax only) nor
`rescan` (checks one line, not the whole file) can catch, and which `compiles` correctly skips because
Go cannot syntax-check a single file out of its package. Nothing in this pipeline auto-applies a
patch: `apply_patch` requires `status == "approved"`, a state `generate_patch` never sets itself, and
the dashboard prints every stage's real status — including `compiles: skipped` — beside the Approve
button. The human reading that line before approving is the actual safety boundary here, not the
validator.

**What remains UNKNOWN:** whether these rates hold at a larger n than 34 pairs. The llm/template accept
gap is small (29.4% vs 26.5%) and not tested for significance here — the two arms are not attempting
the same 34 findings equally (`no-codemod` removes 14 of the template arm's tasks from contention
before the comparison is fair), so a raw percentage-point difference should not be read as "the model
helps by 2.9 points"; the more honest reading is in the table itself: the LLM path reaches every rule
class, and the template path reaches only the ones with a deterministic transform.

---

## L4. Timing, throughput, memory — MEASURED

**Status:** resolved. `phase3_performance.py` ran 5 repetitions per repository on a verified-quiet
machine (CPU load checked and gated at run time; no sweep, no Docker containers doing other work),
across 5 corpus repositories spanning 74 to 11,526 files (`data/performance.csv`, `figures/F13`,
`figures/F14`):

| repository | files | mean wall-clock | files/s | peak Python memory |
|---|---|---|---|---|
| lencx/ChatGPT | 74 | 0.11s ± 0.01 | 675.8 | 0.6 MB |
| valinet/ExplorerPatcher | 238 | 3.44s ± 0.06 | 69.3 | 23.9 MB |
| permissionlesstech/bitchat | 633 | 13.07s ± 0.11 | 48.4 | 18.5 MB |
| JetBrains/compose-multiplatform | 2,127 | 8.49s ± 0.11 | 250.7 | 90.1 MB |
| openwrt/openwrt | 11,526 | 25.65s ± 0.17 | 449.3 | 40.7 MB |

Variance is small (SD under 0.2s on every row), which is what "quiet machine" is supposed to buy.
Throughput does **not** scale monotonically with repository size — bitchat (633 files) is slower
per-file than compose-multiplatform (2,127 files), by roughly 5x. Cost tracks file size and how much
of the grammar the parser actually walks, not the file count or the language, which is what makes an
applicability gate (skipping repositories/files a detector cannot usefully read) worth having on an
expensive scanner.

**What remains UNKNOWN:** the scalability *curve* proper (B5/F12, log-log fit with error bars) still
rests on the corpus sweep's single run rather than 5 repetitions per size bucket — F13/F14 answer the
throughput and memory questions this item asked for, but a formal scaling-law fit was not attempted
on top of them.

---

## L5. No baseline for the migration half — MEASURED

**Status:** resolved, for the ablation this asked for. Detection has four independent baselines
(pqaudit, semgrep, cryptoscan, sonar-cryptography); the migration half now has the one this item
specifically named — the LLM path against the deterministic template-only path, same 34 findings,
same validation gate (see L3's table, `data/migration_outcomes.csv`, `data/case_study.md`).

**What remains UNKNOWN:** a comparison against another model, or against a human-written patch.
Neither was in scope for this pass.

---

## L6. Model provenance — RESOLVED, recorded here because a reader will look for it

**Status:** resolved. Listed rather than deleted because "how do I know what produced this" is the
first question asked of any generation result.

`env/model_provenance.txt` now records the blob digest
(`dae161e27b0e...86f4364`), the Ollama server version (`0.32.15`), the checkpoint's quantisation and
context length, and the decoding options as the code actually sends them. A decoding seed
(`llm.GENERATION_SEED = 20260822`) is now pinned and transmitted with every request; it previously
was not, and greedy decoding at `temperature=0.0` is near-deterministic rather than reproducible.

**Consequence:** any generation result produced from this build is reproducible. Any produced
before it is not, and none is quoted in this pack.

---

## L7. External validity is narrower than the sampling frame suggests — MODERATE

**Status:** measured, and worse than the design intended.

The corpus was drawn as 13 language strata of two repositories each. It is not 13 languages.
GitHub's `language:X` search returns repositories *containing* X rather than repositories whose
primary language is X, so the C# and C++ strata both drew C projects. The corpus actually contains
**11 primary languages**, with **C over-represented at six repositories and C# and C++ absent
entirely** (`tables/T04_dataset.csv`, columns `stratum` and `primary_language`).

Beyond that, the frame is popular open-source software on GitHub, which is better maintained and
more conventional in its cryptography than average code, so every detector in this study probably
looks better here than it would on average code. That is not fixable without a corpus nobody has,
and it is stated rather than hidden.

---

## L8. What the screening classifier still cannot do — MINOR

**Status:** known and bounded.

The classifier is deliberately crude. Two residual behaviours are worth naming:

* Trailing-comment detection uses a conservative marker set (`//`, `#`, `/*`, each requiring
  preceding whitespace). In Python, `a = b // MD5_ROUNDS` is integer division and is scored as a
  comment. The construction is rare and the direction is toward `MENTION`.
* `not-applicable` is returned for whole categories (`PII: EMAIL ADDRESS` and similar), so the
  classifier contributes nothing to judging the HNDL pass. That pass is scored by hand labels only.

Both are enumerated exhaustively in `tables/T12_screening_classifier.md`.

---

## L9. Not applicable, recorded so an absence is not mistaken for an omission

| spec item | why it does not apply |
|---|---|
| B9 PR curves | The screening classifier returns one of four categorical answers with no score. A PR curve would need an invented threshold. |
| B10 Calibration / ECE / Brier | Same reason: no probabilistic output to calibrate. |
| B15 Learning curves | Nothing is trained. The classifier is a rule, the detectors are rule packs, and the language model is a stock checkpoint used as-is. |
| B7 Cost per unit | Inference is local, so there is no token cost. Energy is not instrumented (folded into L4). |
| Model card: splits, leakage, class balance | No training, so there is no train/test split to leak across. |
| B6 Parallel scaling | The sweep is serial by design, so that one repository's cost is attributable. |
