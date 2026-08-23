# Human adjudication protocol

**Written 2026-08-22, after the 801 machine labels and before any human label was assigned.**

`PROTOCOL.md` is the original pre-registration and is **not amended by this file**. It was written
before the first machine label and it stays as it was, including the paragraph headed *"The
annotator, stated as a threat to validity"*, which ends:

> An expert human second-pass on a subset, with κ against these labels, is the obvious strengthening
> and is not claimed here.

This document is that second pass, registered before it happens for the same reason the first one
was: so the result can be checked rather than trusted. Everything below was fixed before the
annotator saw a single item.

## What question the human is answering

Exactly the one in `PROTOCOL.md`, unchanged, with the same four labels (`USE`, `MENTION`, `ABSENT`,
`AMBIGUOUS`) and the same HNDL addendum:

> Does the code at this line perform, configure, or select a cryptographic operation of the named
> family?

Changing the question between the two passes would make the two sets of labels incomparable and the
κ meaningless. `human.py label` prints the question above every session rather than assuming it is
remembered.

## Who

**One annotator: Dharsan L.** There is no second human, so **no inter-rater κ is available or will
be claimed.** This is a real limitation and the paper states it in those words. It is not worked
around by treating the language model as a second rater — the model is the thing being measured.

## Sample

* **100 distinct items**, drawn by `human.py draw --count 100 --repeats 20 --seed 20260822`.
* Drawn from **both cohorts** (`cohorts/calibration/`, 601 items; `cohorts/holdout/`, 200), so the
  human κ describes the same population the machine labels describe, not just the newer half.
* **Stratified, deliberately enriched for disagreement.** Two thirds of the draw comes from items
  where the screening heuristic and the language model already disagree, or where the heuristic
  abstains entirely — which is every HNDL finding. The realised draw is 66 disagreement / 34
  agreement.
* **The enrichment is corrected for, not hidden.** `agreement.py` reports raw κ *and* a
  post-stratified κ reweighting each stratum to its share of the full labelled population
  (394 disagreement / 407 agreement). Raw κ is therefore the **pessimistic** figure: it is measured
  on a sample two-thirds composed of the hard cases. Both are reported. Neither alone is the answer.

## Blinding

`human_worksheet.json` carries exactly the fields `show.py` prints — `seq`, `id`, `repository`,
`path`, `line`, `family`, `source`, and ±3 lines of context — and nothing else. It contains **no**
detector, rule id, heuristic class, model label, or stratum. This is enforced by a test
(`test_human_agreement.py::TestTheWorksheetIsBlind`) rather than by intention, because blinding that
depends on remembering not to look is not blinding.

The stratum of each drawn item is written to `human_strata.json`, which is not opened until scoring.

## Repeats, and why an intra-rater figure is reported at all

**20 of the 100 items appear twice** in the sequence, unmarked, at least 32 positions apart (the
realised minimum; the drawer enforces a floor of a quarter of the run). The annotator is told that
repeats exist — concealing that would be a deception with no methodological benefit — but not which
items they are.

The resulting **intra-rater κ** is the recognised substitute when a second rater is unavailable
(Gwet 2014; Hallgren 2012). It is weaker than an inter-rater figure and the paper says so. Its role
is to **bound the other two numbers**: an annotator who agrees with themselves at κ = 0.6 cannot
meaningfully be said to agree with a machine at κ = 0.8, and reporting the second without the first
would invite exactly that error.

Every judgement is kept. For the two head-to-head comparisons a repeated item contributes its
**first** judgement only, so that one person is not counted twice.

## What is reported, and in what order

1. **Human vs the screening classifier** (`adjudicate.py`). The corpus-level use/mention result
   rests entirely on this classifier, so this is the number the central claim depends on.
2. **Human vs the language model**. With the confusion matrix, because the *direction* matters: a
   model that over-calls `USE` flatters the detectors, one that over-calls `ABSENT` condemns them,
   and those are different findings.
3. **The annotator against themselves.**

Each with a Wilson interval on raw agreement and a bootstrap over **repositories** — not findings —
for the same clustering reason `score.py` documents.

## Fixed in advance

* Disagreements are **not** resolved in any machine's favour. Where the human and a machine differ,
  the human label is the one reported, and the machine's error rate is what changes.
* **No item is relabelled after seeing the κ.** If the figure is poor, it is reported as poor. The
  labels are append-only (`human_labels.jsonl`), so any correction stays visible in the file
  alongside what it corrected.
* **No re-draw after seeing results.** `human.py draw` refuses to overwrite an existing worksheet
  without `--force`, because renumbering the sequence after labelling has begun would orphan
  collected labels and silently change the sample.
* The annotator **supervised the machine pass** and is therefore not naive. This is a genuine
  anchoring risk that blinding reduces but does not eliminate, and it is disclosed in the paper's
  threats to validity rather than argued away.

## Running it

```
uv run python benchmarks/adjudication/human.py draw --count 100 --repeats 20   # done
uv run python benchmarks/adjudication/human.py label --annotator dharsan       # resumable
uv run python benchmarks/adjudication/agreement.py
```
