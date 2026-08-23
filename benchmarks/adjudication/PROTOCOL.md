# Adjudication protocol

**Written 2026-08-22, before any label was assigned. Not revised afterwards.**

This file exists so that the labels in `labels.json` can be checked rather than trusted. If the
rules below had been written after seeing which way the counts fell, the labels would measure the
annotator's preferences and nothing else.

## What is being labelled

One **site**: a `(repository, file, line, algorithm family)` tuple that at least one detector
reported. The question asked of it is deliberately narrow:

> Does the code at this line perform, configure, or select a cryptographic operation of the named
> family?

Not "is this a vulnerability". Not "should this be migrated". Only: **is the cryptography there.**

## The four labels

| label | means | examples |
|---|---|---|
| `USE` | the named family is actually invoked, configured, or selected here | `sha1.New()`, `Cipher.getInstance("DESede/CBC/PKCS5Padding")`, `ssl_ecdh_curve X25519MLKEM768;`, `alg: "RS256"` passed to a signer |
| `MENTION` | the name appears, but as data or prose, not as an operation | a ban list, a severity table, a display label, a test fixture name, a comment, a doc string, an error message |
| `ABSENT` | the family is not referred to at all; the detector matched something else | `DES` inside `CODES`, `EC` inside `encode`, a variable called `rsaHelperTest` in a file with no RSA |
| `AMBIGUOUS` | the line cannot be resolved from the evidence shown | a bare identifier whose definition is elsewhere, a macro, a generated file |

**`MENTION` is not a synonym for false positive.** A JOSE `alg` header genuinely *is* the string
`"ES256"`, and a config file genuinely *is* text. The distinction is whether the string is
**consumed as a cryptographic selection** at this site (`USE`) or merely **listed** (`MENTION`).
`{"alg": "RS256"}` inside a `sign()` call is a USE; `"RS256"` inside `bannedAlgorithms` is a
MENTION. When the line alone cannot settle which, the label is `AMBIGUOUS`, never a guess.

## Blinding

The annotator sees `worksheet.json`: an id, the repository, the file, the line number, the algorithm
family, and ±3 lines of source context. It does **not** contain which detector produced the finding,
its rule id, or the heuristic classifier's opinion. Those live in `key.json`, which is written to a
separate file and is not read until scoring.

This matters because one of the four detectors was written by the annotator. A label that can see
`detector: qubit` is not evidence about QUBIT.

## Ties to the heuristic

`benchmarks/oracles/adjudicate.py` assigns every finding in the corpus one of four classes without
a human. The whole corpus-level use/mention result rests on it, so it is scored against these labels
rather than assumed correct:

| heuristic class | corresponding label |
|---|---|
| `code` | `USE` |
| `string-literal` | `MENTION` |
| `comment` | `MENTION` |
| `substring` | `ABSENT` |

Agreement is reported as a confusion matrix and Cohen's κ. **Disagreements are not resolved in the
heuristic's favour**; where the two differ, the hand label is the one used, and the measured error
rates are what the corpus counts get corrected by.

## Sampling

Stratified, seeded, and fixed before labelling:

* **Exclusive stratum** — findings exactly one detector reported. Sampled heavily: this is where
  both precision (a detector's own exclusive findings) and recall (everyone else's) live.
* **Agreed stratum** — findings ≥2 detectors reported. Sampled lightly, to check the assumption
  that agreement implies truth rather than to estimate anything.

Sampling is proportional within stratum across repositories, so no single large repository
dominates, and the seed is `20260821` — the same one the corpus was drawn with.

## The annotator, stated as a threat to validity

There is one annotator and the labelling was performed by a large language model (Claude, Opus 5)
reading the blinded worksheet under the rules above, supervised by the author. This is disclosed
rather than hidden, and three things bound what it can be worth:

1. **It is blind to provenance.** The annotator cannot preferentially favour QUBIT because it cannot
   see which findings are QUBIT's.
2. **Every label ships as data** (`labels.json`, with the reason recorded per item), so a reviewer
   can disagree with any individual one and recompute.
3. **It is a second opinion, not an oracle.** The reported quantity is *agreement between two
   independently-constructed annotators* — a mechanical classifier and a language model — plus the
   error rates that agreement implies. It is not a claim of ground truth, and κ is reported so a
   reader can see how much the two share.

An expert human second-pass on a subset, with κ against these labels, is the obvious strengthening
and is not claimed here.

## Addendum, written before labelling began: the HNDL categories

151 of the 601 sampled findings are not algorithm findings at all. They come from QUBIT's HNDL
exposure-surface pass and carry a *category* as their family — `PII: EMAIL ADDRESS`,
`HARDCODED PASSWORD/SECRET`, `PII: CREDIT CARD`, `GITHUB TOKEN`, `PRIVATE KEY MATERIAL`. No other
detector reports these, so every one of them is "exclusive" by construction and none of them can be
scored by asking whether an algorithm name appears on the line.

They are labelled anyway, under the same four words, because the paper claims this pass "trades
recall for precision" and that claim has until now been supported by five unit tests on invented
input rather than by any measurement on real repositories:

| label | for an HNDL category means |
|---|---|
| `USE` | a real instance of the category is present: an actual address, an actual credential |
| `MENTION` | the shape is right but the value is not live — a placeholder, an example, a test fixture, a documented sample |
| `ABSENT` | not an instance of the category at all; the pattern matched something else (`package@1.0.0.tgz` is not an email address) |
| `AMBIGUOUS` | cannot be resolved from the evidence shown |

These are scored **separately** from the cryptographic findings and never pooled into a joint
precision figure. They answer a different question about a different subsystem, and averaging the
two would produce a number that describes neither.

Note the direction of interest. For the crypto detectors, `MENTION` is the interesting failure. For
the HNDL pass, `ABSENT` is: a secret scanner that fires on `user@2x.png` is not trading recall for
precision, it is simply wrong, and that is a defect to fix rather than a caveat to report.
