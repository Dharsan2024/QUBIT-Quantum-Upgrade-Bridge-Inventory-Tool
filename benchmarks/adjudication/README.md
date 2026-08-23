# Ground truth: 801 blind-labelled findings, and what they did to the benchmark

`benchmarks/oracles/` compares four detectors and estimates what all four missed. Every number it
produces about *what the findings are* — the use-versus-mention split that is the most interesting
result this project has — came from `adjudicate.py`, a heuristic that reads one line and decides.

Nobody had ever checked it.

This directory checks it. 601 findings were drawn from the 26-repository corpus, stripped of every
trace of which tool produced them, labelled one at a time against the source, and released as data.
Then the heuristic was scored against those labels, and so was each detector.

Three things came out of it, and two of them are unflattering to this project.

---

## 1. The screening heuristic agreed with the labels barely better than chance

|  | before | after |
|---|---|---|
| raw agreement | 56.8% | **84.8%** |
| Cohen's κ | **0.279** | **0.762** |

κ = 0.279 is "fair" on the conventional scale and useless in practice. The corpus-level claim —
*76–96% of some detectors' exclusive findings are mentions rather than uses* — was resting on an
instrument that got a quarter of its answers wrong in ways nobody had looked for.

**One defect caused 107 of the 601.** The word-boundary test accepted a break only at punctuation or
a camelCase hump, so a **digit** after the name read as the word continuing:

```
mac := hmac.New(sha256.New, []byte(secret))     SHA      → "coincidence of letters"
return await argon2.hash(password)              ARGON2   → "coincidence of letters"
SHA256_Update(&ctx, buf, len);                  SHA      → "coincidence of letters"
```

`SHA` could not match `sha256`. The most common spelling of the most common primitive in the corpus,
invisible to the classifier that was scoring it.

**A second defect caused 35 more.** The check for "this family is a category, not a name" tested for
a colon, which caught `PII: EMAIL ADDRESS` and missed `HARDCODED PASSWORD/SECRET`, `GITHUB TOKEN`,
`PRIVATE KEY MATERIAL` and `RUNTIME`. Every one of those was scored `substring` — *the detector
matched nothing real* — for families the classifier had no business ruling on at all.

Both are fixed and pinned (`test_adjudicate.py`). **The 0.762 is in-sample**: the fixes were derived
from these labels, so it measures whether the specific defects were repaired, not accuracy on unseen
code. `pool.py` draws a fresh sample when one is wanted.

### What the classifier still gets wrong, by design

The largest surviving disagreement is 29 of 448: a quoted algorithm name passed as an argument.

```js
const hash = createHash('sha256')          heuristic: string-literal.  label: USE.
```

Its only rule is *does the name survive outside quotes*, and that rule cannot separate
`createHash('sha256')` from `bannedAlgorithms: ["sha256"]`. Resolving that is exactly the job of the
AST detector this benchmark exists to measure, so the heuristic declines it and the confusion matrix
shows the cost.

---

## 2. What the exclusive findings actually are

Findings **one detector reported and no other did** — the stratum where precision and recall both
live.

| detector | n | use | mention | absent | use rate (Wilson) | bootstrap over repos |
|---|---:|---:|---:|---:|---|---|
| `qubit` | 23 | 23 | 0 | 0 | 100.0% [85.7%, 100%] | 8 repos, degenerate |
| `semgrep` | 2 | 2 | 0 | 0 | 100.0% [34.2%, 100%] | 2 repos, degenerate |
| `cryptoscan` | 107 | 51 | 53 | 3 | 47.7% [38.4%, 57.0%] | [26.5%, 69.2%], 12 repos |
| `pqaudit` | 317 | 57 | 57 | 203 | **18.0%** [14.1%, 22.6%] | [8.9%, 31.0%], 17 repos |

**64% of pqaudit's exclusive findings are not about cryptography at all.** Not weak matches — the
algorithm is not on the line:

```
ORDER BY scheduled_time DESC          reported as 3DES
id: CODES.BadResponse,                reported as 3DES
static OVERRIDES_CWD_A: &str = ...    reported as 3DES
GOOGLE_SLIDES = "google-slides",      reported as 3DES
```

`DES` inside `DESC`, `CODES`, `OVERRIDES`, `SLIDES`. 199 of the 601 sampled findings are that one
pattern. This is what a recall benchmark scored against a regex oracle is actually measuring, and it
is why the earlier "QUBIT recall 8%" figure was known to be false before it was ever published.

**Read QUBIT's row narrowly.** 23 of 23 is precision on *exclusive* findings only — not overall
precision — at n = 23 across 8 repositories. The bootstrap interval is degenerate (every resample is
100%) and carries no information; the Wilson interval, [85.7%, 100%], is the honest one. What it
supports is a comparison of kind, not a headline: when an AST detector is the only one to fire, it
is usually looking at real cryptography; when a pattern detector is, usually it is not.

---

## 3. QUBIT's own HNDL pass was the worst detector in the study

The paper says the secret/PII pass "trades recall for precision — a noisy secret scanner is worse
than none". That was an intention supported by five unit tests on invented input. Measured on 151
labelled findings from real repositories:

| | count | share |
|---|---:|---|
| a real secret or a real address | 31 | **20.5%** [14.9%, 27.7%] |
| a placeholder, fixture or example | 73 | 48.3% |
| **not an instance of the category at all** | **47** | **31.1%** |

The 47 were not close calls:

```
'icon@2x.png', // Retina image naming              PII-EMAIL
'package@1.0.0.tgz', // NPM package versioning     PII-EMAIL
ssh ubuntu@host.redis.io "cd /var/www/download;    PII-EMAIL
git@github.com:multica-ai/multica.git              PII-EMAIL
0.4365079365079365                                 PII-CREDIT-CARD   (a doctest float)
Password = "password",                             SECRET-HARDCODED-PW  (an enum member)
```

Sixteen digits after a decimal point start with 4 and match the Visa pattern exactly; `\b` does not
help, because `.` *is* a word boundary.

### Fixed, and re-measured against the same labels

`recheck.py` re-runs the scanner over exactly the lines that were labelled:

```
  label       labelled  still reported   dropped
  USE               31              31         0
  MENTION           73              58        15
  ABSENT            47               0        47

  real findings kept: 31/31    outright false positives dropped: 47/47
  precision on this sample: 34.8%, was 20.5%
```

Both halves matter. A filter that dropped everything would score perfectly on the false positives
and be worthless; **all 31 genuine findings survived**. Pinned in
`packages/qubit-scanner/tests/test_secrets_precision.py`, every case a real line from the corpus.

The 58 remaining mentions are test fixtures with plausible values — `password123`, `sk-test`,
`alice@gmail.com` in a test assertion. Separating those needs "is this a test file", which is a
policy question about what an inventory should show, not a detection bug. It is left open.

---

## 4. The held-out cohort: the repairs were not overfitting

Everything above is **in-sample**. The classifier's word-boundary defect and the scanner's filters
were both found in those 601 items and repaired against them, so re-scoring on the same items
answers "were these specific defects fixed" and cannot answer "does it work". The two questions look
identical in a table and are not the same question.

So a second cohort was drawn — 200 findings, from the clean sweep, excluding every already-labelled
id (`pool.py --exclude-labelled labels.jsonl --seed 20260822`), labelled under the same protocol,
scored with no further repair of anything.

### The screening classifier holds

| | calibration (in-sample) | **held-out** |
|---|---|---|
| scored | 448 | 149 |
| raw agreement | 84.8% | **85.2%** |
| **Cohen's κ** | 0.762 | **0.758** |
| `ABSENT` precision | 95.8% [92.2%, 97.8%] | 94.9% [87.5%, 98.0%] |
| `USE` precision | 76.6% [68.4%, 83.2%] | 80.0% [66.2%, 89.1%] |
| `MENTION` precision | 72.7% [63.7%, 80.2%] | 65.4% [46.2%, 80.6%] |

κ moved by 0.004. The fix that took it from 0.279 to 0.762 was derived from the calibration set and
generalises to items it was never shown. `MENTION` is the weak class in both cohorts, and is where
the remaining error lives.

### The HNDL repair shows up on findings nobody had looked at

The two cohorts were drawn from **different sweeps** — calibration before the scanner fix, held-out
after — over disjoint findings:

| | n | use rate |
|---|---|---|
| calibration, before the fix | 151 | 20.5% [14.9%, 27.7%] |
| **held-out, after the fix** | 51 | **47.1% [34.1%, 60.5%]** |

The Wilson intervals do not overlap. This is the out-of-sample version of the 34.8% above, and it is
the stronger claim: the earlier figure could have been a re-fit, and this one cannot be.

### What the held-out cohort does not settle

QUBIT's *cryptographic* arm remains unmeasured. It contributed 23 exclusive crypto findings to the
calibration cohort and 4 to the held-out one, all labelled `USE`. That is not 100% precision; it is
a sample too small to have a precision. The cause is structural and worth stating plainly: **799 of
QUBIT's 866 exclusive corpus findings are HNDL categories** the classifier declines to judge by
name, so there is very little exclusive crypto left to sample. Reporting 27/27 as a headline would
be the same error this whole exercise exists to catch.

| detector | n | held-out use rate | bootstrap over repos |
|---|---|---|---|
| cryptoscan | 17 | 64.7% [41.3%, 82.7%] | n=2, too few repositories |
| pqaudit | 128 | 24.2% [17.6%, 32.3%] | [9.6%, 40.4%] n=11 |
| qubit | 4 | 100% [51.0%, 100.0%] | one repository only |

> **Corpus-level counts in this section (866 exclusive findings, 799 of them HNDL) are from the
> sweep that produced these labels.** Detection has changed since — rules describing one site are
> now reconciled, and Swift gained ML-KEM/ML-DSA rules — so those totals are re-derived by the next
> sweep. The label-level figures above do not move: an item's id is a statement about a line of
> source, and `score.py` reads the archived cohort worksheets, not the current sweep output.

---

## How the labels were made

Full rules in [`PROTOCOL.md`](PROTOCOL.md), written before any label was assigned and not revised
afterwards. In short:

- **One site, one question.** *Does the code at this line perform, configure or select a
  cryptographic operation of the named family?* Not "is this a vulnerability".
- **Four answers.** `USE`, `MENTION` (the name is there as data or prose), `ABSENT` (the name is not
  there at all), `AMBIGUOUS` (1 of 601).
- **Blind.** `worksheet.json` carries the id, repository, file, line, family and ±3 lines of source.
  The detector, the rule id and the heuristic's opinion live in `key.json`, a separate file, unread
  until scoring. One of the four detectors was written by the person running this.
- **Stable ids.** An item's id is a hash of `(repo, path, line, family)`, so labels survive a re-run
  of the sweep or a change to any detector.

### The annotator is a threat to validity, and is stated as one

There is one annotator, and the labelling was done by a large language model (Claude, Opus 5)
reading the blinded worksheet under the rules above, supervised by the author. Three things bound
what that is worth:

1. It is blind to provenance — it cannot favour QUBIT, because it cannot see which findings are
   QUBIT's.
2. Every label ships as data, with a one-line reason each, so a reviewer can disagree with any
   single one and recompute.
3. It is a second opinion, not an oracle. The quantity reported is **agreement between two
   independently constructed annotators** — a mechanical classifier and a language model — and the
   error rates that agreement implies. An expert human pass on a subset, with κ against these
   labels, is the obvious strengthening and is not claimed here.

---

## Files

| file | what it is |
|---|---|
| `PROTOCOL.md` | the labelling rules, fixed before the first machine label and never revised |
| `HUMAN_PROTOCOL.md` | the human pass, registered before the first human label |
| `pool.py` | draws the blind stratified sample → `worksheet.json` + `key.json` |
| `cohorts/` | the archived per-cohort worksheets and keys, so a redraw cannot destroy them |
| `show.py` | prints a batch for the annotator; physically cannot read `key.json` |
| `labels.jsonl` | **the data**: 801 labels, each with a reason, an annotator and a cohort |
| `score.py` | confusion matrix, κ, Wilson intervals, bootstrap over repositories |
| `recheck.py` | re-runs the fixed scanner over the labelled lines and reports what moved |
| `human.py` | draws and collects the human pass; blinding enforced by test |
| `agreement.py` | human vs heuristic, human vs model, and the annotator against themselves |

```bash
uv run python benchmarks/adjudication/score.py --cohort calibration   # in-sample
uv run python benchmarks/adjudication/score.py --cohort holdout       # out-of-sample
uv run python benchmarks/adjudication/recheck.py                      # did the fixes work

uv run python benchmarks/adjudication/human.py label --annotator <name>   # the human pass
uv run python benchmarks/adjudication/agreement.py
```

Redrawing (`pool.py`) is safe: an item's id is `sha1(repo|path|line|family)`, so labels carry over a
re-run of the sweep, a re-draw of the sample, and a change to any detector.

## Why the intervals are what they are

Every proportion carries a **Wilson score interval**, not a normal approximation — at n = 23 the
normal approximation puts the upper bound above 100%.

The bootstrap resamples **repositories, not findings**. Findings inside one repository are nowhere
near independent: eleven of the 601 are the same address in one checked-in fixture file, and 199 are
`DES` inside a SQL `ORDER BY`. Resampling findings would treat those as independent evidence and
produce intervals several times too narrow. The repository is the unit that was actually sampled, so
it is the unit that is resampled.

Where a detector's findings all fall the same way, the bootstrap interval collapses to a point. That
is reported as degenerate rather than as a tight interval, because it is the absence of variation in
a small sample and not the presence of precision.
