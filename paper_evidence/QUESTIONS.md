# Open author decisions

Decisions a person must make. Where the repository already settles part of an answer it is quoted
as context, kept separate from what is still open. Nothing below is filled in on the author's
behalf.

---

## Q1. Target venue, and therefore template and page limit

**Open.** Established constraints:

* Budget **₹15,000 total**, which rules out any open-access APC (IEEE Access is ≈ $1,950) and any
  conference where acceptance obliges author registration at international rates.
* Journals on the subscription track — IEEE TDSC, Springer EMSE, Elsevier Computers & Security —
  charge nothing to publish and have no deadline race.
* **MSR 2027** technical papers close **20 October 2026**. CORE A, and the closest genre fit: a
  mined corpus, agreement measurement, and sampling methodology as first-class contributions.
* An **arXiv preprint** costs nothing and is citable the day it posts.

**Still needed:** the actual choice.

---

## Q2. The novelty claim, in one sentence

**Open, and it has moved.** The original claim was the synthesis — CRQC Monte-Carlo fused with AST
discovery, local-model transformation behind a validation gate, CBOM output. The measurement work
supports a different and stronger candidate: that a detector's own screening instrument can be
wrong in the direction that flatters the tool under test, and that this is detectable and
quantifiable with capture–recapture plus blind hand labelling.

These imply different papers, different venues, and different related work. The author must choose.

---

## Q3. Which baselines are the right comparison

**Partly settled by what has been run:** `pqaudit`, CWE-filtered `semgrep`, `cryptoscan`, and IBM's
`sonar-cryptography` (which reads 7 of the 26 repositories and is gated by an applicability check).

**Still needed:** whether CryptoGuard and CogniCrypt must also appear. They are named in the related
work and have **not** been run. `docs/PAPER_AUTHORING_KIT.md` already carries a caution against
tabulating their published numbers beside these — different corpora, different scoring.

---

## Q4. Dataset redistribution

**Partly documented.** The sampling frame, the fixed-seed draw and the pre-registered inclusion
criterion (`MIN_DETECTORS_WITH_FINDINGS = 2`) are in `benchmarks/corpus/`. Each repository's licence
and pinned commit are in `corpus.lock.json` and reproduced in `tables/T04_dataset.csv`.

**Still needed:** whether the corpus itself is redistributed, or only the lockfile and the scripts
that reconstruct it. This is a licensing question across 26 separate projects, one of which carries
`NOASSERTION`.

---

## Q5. Whether an intra-rater κ is acceptable in place of an inter-rater one — RESOLVED

No longer a live decision: a second independent annotator (Akshay Kumar S) labelled 50 blind items
against the primary annotator's own sample. See Limitations L2 for the measured figures — a real
inter-rater κ now stands in the pack, not a substitute. The residual open question is only whether
the observed use/mention disagreement pattern (κ = 0.399) would hold at a larger n; it is not a
methodological gap any more, it is a direction for a future, larger rater panel.

---

## Q6. Author list, order, ORCIDs, affiliations, CRediT roles

**Open.** The repository names Dharsan L (43614012) and Akshay Kumar S (43614004), BE-CSE
(Cybersecurity). Order, ORCIDs, affiliation strings and CRediT roles are recorded nowhere and must
not be guessed.

**Related and unavoidable:** a language model produced 801 of the labels and much of the
implementation. How that is disclosed — CRediT, acknowledgements, or a methods statement — is an
authorship decision, and several venues now have explicit policies on it.

---

## Q7. Funding and conflicts of interest

**Open.** Nothing in the repository records either.

---

## Q8. Ethics, and one decision that is needed regardless

**Open.** All scanning is of public open-source repositories at pinned commits. The only live-system
testing is against locally-run containers (a dev-mode Vault, a local nginx). No third-party system
was probed. Whether that needs institutional sign-off is an institutional question.

**Needs a decision either way:** the corpus contains **real personal email addresses** in
checked-in fixture files, and some appear in labelled data. Publishing them reproduces personal
data. The author should decide whether to redact before anything is released.

---

## Q9. Prior preprint or thesis overlap

**Open.** No preprint exists yet. Overlap with the final-year thesis is likely and most venues
require it to be declared.

---

## Q10. Scope limits — drafted from the code, needs endorsement as a claim

* Does not *prove* the cryptographic correctness of a rewrite. It validates that the patch applies,
  parses, compiles, passes tests, and no longer matches the rule.
* Does not resolve algorithms bound at run time; those are reported `UNRESOLVED` deliberately.
* Does not analyse binaries, container images or deployment artifacts — source, configuration,
  certificates, manifests, network handshakes and Vault only.
* Has **no explicit post-quantum rules** for bash, dart, kotlin, php, powershell, ruby, scala or
  sql, though the generic resolvers in several of those packs will still report a PQC algorithm
  named in source (`tables/T05_coverage.csv`).
* Does not distinguish test fixtures from production code, which is the largest single source of
  HNDL false positives and the exact point where the human annotator and the model disagree.

---

## Q11. Threats to validity — drafted, needs the author's wording

* **Internal.** The annotator supervised the machine labelling pass and is therefore not naive.
  Blinding reduces but does not eliminate anchoring. The human sample was enriched for
  disagreement, which makes raw agreement pessimistic; post-stratified figures are reported
  alongside.
* **External.** 11 primary languages rather than the 13 strata drawn, C over-represented at six
  repositories, GitHub-only, popular projects only. See L7.
* **Construct.** "Use or mention" turns out not to be reliably communicable between annotators
  (κ = 0.575, and 0.381 on the HNDL categories). The construct is part of what is being measured,
  and the paper should say so rather than treat the labels as ground truth.
* **Conclusion.** Bootstrap is over repositories rather than findings, because findings cluster
  heavily within a repository. Several detector-level intervals rest on very few repositories and
  are reported as degenerate rather than as tight.
