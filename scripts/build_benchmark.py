"""Assemble `pqc-migration-bench/` — everything a reader needs to check the claims.

A benchmark release is not a results dump. Its job is to let someone who does not trust the paper
re-derive its numbers, and that means shipping the things that would let them find it wrong:

* the **gate table for every candidate**, including the rejections and the negative controls, so
  corpus selection can be seen to be mechanical
* the **oracle's admission controls**, without which every evidence level is unfalsifiable — a
  reader cannot tell a gate that discriminates from one that says yes to everything
* the **relations spec**, so the metamorphic claims can be read rather than taken on trust
* the **image recipe and the probed library version**, because the oracle's verdicts are only
  reproducible against the library it was probed on
* the **blind labelling packet**, so the precision figure can be recomputed from the raw labels
* every **script**, so each table has a command that regenerates it

Deliberately included even though they weaken the headline: the corpus-selection null result, the
detection comparison QUBIT loses, and the vacuous-expectation counts.

Everything is copied rather than referenced, and a MANIFEST records a SHA-256 for each file, so a
reader can tell whether what they have is what was released.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Item:
    """One file in the release, and why it is there."""

    source: str
    dest: str
    why: str
    #: When absent, the release still builds and the manifest records the absence. A benchmark
    #: that refuses to assemble because one artefact has not been produced yet is a benchmark
    #: nobody assembles.
    required: bool = False


ITEMS: tuple[Item, ...] = (
    # --- corpora -----------------------------------------------------------------------------
    Item(
        "qubit-v2/08-evaluation/corpus_gates.csv",
        "corpora/corpus_gates.csv",
        "every candidate scored, including the rejections and both negative controls",
        required=True,
    ),
    Item(
        "qubit-v2/08-evaluation/PRE-REGISTRATION.md",
        "corpora/PRE-REGISTRATION.md",
        "the gates, endpoints and statistics, fixed before the sweep finished",
        required=True,
    ),
    Item(
        "qubit-v2/08-evaluation/RESULTS-corpus-selection.md",
        "corpora/RESULTS-corpus-selection.md",
        "the null result: zero candidates pass, and which thresholds bind",
    ),
    # --- detection ---------------------------------------------------------------------------
    Item(
        "qubit-v2/05-detection/detection_agreement.csv",
        "detection/detection_agreement.csv",
        "per-file agreement against sonar-cryptography's own corpus",
    ),
    Item(
        "qubit-v2/05-detection/README.md",
        "detection/README.md",
        "the comparison QUBIT loses, and why it is still worth publishing",
    ),
    # --- oracle ------------------------------------------------------------------------------
    Item(
        "packages/qubit-migrate/src/qubit_migrate/params/relations.yaml",
        "oracle/relations.yaml",
        "the metamorphic relations, positive and negative, per family",
        required=True,
    ),
    Item(
        "packages/qubit-migrate/src/qubit_migrate/oracles/shapes.py",
        "oracle/shapes.py",
        "the probed API facts the harness depends on, with the traps documented",
    ),
    Item(
        "packages/qubit-migrate/src/qubit_migrate/oracles/controls.py",
        "oracle/controls.py",
        "the admission controls: without these every evidence level is unfalsifiable",
        required=True,
    ),
    Item(
        "qubit-v2/02-verification/Dockerfile.oracle",
        "oracle/Dockerfile.oracle",
        "the image recipe; the oracle's verdicts hold only against the library it was probed on",
    ),
    Item(
        "qubit-v2/02-verification/evidence-ladder.md",
        "oracle/evidence-ladder.md",
        "what each rung claims, and what a skipped or vacuous gate is worth",
    ),
    # --- policy ------------------------------------------------------------------------------
    Item(
        "packages/qubit-migrate/src/qubit_migrate/params/regimes.yaml",
        "policy/regimes.yaml",
        "the five regimes, their conflicts, and the confidence of each entry",
    ),
    Item(
        "qubit-v2/vendor/standards/README.md",
        "policy/SOURCES.md",
        "which publisher document each regime was read from, and what reading it corrected",
    ),
    Item(
        "qubit-v2/references.md",
        "policy/references.md",
        "every load-bearing claim traced to a source, including the three that were re-sourced "
        "and the four regime entries that changed when the primary text was read",
    ),
    # --- labels ------------------------------------------------------------------------------
    Item(
        "unwanted/paper_evidence/label_packet.csv",
        "labels/label_packet.csv",
        "600 blind findings for two raters; the key is withheld until labels are returned",
    ),
    Item(
        "unwanted/paper_evidence/label_packet_manifest.json",
        "labels/label_packet_manifest.json",
        "seed, strata and sampling rule, so the packet can be rebuilt byte-identically",
    ),
    # --- harness -----------------------------------------------------------------------------
    Item("scripts/corpus_select.py", "harness/corpus_select.py", "regenerates the gate table"),
    Item(
        "scripts/sonar_agreement.py",
        "harness/sonar_agreement.py",
        "regenerates the agreement CSV",
    ),
    Item("scripts/run_arms.py", "harness/run_arms.py", "runs the arms, one OS process per finding"),
    Item(
        "scripts/build_label_packet.py",
        "harness/build_label_packet.py",
        "rebuilds the labelling packet from a database",
    ),
    Item(
        "packages/qubit-migrate/src/qubit_migrate/report/analysis.py",
        "harness/analysis.py",
        "denominator ladder, cluster bootstrap, exact McNemar, verified_accept",
    ),
    Item(
        "packages/qubit-migrate/src/qubit_migrate/report/measurements.py",
        "harness/measurements.py",
        "the byte-reproducible export and the per-path summary that refuses to pool",
    ),
    # --- the evaluation actually run -----------------------------------------------------------
    Item(
        "qubit-v2/08-evaluation/DECISION-corpus.md",
        "corpora/DECISION-corpus.md",
        "the corpus choice, dated and recorded BEFORE any arm ran, with no threshold moved",
    ),
    Item(
        "qubit-v2/08-evaluation/RESULTS-G5-oracle.md",
        "oracle/RESULTS-G5-oracle.md",
        "G5 run for the first time and FAILING: 116 passing tests against a floor of 500, and "
        "exactly 1 of 34 findings on a covered line",
    ),
    Item(
        "qubit-v2/02-verification/Dockerfile.pyload",
        "oracle/Dockerfile.pyload",
        "the corpus image; the project is deliberately NOT installed, so the overlay is what runs",
    ),
    Item(
        "qubit-v2/08-evaluation/RESULTS-B0-arm.md",
        "arms/RESULTS-B0-arm.md",
        "7 codemod patches passing every runnable gate, all of which break authentication",
    ),
    Item(
        "qubit-v2/08-evaluation/RESULTS-pilot-arm.md",
        "arms/RESULTS-pilot-arm.md",
        "the same outcome from a language model: 11 patches, two generators, all broken",
    ),
    Item(
        "qubit-v2/08-evaluation/seed-pyload.json",
        "arms/seed-pyload.json",
        "what the arms were seeded from: 32 ready tasks over 5 rules",
    ),
    Item("scripts/seed_corpus.py", "harness/seed_corpus.py", "rebuilds the arm template database"),
    Item(
        "scripts/kappa.py", "harness/kappa.py", "Cohen's kappa per stratum, and the disagreements"
    ),
    Item(
        "qubit-v2/08-evaluation/RESULTS-8.4-patch-review.md",
        "arms/RESULTS-8.4-patch-review.md",
        "the blind patch review: 1 of 7 patches mergeable, and the failure no gate looks for",
    ),
    Item(
        "unwanted/paper_evidence/review_packet.csv",
        "arms/review_packet.csv",
        "the blind review packet, arm and generator stripped",
    ),
    Item(
        "unwanted/paper_evidence/review_rater_a.csv",
        "arms/review_rater_a.csv",
        "rater A's verdicts with per-patch reasoning",
    ),
    Item(
        "packages/qubit-migrate/src/qubit_migrate/protocol_contract.py",
        "oracle/protocol_contract.py",
        "the guard that withholds migrations of cryptography another party defines",
    ),
    Item(
        "qubit-v2/05-detection/fp_filter.json",
        "labels/fp_filter.json",
        "the false-positive filter: 72.4% -> 94.9% precision, with the ablation",
    ),
    Item("scripts/fp_filter.py", "harness/fp_filter.py", "trains and cross-validates the filter"),
    Item(
        "scripts/analyse_arms.py",
        "harness/analyse_arms.py",
        "the denominator ladder over the arm databases",
    ),
    Item(
        "qubit-v2/08-evaluation/RESULTS-L3-oracle-runs.md",
        "oracle/RESULTS-L3-oracle-runs.md",
        "the metamorphic oracle running on real patches (0/39 -> 8/8), what it catches, and the "
        "call-site gap it does not",
    ),
    Item(
        "qubit-v2/02-verification/Dockerfile.oracle-flexget",
        "oracle/Dockerfile.oracle-flexget",
        "a corpus oracle image; the generic one lacks the imports a patched module needs",
    ),
    Item(
        "packages/qubit-migrate/tests/test_oracle_discriminates.py",
        "oracle/test_oracle_discriminates.py",
        "proof the oracle can FAIL: a stub primitive and a strong name aliased to a weak algorithm",
    ),
    # --- detection precision ---------------------------------------------------------------------
    Item(
        "qubit-v2/05-detection/RESULTS-precision.md",
        "labels/RESULTS-precision.md",
        "per-stratum precision, including the 0% stratum and the substring-matching sensitivity "
        "analysis",
    ),
    Item(
        "unwanted/paper_evidence/labels_rater_a.csv",
        "labels/labels_rater_a.csv",
        "rater A's 600 verdicts with per-item notes",
    ),
    Item(
        "unwanted/paper_evidence/RATING-INSTRUCTIONS-CLEAN.md",
        "labels/RATING-INSTRUCTIONS-CLEAN.md",
        "the rubric given to the independent rater, deliberately without rater A's conventions",
    ),
    # --- findings ----------------------------------------------------------------------------
    Item(
        "qubit-v2/11-implementation-findings.md",
        "FINDINGS.md",
        "defects found by building it, including the ones in QUBIT's own gates",
    ),
)


#: The release's front page. Generated with the tree so it cannot fall out of step with it.
README = """# pqc-migration-bench

Everything needed to check the claims in the QUBIT paper - **including the artefacts that weaken
them.** A benchmark whose job is to make its author look right is not a benchmark.

## What is here

| directory | contents |
|---|---|
| `corpora/` | every candidate's gate score, the negative controls, the pre-registration |
| `detection/` | per-file agreement against sonar-cryptography's own test corpus |
| `oracle/` | metamorphic relations, probed API facts, admission controls, image recipe |
| `policy/` | the five regimes, where they disagree, and the document each was read from |
| `labels/` | the blind labelling packet, rater A's verdicts, and per-stratum precision |
| `arms/` | the arms that were run, and the patches that passed every gate while breaking the app |
| `harness/` | every script, so each table has a command that regenerates it |
| `FINDINGS.md` | defects found by building this, including several in QUBIT's own gates |
| `MANIFEST.json` | SHA-256 per file, so you can tell whether this is what was released |

## Start with the parts that undermine the paper

* **`corpora/RESULTS-corpus-selection.md`** - 36 candidates scored, **zero pass the gates**. The
  thresholds were fixed in advance and are reported unmet rather than relaxed.
* **`detection/README.md`** - a detection comparison QUBIT **loses** on the one library both tools
  cover, published with the reason it is still worth having.
* **`arms/RESULTS-B0-arm.md`** - the result that undermines the tool most, and the one worth
  reading first. **Eleven patches, from a deterministic codemod and from a language model, all
  passing `applies`, `parses`, `symbols`, `compiles` and `rescan` - and all breaking
  authentication.**
  The scanner stopped seeing MD5; that is the entire content of `rescan: pass`.
* **`oracle/RESULTS-G5-oracle.md`** - the oracle gate run for the first time and **failing**. The
  chosen corpus has 116 passing tests against a pre-registered floor of 500, 14.8% coverage, and
  **exactly one of its 34 crypto findings on a line the suite executes**. The pre-registered primary
  endpoint is unmeasurable here, and that is reported rather than substituted.
* **`labels/RESULTS-precision.md`** - one stratum at **0% precision**: 75 of 75 `library` findings
  are algorithms a dependency *could* provide, recorded as uses at `requirements.txt:0`.
* **`FINDINGS.md`** - defects found while building this. Nine were mechanisms that reported success
  while measuring nothing, and several were in QUBIT's own gates.
* **`policy/SOURCES.md`** - reading the publishers' own PDFs **corrected four regime entries**,
  two of them after a previous correction had already been made confidently in the other
  direction. The `confidence` field on each entry records whether it was read from the standard or
  from something quoting it, so a reader can weigh the entries differently.

## The one artefact everything else depends on

`oracle/controls.py`. Two fixtures per relation family: a correct migration that must **pass**, and
a deliberately broken one that must **fail** on named relations while remaining invisible to the
weaker ones.

Without those, an evidence level is unfalsifiable - a reader has no way to tell a gate that
discriminates from a gate that says yes to everything. Any figure citing an evidence level should
be read against this file first.

## What is deliberately absent

* **The corpora themselves.** Third-party source trees, referenced by name and commit.
* **`label_key.csv`.** Withheld until both raters return their labels. Releasing the join would let
  a rater see QUBIT's own verdict, which turns judging into agreeing.
* **Arm results.** Not run: no corpus passes the gates. See `corpora/RESULTS-corpus-selection.md`.

## Reproducing

```bash
uv run python harness/corpus_select.py --root <corpora> --out corpora/
uv run python harness/sonar_agreement.py
docker build -t qubit-eval/oracle:py312 -f oracle/Dockerfile.oracle .
```

The oracle's verdicts hold only against the library version it was probed on - `cryptography`
49.0.0, recorded in `oracle/shapes.py`. Re-probe on a version bump; three of the facts in that file
are traps that would otherwise fail every *correct* patch.
"""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def build(root: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    entries: list[dict[str, object]] = []
    missing: list[str] = []
    for item in ITEMS:
        src = root / item.source
        if not src.exists():
            missing.append(item.source)
            if item.required:
                raise SystemExit(f"required artefact missing: {item.source}")
            entries.append({"path": item.dest, "why": item.why, "present": False})
            continue
        dst = out / item.dest
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        entries.append(
            {
                "path": item.dest,
                "why": item.why,
                "present": True,
                "sha256": _sha256(dst),
                "bytes": dst.stat().st_size,
                "source": item.source,
            }
        )

    manifest = {
        # UTC with an explicit offset. A naive timestamp is read as local time by half the tools
        # that will open this.
        "built_at": datetime.now(UTC).isoformat(),
        "files": sorted(entries, key=lambda e: str(e["path"])),
        "absent": sorted(missing),
        "what_this_is": (
            "Everything needed to check the claims, including the artefacts that weaken them: "
            "the corpus-selection null result, the detection comparison QUBIT loses, and the "
            "vacuous-expectation counts."
        ),
        "not_included": {
            "corpora themselves": (
                "third-party source trees, referenced by name and commit rather than vendored"
            ),
            "label_key.csv": (
                "withheld deliberately until both raters return their labels — releasing the "
                "join would let a rater see QUBIT's verdict and turn judging into agreeing"
            ),
            "arm results beyond B0 and the pilot": (
                "A1/B1-fwd/B1-rev/A2/B2 were not run. G5 fails on this corpus, so the "
                "pre-registered primary endpoint `verified_accept` is ~0 by construction and the "
                "paired comparisons would rank arms on an endpoint none of them can reach. "
                "See RESULTS-G5-oracle.md"
            ),
        },
    }
    (out / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    # Generated, not placed beside the tree by hand. `build` starts by removing `out`, so a
    # hand-written README survives exactly until the next rebuild — as one already did. Anything
    # that must be in the release has to be produced BY the release.
    (out / "README.md").write_text(README, encoding="utf-8", newline="")
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path())
    ap.add_argument("--out", type=Path, default=Path("pqc-migration-bench"))
    args = ap.parse_args()
    manifest = build(args.root, args.out)
    present = sum(1 for f in manifest["files"] if f["present"])  # type: ignore[index,union-attr]
    print(f"built {args.out}: {present}/{len(ITEMS)} artefacts")
    for name in manifest["absent"]:  # type: ignore[union-attr]
        print(f"  absent (optional): {name}")


if __name__ == "__main__":
    main()
