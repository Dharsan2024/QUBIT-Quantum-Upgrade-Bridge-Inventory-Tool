"""How far the language model, the heuristic, and a person are from each other.

`score.py` answers "how well does the screening classifier reproduce the labels". It cannot answer
"are the labels right", because both of its inputs are machines. This module is the only place in
the benchmark where a human judgement enters, and it reports three quantities that a reviewer of
`PROTOCOL.md`'s stated threat to validity will want in this order:

1. **Human vs the heuristic.** The corpus-level use/mention result rests entirely on
   `adjudicate.py`. This is that classifier measured against a person rather than against a model,
   and it is the number the paper's central claim actually depends on.
2. **Human vs the language model.** How much of the 801-label pass a person would have agreed with.
   Reported as kappa with a confusion matrix, because the *direction* of the disagreement decides
   whether the model was generous to the detectors or harsh on them, and those are different
   problems.
3. **The human against themselves.** With one annotator there is no inter-rater kappa. Items shown
   twice give an intra-rater one instead -- a weaker substitute (Gwet 2014; Hallgren 2012), and one
   that bounds the other two: no annotator can agree with a machine more reliably than they agree
   with themselves.

**Reweighting.** `human.py` deliberately enriched the sample for items where the two machines
disagreed, so raw agreement here is *pessimistic* -- it is measured on a sample two-thirds composed
of the hard cases. Post-stratified figures reweight each stratum by how common it is in the full
labelled population, and both are printed. Quoting only the raw number would understate agreement;
quoting only the reweighted one would hide that the hard cases are where the disagreement lives.

For the head-to-head comparisons an item shown twice contributes its **first** judgement only. The
second exists to measure the annotator, and letting it also vote would count one person twice.

    uv run python benchmarks/adjudication/agreement.py
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from adjudicate import classify  # noqa: E402
from human import HEURISTIC_TO_LABEL, load_cohorts, machine_labels, stratum_of  # noqa: E402
from population import wilson_interval  # noqa: E402

USE, MENTION, ABSENT, AMBIGUOUS = "USE", "MENTION", "ABSENT", "AMBIGUOUS"
ORDER = (USE, MENTION, ABSENT, AMBIGUOUS)
BOOTSTRAP_ROUNDS = 2000
SEED = 20260822
WIDTH = 92


def kappa(pairs: list[tuple[str, str]], weights: list[float] | None = None) -> float | None:
    """Cohen's kappa, optionally with a weight per pair for post-stratification.

    Weights multiply each observation's contribution to both the observed and the expected
    agreement, which is what post-stratifying a two-rater table amounts to: it asks what the table
    would have looked like had the strata been sampled in proportion.
    """
    if not pairs:
        return None
    w = weights or [1.0] * len(pairs)
    total = sum(w)
    if total <= 0:
        return None
    observed = sum(wi for (a, b), wi in zip(pairs, w, strict=True) if a == b) / total
    left: dict[str, float] = defaultdict(float)
    right: dict[str, float] = defaultdict(float)
    for (a, b), wi in zip(pairs, w, strict=True):
        left[a] += wi
        right[b] += wi
    expected = sum((left[k] / total) * (right[k] / total) for k in set(left) | set(right))
    if expected >= 1.0:
        return None
    return (observed - expected) / (1 - expected)


def matrix(pairs: list[tuple[str, str]], rows_label: str, cols_label: str) -> None:
    present = [c for c in ORDER if any(c in pair for pair in pairs)]
    counts = Counter(pairs)
    print(f"\n    rows = {rows_label}, columns = {cols_label}\n")
    print(" " * 14 + "".join(f"{c:>10}" for c in present))
    for r in present:
        print(f"    {r:<10}" + "".join(f"{counts.get((r, c), 0):>10}" for c in present))


def human_labels(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(
            f"no {path.name}. Draw and label the human sample first:\n"
            f"  uv run python benchmarks/adjudication/human.py draw\n"
            f"  uv run python benchmarks/adjudication/human.py label --annotator <name>"
        )
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def bootstrap_kappa(rows: list[dict], rounds: int = BOOTSTRAP_ROUNDS) -> tuple[float, float] | None:
    """Resample repositories, for the same clustering reason `score.py` documents."""
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_repo[row["repository"]].append(row)
    names = sorted(by_repo)
    if len(names) < 2:
        return None
    rng = random.Random(SEED)  # noqa: S311 - resampling, not cryptography
    draws = []
    for _ in range(rounds):
        picked = [rng.choice(names) for _ in names]
        pairs = [(r["a"], r["b"]) for name in picked for r in by_repo[name]]
        value = kappa(pairs)
        if value is not None:
            draws.append(value)
    if not draws:
        return None
    draws.sort()
    return draws[int(0.025 * len(draws))], draws[min(len(draws) - 1, int(0.975 * len(draws)))]


def _inter_rater(args: argparse.Namespace, by_id: dict, visible: dict) -> dict | None:
    """A second annotator against the first, over the items both of them judged.

    This is the figure an intra-rater kappa stands in for, and the substitution is the largest
    remaining methodological weakness in the study. The section prints nothing at all when no
    second rater has labelled anything, rather than printing a zero -- an absent measurement and a
    measurement of zero are not the same claim.
    """
    second_path = getattr(args, "second", None)
    if second_path is None or not Path(second_path).exists():
        return None
    second_rows = [
        json.loads(line)
        for line in Path(second_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not second_rows:
        return None

    # Last judgement wins for each id, matching how the primary side is collapsed.
    second: dict[str, str] = {str(row["id"]): row["label"] for row in second_rows}
    first: dict[str, str] = {i: rs[-1]["label"] for i, rs in by_id.items()}
    shared = sorted(set(first) & set(second))

    print("\n" + "-" * WIDTH)
    print("A SECOND ANNOTATOR AGAINST THE FIRST")
    print("  the figure the intra-rater kappa above is a substitute for.")
    if not shared:
        print("\n  no item has been judged by both")
        return None

    pairs = [(first[i], second[i]) for i in shared]
    agree = sum(1 for a, b in pairs if a == b)
    band = wilson_interval(agree, len(pairs))
    value = kappa(pairs)
    print(f"\n  n              {len(pairs)}")
    print(f"  raw agreement  {agree / len(pairs):.1%} [{band.low:.1%}, {band.high:.1%}]")
    print(f"  Cohen's kappa  {value:.3f}" if value is not None else "  Cohen's kappa  undefined")

    boot = [
        {"repository": visible[i]["repository"], "a": first[i], "b": second[i]}
        for i in shared
        if i in visible
    ]
    interval = bootstrap_kappa(boot)
    if interval:
        print(f"  bootstrap over repositories  [{interval[0]:.3f}, {interval[1]:.3f}]")

    matrix(pairs, "first annotator", "second annotator")
    annotators = sorted({row.get("annotator", "?") for row in second_rows})
    return {
        "n": len(pairs),
        "kappa": value,
        "raw_agreement": agree / len(pairs),
        "second_annotators": annotators,
    }


def report(args: argparse.Namespace) -> int:
    visible, hidden = load_cohorts()
    model = machine_labels(args.labels)
    # Recomputed over the whole labelled population rather than read from `human_strata.json`,
    # which only ever holds the drawn items. Reading it would make every item outside the sample
    # look like the default stratum and the post-stratification weights meaningless.
    strata = {
        ident: stratum_of(hidden[ident], llm)
        for ident, llm in model.items()
        if ident in visible and ident in hidden
    }
    rows = human_labels(args.human)

    # First judgement per id for the head-to-heads; every judgement kept for the repeat analysis.
    by_id: dict[str, list[dict]] = defaultdict(list)
    for row in sorted(rows, key=lambda r: r["seq"]):
        by_id[row["id"]].append(row)
    first = {i: rs[0]["label"] for i, rs in by_id.items()}

    annotators = sorted({r.get("annotator", "?") for r in rows})
    print("\n" + "=" * WIDTH)
    print(f"{len(rows)} human judgements over {len(by_id)} items by {', '.join(annotators)}")
    print(f"  distribution: {dict(Counter(first.values()))}")

    # Population proportions, for post-stratification.
    population = Counter(strata.get(i, "agree") for i in model if i in visible)
    sampled = Counter(strata.get(i, "agree") for i in first)
    weight = {
        s: (population[s] / sampled[s]) if sampled.get(s) else 0.0
        for s in set(population) | set(sampled)
    }
    if len(sampled) > 1:
        print(f"  sampled {dict(sampled)} out of a population of {dict(population)}")

    def head_to_head(title: str, other: dict[str, str], note: str) -> None:
        pairs, weights, boot = [], [], []
        for ident, human in first.items():
            if ident not in other or human == AMBIGUOUS or other[ident] == AMBIGUOUS:
                continue
            pairs.append((human, other[ident]))
            weights.append(weight.get(strata.get(ident, "agree"), 1.0))
            boot.append({"repository": visible[ident]["repository"], "a": human, "b": other[ident]})
        if not pairs:
            print(f"\n{title}\n  no comparable items")
            return
        agree = sum(1 for a, b in pairs if a == b)
        raw = kappa(pairs)
        adjusted = kappa(pairs, weights) if len(set(weights)) > 1 else None
        band = wilson_interval(agree, len(pairs))
        print("\n" + "-" * WIDTH)
        print(f"{title}")
        print(f"  {note}")
        print(f"\n  n              {len(pairs)}")
        print(f"  raw agreement  {agree / len(pairs):.1%} [{band.low:.1%}, {band.high:.1%}]")
        print(f"  Cohen's kappa  {raw:.3f}" if raw is not None else "  Cohen's kappa  undefined")
        if adjusted is not None:
            print(
                f"  post-stratified kappa  {adjusted:.3f}  (reweighted to population proportions)"
            )
        interval = bootstrap_kappa(boot)
        if interval:
            print(f"  bootstrap over repositories  [{interval[0]:.3f}, {interval[1]:.3f}]")
        matrix(pairs, "human", title.split(" vs ")[-1].lower())

    # Recomputed from the source line, never read from `key.json`. The stored classes were written
    # by whichever version of the classifier ran that sweep, and for the calibration cohort that is
    # the version whose word-boundary defect this study exists to report -- comparing a person
    # against it would measure a bug that has since been fixed. `score.py` recomputes for the same
    # reason; the two must agree, or they are quietly answering different questions.
    heuristic = {
        i: HEURISTIC_TO_LABEL[cls]
        for i, item in visible.items()
        if (cls := classify(item["source"], item["family"])) in HEURISTIC_TO_LABEL
    }
    head_to_head(
        "HUMAN vs THE SCREENING CLASSIFIER",
        heuristic,
        "adjudicate.py is what the corpus-level result rests on;"
        " this is it measured against a person.",
    )
    head_to_head(
        "HUMAN vs THE LANGUAGE MODEL",
        model,
        "the 801 labels in labels.jsonl, checked against the annotator who supervised them.",
    )

    # --- Which boundary is reliable ------------------------------------------------------------
    # One three-class kappa hides the thing that matters. Every claim in this study about a detector
    # matching text that is not there rests on the ABSENT boundary; only the softer
    # use-versus-mention claims rest on the other one. They have very different reliability, and a
    # single number would misrepresent both.
    def _hndl(ident: str) -> bool:
        rule = str(hidden.get(ident, {}).get("rule_id", "") or "")
        family = str(visible.get(ident, {}).get("family", "") or "")
        return rule.startswith(("SECRET-", "PII-")) or family.startswith(
            ("PII", "HARDCODED", "GITHUB", "PRIVATE")
        )

    comparable = [(i, h, model[i]) for i, h in first.items() if i in model]
    print("\n" + "-" * WIDTH)
    print("WHICH BOUNDARY IS RELIABLE")
    print("  the same items, split by the question being asked of them.")

    collapsed = [
        (ABSENT if h == ABSENT else "PRESENT", ABSENT if m == ABSENT else "PRESENT")
        for _, h, m in comparable
    ]
    if collapsed:
        agree = sum(1 for a, b in collapsed if a == b)
        value = kappa(collapsed)
        band = wilson_interval(agree, len(collapsed))
        print("\n  Is the algorithm there at all?   (ABSENT vs everything else)")
        line = f"    n {len(collapsed)}   agreement {agree / len(collapsed):.1%} "
        line += f"[{band.low:.1%}, {band.high:.1%}]"
        if value is not None:
            line += f"   kappa {value:.3f}"
        print(line)

    three = [(h, m) for _, h, m in comparable]
    value = kappa(three)
    print("\n  Is it a use or a mention?        (all three classes)")
    print(f"    n {len(three)}" + (f"   kappa {value:.3f}" if value is not None else ""))
    for label, subset in (
        ("cryptographic findings", [(h, m) for i, h, m in comparable if not _hndl(i)]),
        ("HNDL categories", [(h, m) for i, h, m in comparable if _hndl(i)]),
    ):
        value = kappa(subset)
        shown = f"kappa {value:.3f}" if value is not None else "kappa undefined"
        print(f"      {label:24} n {len(subset):<4} {shown}")

    directions = Counter((h, m) for _, h, m in comparable if h != m)
    if directions:
        print("\n  Every disagreement, by direction (human -> model):")
        for (h, m), n in directions.most_common():
            print(f"      {h:8} vs {m:8}  {n}")

    repeated = {i: rs for i, rs in by_id.items() if len(rs) > 1}
    print("\n" + "-" * WIDTH)
    print("THE ANNOTATOR AGAINST THEMSELVES")
    print("  items shown twice, unmarked and far apart; the ceiling on both figures above.")
    if not repeated:
        print("\n  no item has been labelled twice yet")
    else:
        pairs = [(rs[0]["label"], rs[1]["label"]) for rs in repeated.values()]
        agree = sum(1 for a, b in pairs if a == b)
        band = wilson_interval(agree, len(pairs))
        value = kappa(pairs)
        print(f"\n  n              {len(pairs)}")
        print(f"  raw agreement  {agree / len(pairs):.1%} [{band.low:.1%}, {band.high:.1%}]")
        print(f"  intra-rater kappa  {value:.3f}" if value is not None else "  kappa undefined")
        flips = [
            (i, rs[0]["label"], rs[1]["label"])
            for i, rs in repeated.items()
            if rs[0]["label"] != rs[1]["label"]
        ]
        for ident, a, b in flips:
            print(f"    {ident}  {a} -> {b}   {visible[ident]['path']}:{visible[ident]['line']}")

    inter = _inter_rater(args, by_id, visible)

    out = {
        "judgements": len(rows),
        "items": len(by_id),
        "annotators": annotators,
        "repeated": len(repeated),
        "inter_rater": inter,
    }
    args.json.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nwrote {args.json}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--human", type=Path, default=HERE / "human_labels.jsonl")
    parser.add_argument("--labels", type=Path, default=HERE / "labels.jsonl")
    parser.add_argument("--json", type=Path, default=HERE / "agreement.json")
    parser.add_argument(
        "--second",
        type=Path,
        default=HERE / "human_labels.second.jsonl",
        help="a second annotator's labels, for an inter-rater kappa; silently skipped if absent",
    )
    return report(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
