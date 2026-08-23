"""Draw and collect a *human* pass over items the language model has already labelled.

Every one of the 801 labels in `labels.jsonl` was produced by Claude Opus 5 reading the blinded
worksheet. That is disclosed in `PROTOCOL.md` and it is the single largest threat to validity in
this evaluation: the reported quantity is agreement between a mechanical classifier and a language
model, and a reviewer is entitled to ask what either has to do with the truth. This module is the
answer to that question. It puts a person in front of the same blinded evidence and reports how far
the model is from them.

Three things it is careful about.

**It never shows the model's label.** `human_worksheet.json` carries the same visible fields
`show.py` prints -- id, repository, path, line, family, source, +/-3 lines of context -- and nothing
else. An annotator who can see that the model said `MENTION` is not an independent annotator, and
the number that came out would be a measure of anchoring rather than of agreement.

**It oversamples disagreement, and says so.** Items where the model and the heuristic already agree
carry little information: they are mostly `DES` inside `ORDER BY`, and a human confirming two
hundred of those measures patience, not agreement. The draw is therefore stratified, weighted
towards items where the two machines disagreed. That deliberately makes raw kappa *pessimistic* --
the sample is enriched for hard cases -- so `agreement.py` reports both the raw figure and one
reweighted back to the population proportions. The stratum of each item is written to
`human_strata.json`, which the annotator never opens.

**It measures the human too.** `--repeats N` puts N of the drawn items into the sequence twice, far
apart and unmarked. Relabelling them differently is not a mistake to hide: it is the only available
estimate of how stable the human standard itself is. With one annotator there is no inter-rater
kappa to report, and an intra-rater one is the recognised substitute (Gwet 2014; Hallgren 2012). It
is weaker, and the paper says so rather than implying otherwise.

    uv run python benchmarks/adjudication/human.py draw --count 100 --repeats 20
    uv run python benchmarks/adjudication/human.py label --annotator dharsan
    uv run python benchmarks/adjudication/agreement.py

`label` is resumable: it skips any sequence position already in `human_labels.jsonl`, so the pass
can be done in several sittings without losing place or re-showing an item.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from adjudicate import CODE, COMMENT, STRING_LITERAL, SUBSTRING  # noqa: E402

COHORTS = HERE / "cohorts"
WORKSHEET = HERE / "human_worksheet.json"
STRATA = HERE / "human_strata.json"
LABELS = HERE / "human_labels.jsonl"
SEED = 20260822

#: The first annotator writes the unsuffixed files. A second rater gets their own worksheet and
#: label file so neither can see the other's work, which is the whole point of an inter-rater
#: figure. `--rater` names the suffix.
PRIMARY = "primary"


def worksheet_for(rater: str) -> Path:
    return WORKSHEET if rater == PRIMARY else HERE / f"human_worksheet.{rater}.json"


def strata_for(rater: str) -> Path:
    return STRATA if rater == PRIMARY else HERE / f"human_strata.{rater}.json"


def labels_for(rater: str) -> Path:
    return LABELS if rater == PRIMARY else HERE / f"human_labels.{rater}.jsonl"


USE, MENTION, ABSENT, AMBIGUOUS = "USE", "MENTION", "ABSENT", "AMBIGUOUS"
VALID = {USE, MENTION, ABSENT, AMBIGUOUS}

#: Same mapping PROTOCOL.md fixed before labelling; duplicated rather than imported from score.py
#: so that drawing a sample cannot be affected by a later change to how scoring reports.
HEURISTIC_TO_LABEL = {
    CODE: USE,
    STRING_LITERAL: MENTION,
    COMMENT: MENTION,
    SUBSTRING: ABSENT,
}

DISAGREE, AGREE = "disagree", "agree"


def stratum_of(hidden_row: dict, llm_label: str) -> str:
    """Which stratum an item belongs to, by the rule fixed before the human sample was drawn.

    Shared with `agreement.py` so that the population the sample is reweighted back to is defined
    by exactly the same rule that selected it. Computing it twice, slightly differently, is how a
    post-stratified figure quietly stops meaning anything.
    """
    predicted = HEURISTIC_TO_LABEL.get(hidden_row.get("heuristic", ""))
    if predicted is None:
        # A category the heuristic declines to judge by name -- every HNDL finding lands here.
        # These are exactly the items no machine has an opinion on, so they are as informative
        # as an outright disagreement and are pooled with them.
        return DISAGREE
    return DISAGREE if predicted != llm_label else AGREE


WIDTH = 100

#: Keystrokes. `?` is AMBIGUOUS and is a real answer, not a refusal to answer -- the protocol
#: requires it whenever the line alone cannot settle the question, and pressing it is always
#: preferable to guessing.
KEYS = {"u": USE, "m": MENTION, "a": ABSENT, "?": AMBIGUOUS}


def load_cohorts() -> tuple[dict[str, dict], dict[str, dict]]:
    """Every item ever drawn, and its hidden provenance, keyed by id.

    Reads the archived per-cohort directories rather than the top-level `worksheet.json`, which
    holds only the most recent draw: a human sample that could see just the last one would be a
    sample of the held-out set wearing the name of the whole study.
    """
    visible: dict[str, dict] = {}
    hidden: dict[str, dict] = {}
    for directory in sorted(COHORTS.iterdir()) if COHORTS.is_dir() else []:
        if not directory.is_dir():
            continue
        sheet = directory / "worksheet.json"
        key = directory / "key.json"
        if not (sheet.exists() and key.exists()):
            continue
        for row in json.loads(sheet.read_text(encoding="utf-8")):
            visible.setdefault(row["id"], {**row, "cohort": directory.name})
        for row in json.loads(key.read_text(encoding="utf-8")):
            hidden.setdefault(row["id"], row)
    return visible, hidden


def machine_labels(path: Path) -> dict[str, str]:
    """The model's label per id, last row winning, matching how `score.py` reads the same file."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            out[str(row["id"])] = row["label"]
    return out


def draw(
    count: int, repeats: int, seed: int, labels_path: Path
) -> tuple[list[dict], dict[str, str]]:
    """Stratified draw, enriched for the items where the two machines already disagree."""
    visible, hidden = load_cohorts()
    model = machine_labels(labels_path)

    strata: dict[str, str] = {
        ident: stratum_of(hidden[ident], llm)
        for ident, llm in model.items()
        if ident in visible and ident in hidden
    }

    rng = random.Random(seed)  # noqa: S311 - choosing which findings a person reads
    pools = {name: sorted(i for i, s in strata.items() if s == name) for name in (DISAGREE, AGREE)}
    for pool in pools.values():
        rng.shuffle(pool)

    # Two thirds from the informative stratum. Not tuned: fixed here, before the human sees
    # anything, so the mix cannot be adjusted after seeing which way agreement fell.
    want_disagree = min(len(pools[DISAGREE]), (count * 2) // 3)
    chosen = pools[DISAGREE][:want_disagree]
    chosen += pools[AGREE][: count - len(chosen)]
    if len(chosen) < count:  # small pools: top up from whatever is left
        rest = [i for i in pools[DISAGREE][want_disagree:] if i not in set(chosen)]
        chosen += rest[: count - len(chosen)]

    repeated = rng.sample(chosen, min(repeats, len(chosen)))
    order = chosen + repeated
    rng.shuffle(order)

    # A repeat sitting three items after its first showing measures recall, not judgement. Push
    # any such pair apart until they are at least a quarter of the run away from each other.
    minimum_gap = max(4, len(order) // 4)
    for _ in range(400):
        seen: dict[str, int] = {}
        clashes = []
        for position, ident in enumerate(order):
            if ident in seen and position - seen[ident] < minimum_gap:
                clashes.append(position)
            seen[ident] = position
        if not clashes:
            break
        for position in clashes:
            swap = rng.randrange(len(order))
            order[position], order[swap] = order[swap], order[position]

    sheet = [{"seq": n, **visible[i]} for n, i in enumerate(order, 1)]
    for row in sheet:
        row.pop("cohort", None)  # the cohort is provenance; the annotator judges a line of code
    return sheet, {i: strata[i] for i in set(order)}


def draw_second(count: int, repeats: int, seed: int) -> tuple[list[dict], dict[str, str]]:
    """A second rater's sheet, drawn from the items the FIRST rater already judged.

    Inter-rater agreement is only defined over items both people saw, so this samples from the
    primary worksheet rather than drawing fresh from the cohorts. The order is reshuffled and the
    repeats are chosen independently, so nothing about the first rater's sequence -- let alone their
    labels -- is visible here.
    """
    if not WORKSHEET.exists():
        raise SystemExit(f"no {WORKSHEET.name}; the primary rater's draw must exist first")
    primary = json.loads(WORKSHEET.read_text(encoding="utf-8"))
    strata = json.loads(STRATA.read_text(encoding="utf-8")) if STRATA.exists() else {}

    by_id: dict[str, dict] = {}
    for row in primary:
        by_id.setdefault(row["id"], row)

    rng = random.Random(seed + 1)  # noqa: S311 - choosing which findings a person reads
    identifiers = sorted(by_id)
    rng.shuffle(identifiers)
    chosen = identifiers[: min(count, len(identifiers))]

    repeated = rng.sample(chosen, min(repeats, len(chosen)))
    order = chosen + repeated
    rng.shuffle(order)

    minimum_gap = max(4, len(order) // 4)
    for _ in range(400):
        seen: dict[str, int] = {}
        clashes = []
        for position, ident in enumerate(order):
            if ident in seen and position - seen[ident] < minimum_gap:
                clashes.append(position)
            seen[ident] = position
        if not clashes:
            break
        for position in clashes:
            swap = rng.randrange(len(order))
            order[position], order[swap] = order[swap], order[position]

    sheet = []
    for number, ident in enumerate(order, 1):
        row = {key: value for key, value in by_id[ident].items() if key != "seq"}
        sheet.append({"seq": number, **row})
    return sheet, {i: strata.get(i, "unknown") for i in set(order)}


def show(row: dict, total: int) -> None:
    print("\n" + "=" * WIDTH)
    print(f"  {row['seq']} of {total}   [{row['family']}]   {row['repository']}")
    print(f"  {row['path']}:{row['line']}")
    print("-" * WIDTH)
    for line in row.get("context", []):
        print("  " + line)
    print("-" * WIDTH)


def prompt() -> tuple[str, str] | None:
    """One judgement. Returns None on end-of-input so a session can be stopped with Ctrl-D."""
    while True:
        print("\n  [u]se   [m]ention   [a]bsent   [?] ambiguous   ([s]kip, [q]uit)")
        try:
            answer = input("  > ").strip().lower()
        except EOFError:
            return None
        if answer in {"q", "quit"}:
            return None
        if answer in {"s", "skip"}:
            return ("", "")
        if answer in KEYS:
            try:
                reason = input("  why (optional): ").strip()
            except EOFError:
                reason = ""
            return (KEYS[answer], reason)
        print("  not one of u / m / a / ? / s / q")


def cmd_draw(args: argparse.Namespace) -> int:
    rater = args.rater
    worksheet, strata_path, labels_path = (
        worksheet_for(rater),
        strata_for(rater),
        labels_for(rater),
    )
    if worksheet.exists() and not args.force:
        raise SystemExit(
            f"{worksheet.name} already exists. Re-drawing would renumber the sequence and orphan "
            f"any labels already collected in {labels_path.name}. Pass --force only if intended."
        )
    if rater == PRIMARY:
        sheet, strata = draw(args.count, args.repeats, args.seed, args.labels)
    else:
        sheet, strata = draw_second(args.count, args.repeats, args.seed)
    worksheet.write_text(json.dumps(sheet, indent=1), encoding="utf-8")
    strata_path.write_text(json.dumps(strata, indent=1, sort_keys=True), encoding="utf-8")

    unique = len({row["id"] for row in sheet})
    counts = Counter(strata[row["id"]] for row in sheet)
    print(f"\n{len(sheet)} positions over {unique} distinct items ({len(sheet) - unique} repeated)")
    print("  strata: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    if rater != PRIMARY:
        print(f"  drawn from the {unique} items the primary rater already judged, reshuffled")
    print(f"\nwrote {worksheet.name} (blind) and {strata_path.name} (not opened before scoring)")
    print(
        f"\nnext:  uv run python {Path(__file__).name} label --annotator <name>"
        + ("" if rater == PRIMARY else f" --rater {rater}")
    )
    return 0


def cmd_label(args: argparse.Namespace) -> int:
    worksheet, labels_path = worksheet_for(args.rater), labels_for(args.rater)
    if not worksheet.exists():
        raise SystemExit(f"no {worksheet.name}; run `human.py draw --rater {args.rater}` first")
    sheet = json.loads(worksheet.read_text(encoding="utf-8"))
    done = set()
    if labels_path.exists():
        for line in labels_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                done.add(json.loads(line)["seq"])

    todo = [row for row in sheet if row["seq"] not in done]
    if not todo:
        print(f"all {len(sheet)} positions already labelled in {labels_path.name}")
        return 0

    print(f"\n{len(todo)} of {len(sheet)} left. Ctrl-D or 'q' stops; progress is saved as you go.")
    print("\nThe question, from PROTOCOL.md:")
    print("  Does the code at this line perform, configure, or select a cryptographic")
    print("  operation of the named family?  (For PII/SECRET families: is a real instance")
    print("  of that category present, as opposed to a placeholder or a test fixture?)")

    written = 0
    with labels_path.open("a", encoding="utf-8") as fh:
        for row in todo:
            show(row, len(sheet))
            answer = prompt()
            if answer is None:
                break
            label, reason = answer
            if not label:
                continue
            fh.write(
                json.dumps(
                    {
                        "seq": row["seq"],
                        "id": row["id"],
                        "label": label,
                        "reason": reason,
                        "annotator": args.annotator,
                        "at": datetime.now(UTC).isoformat(timespec="seconds"),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            fh.flush()
            written += 1

    print(f"\n{written} labelled this session; {len(done) + written} of {len(sheet)} done")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    drawer = sub.add_parser("draw", help="draw the blind human sample")
    drawer.add_argument("--count", type=int, default=100)
    drawer.add_argument(
        "--repeats", type=int, default=20, help="items shown twice, for intra-rater"
    )
    drawer.add_argument("--seed", type=int, default=SEED)
    drawer.add_argument("--labels", type=Path, default=HERE / "labels.jsonl")
    drawer.add_argument("--force", action="store_true")
    drawer.add_argument(
        "--rater",
        default=PRIMARY,
        help=(
            "which annotator's sheet. `primary` is the unsuffixed one; any other name draws "
            "from the primary's items, so an inter-rater kappa is defined over shared items"
        ),
    )
    drawer.set_defaults(func=cmd_draw)

    labeller = sub.add_parser("label", help="work through the sample")
    labeller.add_argument("--annotator", required=True)
    labeller.add_argument("--rater", default=PRIMARY, help="which sheet to label")
    labeller.set_defaults(func=cmd_label)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
