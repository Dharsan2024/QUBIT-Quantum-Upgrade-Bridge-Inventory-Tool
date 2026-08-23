"""Phase 2 (accuracy half): B8, B11, B14, B17, B18 from the hand-labelled data.

Every number here comes from `benchmarks/adjudication/labels.jsonl` (801 machine labels) and
`human_labels.jsonl` (120 human judgements over 100 items), scored against the archived per-cohort
worksheets. Nothing is recomputed from a summary: the raw label files are the input, so a reviewer
who disagrees with an individual label can change it and re-run this.

What is deliberately **not** produced here, and why, so `GAPS.md` can say so precisely:

* **PR curves (B9) and calibration (B10)** need a score, and the screening classifier does not have
  one -- it returns one of four categorical answers with no confidence attached. A PR curve drawn
  over an artificial threshold would be a picture of an assumption.
* **Learning curves (B15)** need training. Nothing here is trained; the classifier is a rule and the
  detectors are rule packs.

    uv run python paper_evidence/scripts/phase2_accuracy.py
"""

from __future__ import annotations

import json
import math
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "paper_evidence"
ADJ = ROOT / "benchmarks" / "adjudication"
sys.path.insert(0, str(ROOT / "benchmarks" / "oracles"))
sys.path.insert(0, str(ADJ))

from adjudicate import CODE, COMMENT, STRING_LITERAL, SUBSTRING, classify  # noqa: E402
from human import load_cohorts, machine_labels  # noqa: E402

USE, MENTION, ABSENT = "USE", "MENTION", "ABSENT"
CLASSES = (USE, MENTION, ABSENT)
HEURISTIC_TO_LABEL = {CODE: USE, STRING_LITERAL: MENTION, COMMENT: MENTION, SUBSTRING: ABSENT}
BOOTSTRAP = 10_000
SEED = 20260822


def wilson(successes: int, trials: int, z: float = 1.96) -> tuple[float, float, float]:
    if trials == 0:
        return 0.0, 0.0, 0.0
    p = successes / trials
    d = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / d
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


def mcc(pairs: list[tuple[str, str]], positive: str) -> float:
    """Matthews correlation for one class against the rest.

    Reported alongside F1 because F1 ignores true negatives, and `ABSENT` is 42% of the sample on
    its own -- a class that large makes F1 flattering in a way MCC is not.
    """
    tp = sum(1 for t, p in pairs if t == positive and p == positive)
    tn = sum(1 for t, p in pairs if t != positive and p != positive)
    fp = sum(1 for t, p in pairs if t != positive and p == positive)
    fn = sum(1 for t, p in pairs if t == positive and p != positive)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn - fp * fn) / denominator) if denominator else 0.0


def mcnemar_exact(only_a: int, only_b: int) -> float:
    """Two-sided exact McNemar. Binomial rather than chi-square: the discordant counts are small.

    Compares two classifiers on the SAME items, which is what makes it the right test here -- the
    heuristic and the language model both labelled every one of these findings.
    """
    n = only_a + only_b
    if n == 0:
        return 1.0
    k = min(only_a, only_b)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2**n)
    return min(1.0, 2 * tail)


def bootstrap_by_repository(
    rows: list[tuple[str, str, str]], statistic, rounds: int = BOOTSTRAP
) -> tuple[float, float]:
    """Resample repositories, not findings: findings inside one repository are not independent."""
    by_repo: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for repo, truth, predicted in rows:
        by_repo[repo].append((repo, truth, predicted))
    names = sorted(by_repo)
    if len(names) < 2:
        return float("nan"), float("nan")
    rng = random.Random(SEED)  # noqa: S311 - resampling, not cryptography
    draws = []
    for _ in range(rounds):
        picked = [x for name in (rng.choice(names) for _ in names) for x in by_repo[name]]
        value = statistic(picked)
        if value is not None and not math.isnan(value):
            draws.append(value)
    if not draws:
        return float("nan"), float("nan")
    draws.sort()
    return draws[int(0.025 * len(draws))], draws[min(len(draws) - 1, int(0.975 * len(draws)))]


def _rows() -> dict[str, list[tuple[str, str, str]]]:
    """(repository, hand label, heuristic prediction) per cohort, for the comparable findings.

    Two things here have to match `score.py` exactly, and both were got wrong first time:

    * **The classifier is recomputed, not read from `key.json`.** The stored classes were written by
      whichever version ran that sweep, and for the calibration cohort that is the version whose
      word-boundary defect this study reports. Reading them scored the classifier against its own
      bug and put `ABSENT` precision at 58% where it is really 96%.
    * **HNDL findings are excluded from the classifier's score.** `PII: EMAIL ADDRESS` and
      `HARDCODED PASSWORD/SECRET` cannot be judged by asking whether an algorithm name survives
      outside quotes, so the classifier abstains; scoring an abstention as a wrong answer would
      punish the one honest thing it does. They are measured separately, as a different subsystem.
    """
    visible, hidden = load_cohorts()
    out: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for line in (ADJ / "labels.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        ident = str(row["id"])
        if ident not in visible or ident not in hidden:
            continue
        if str(hidden[ident].get("rule_id", "")).startswith(("SECRET-", "PII-")):
            continue
        item = visible[ident]
        predicted = HEURISTIC_TO_LABEL.get(classify(item["source"], item["family"]))
        if predicted is None or row["label"] not in CLASSES:
            continue
        out[row.get("cohort", "calibration")].append((item["repository"], row["label"], predicted))
    return out


def b8_b11_per_class(cohorts: dict[str, list[tuple[str, str, str]]]) -> None:
    csv = [
        "cohort,class,n_true,n_predicted,precision,prec_lo,prec_hi,recall,rec_lo,rec_hi,f1,mcc,boot_f1_lo,boot_f1_hi"
    ]
    for cohort, rows in sorted(cohorts.items()):
        pairs = [(t, p) for _, t, p in rows]
        for cls in CLASSES:
            tp = sum(1 for t, p in pairs if t == cls and p == cls)
            predicted = sum(1 for _, p in pairs if p == cls)
            actual = sum(1 for t, _ in pairs if t == cls)
            pr, pr_lo, pr_hi = wilson(tp, predicted)
            rc, rc_lo, rc_hi = wilson(tp, actual)
            f1 = (2 * pr * rc / (pr + rc)) if (pr + rc) else 0.0

            def f1_of(sample: list[tuple[str, str, str]], _cls: str = cls) -> float:
                inner = [(t, p) for _, t, p in sample]
                itp = sum(1 for t, p in inner if t == _cls and p == _cls)
                ipred = sum(1 for _, p in inner if p == _cls)
                iact = sum(1 for t, _ in inner if t == _cls)
                if not ipred or not iact:
                    return float("nan")
                ip, ir = itp / ipred, itp / iact
                return (2 * ip * ir / (ip + ir)) if (ip + ir) else 0.0

            lo, hi = bootstrap_by_repository(rows, f1_of)
            csv.append(
                f"{cohort},{cls},{actual},{predicted},{pr:.4f},{pr_lo:.4f},{pr_hi:.4f},"
                f"{rc:.4f},{rc_lo:.4f},{rc_hi:.4f},{f1:.4f},{mcc(pairs, cls):.4f},{lo:.4f},{hi:.4f}"
            )
    (OUT / "tables" / "T07.csv").write_text("\n".join(csv) + "\n", encoding="utf-8")
    print(f"B8: T07.csv, {len(csv) - 1} rows (per class per cohort, Wilson + bootstrap-by-repo F1)")

    for cohort, rows in sorted(cohorts.items()):
        counts = Counter((t, p) for _, t, p in rows)
        lines = [
            f"# Confusion matrix — {cohort} cohort",
            "",
            "rows = hand label, columns = heuristic",
            "",
        ]
        lines.append("| | " + " | ".join(CLASSES) + " | total |")
        lines.append("|---|" + "|".join("---" for _ in CLASSES) + "|---|")
        for truth in CLASSES:
            cells = [str(counts.get((truth, p), 0)) for p in CLASSES]
            lines.append(
                f"| **{truth}** | " + " | ".join(cells) + f" | {sum(int(c) for c in cells)} |"
            )
        (OUT / "tables" / f"T_confusion_{cohort}.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    print(f"B11: confusion matrices for {len(cohorts)} cohorts")


def b14_tests() -> None:
    """McNemar between the heuristic and the language model, on the items a human also judged."""
    visible, hidden = load_cohorts()
    model = machine_labels(ADJ / "labels.jsonl")
    human_rows = [
        json.loads(line)
        for line in (ADJ / "human_labels.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    first: dict[str, str] = {}
    for row in sorted(human_rows, key=lambda r: r["seq"]):
        first.setdefault(str(row["id"]), row["label"])

    csv = ["comparison,n,only_a_correct,only_b_correct,both,neither,mcnemar_p,holm_adjusted"]
    raw: list[tuple[str, list[int], float]] = []
    for label in (
        "heuristic vs language model (3-class)",
        "heuristic vs language model (ABSENT only)",
    ):
        absent_only = "ABSENT only" in label
        a_hits, b_hits = [], []
        for ident, truth in first.items():
            if ident not in hidden or ident not in model or truth not in CLASSES:
                continue
            # Recomputed from the source line, never read from key.json: the stored class was
            # written by whichever classifier ran that sweep, and comparing a current model
            # against a superseded classifier is not the test this claims to be.
            item = visible[ident]
            predicted = HEURISTIC_TO_LABEL.get(classify(item["source"], item["family"]))
            if predicted is None:
                continue
            if absent_only:
                t = ABSENT if truth == ABSENT else "PRESENT"
                a = ABSENT if predicted == ABSENT else "PRESENT"
                b = ABSENT if model[ident] == ABSENT else "PRESENT"
            else:
                t, a, b = truth, predicted, model[ident]
            a_hits.append(a == t)
            b_hits.append(b == t)
        only_a = sum(1 for a, b in zip(a_hits, b_hits, strict=True) if a and not b)
        only_b = sum(1 for a, b in zip(a_hits, b_hits, strict=True) if b and not a)
        both = sum(1 for a, b in zip(a_hits, b_hits, strict=True) if a and b)
        neither = sum(1 for a, b in zip(a_hits, b_hits, strict=True) if not a and not b)
        raw.append(
            (label, [len(a_hits), only_a, only_b, both, neither], mcnemar_exact(only_a, only_b))
        )

    # Holm-Bonferroni over the family of tests reported here.
    ordered = sorted(range(len(raw)), key=lambda i: raw[i][2])
    adjusted = [0.0] * len(raw)
    running = 0.0
    for rank, index in enumerate(ordered):
        running = max(running, min(1.0, (len(raw) - rank) * raw[index][2]))
        adjusted[index] = running
    for (label, counts, p), adj in zip(raw, adjusted, strict=True):
        n, only_a, only_b, both, neither = counts
        csv.append(f"{label},{n},{only_a},{only_b},{both},{neither},{p:.4g},{adj:.4g}")
    (OUT / "tables" / "T11.csv").write_text("\n".join(csv) + "\n", encoding="utf-8")
    print(f"B14: T11.csv, {len(raw)} paired tests (exact McNemar, Holm-adjusted)")


def b17_convergence(cohorts: dict[str, list[tuple[str, str, str]]]) -> None:
    """Monte-Carlo standard error of the bootstrap against the number of resamples."""
    rows = cohorts.get("holdout") or next(iter(cohorts.values()))

    def accuracy(sample: list[tuple[str, str, str]]) -> float:
        return sum(1 for _, t, p in sample if t == p) / len(sample) if sample else float("nan")

    csv = ["rounds,low,high,width,mc_standard_error"]
    for rounds in (100, 250, 500, 1000, 2000, 5000, 10000):
        lo, hi = bootstrap_by_repository(rows, accuracy, rounds=rounds)
        csv.append(
            f"{rounds},{lo:.5f},{hi:.5f},{hi - lo:.5f},{(hi - lo) / (4 * math.sqrt(rounds)):.6f}"
        )
    (OUT / "data" / "convergence.csv").write_text("\n".join(csv) + "\n", encoding="utf-8")
    print("B17: convergence.csv, bootstrap interval width vs resample count")


#: Corpus fixtures contain real personal email addresses, and the HNDL failure cases are exactly
#: the findings that quote them. Publishing a paper artifact that reproduces someone's address is a
#: data-protection problem regardless of the address being public on GitHub, so the pack redacts by
#: default. Un-redacting is an author decision recorded in QUESTIONS.md (Q8), not a default.
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def redact(text: str) -> str:
    """Replace any email address with a stable placeholder that keeps the shape of the finding."""
    return _EMAIL.sub(lambda m: f"<redacted-email:{len(m.group())}chars>", text)


def b18_failures() -> None:
    """Real inputs the system gets wrong, with the reason, taken from the labelled disagreements."""
    visible, hidden = load_cohorts()
    lines = [
        "# B18 — Failure cases",
        "",
        "Real corpus lines where the screening classifier disagrees with the hand label. Not "
        "selected for effect: these are every disagreement class that occurs, with the first "
        "example of each.",
        "",
    ]
    seen: set[tuple[str, str]] = set()
    for raw in (ADJ / "labels.jsonl").read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        ident = str(row["id"])
        if ident not in visible or ident not in hidden:
            continue
        item_now = visible[ident]
        predicted = HEURISTIC_TO_LABEL.get(classify(item_now["source"], item_now["family"]))
        truth = row["label"]
        if predicted is None or truth not in CLASSES or predicted == truth:
            continue
        key = (truth, predicted)
        if key in seen:
            continue
        seen.add(key)
        item = visible[ident]
        lines += [
            f"## hand label `{truth}`, classifier said `{predicted}`",
            "",
            f"* **repository** {item['repository']}",
            f"* **location** `{item['path']}:{item['line']}`",
            f"* **family** {item['family']}",
            f"* **source** `{redact(item['source'][:110])}`",
            f"* **why the label** {redact(row.get('reason', '')[:160])}",
            "",
        ]
    (OUT / "data" / "failures.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"B18: failures.md, {len(seen)} distinct disagreement classes")


def main() -> int:
    cohorts = _rows()
    print(f"cohorts: { {k: len(v) for k, v in cohorts.items()} }\n")
    b8_b11_per_class(cohorts)
    b14_tests()
    b17_convergence(cohorts)
    b18_failures()
    print("\nphase 2 (accuracy) complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
