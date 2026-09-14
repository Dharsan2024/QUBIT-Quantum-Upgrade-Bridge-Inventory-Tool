"""Turn the hand-filled ANSWERS.txt into `labels_rater_b.csv`.

Editing `label_packet_min.csv` by hand is unpleasant — the `context` column contains embedded
newlines, so most spreadsheet tools mangle it and a mangled `token` column silently breaks the join
that kappa depends on. So the rater reads `WORKSHEET.txt` and writes verdicts into `ANSWERS.txt`,
one per numbered line, and this converts that back into the CSV shape `kappa.py` expects.

Partial files are fine and expected: kappa is computed over whatever overlaps, so a rater can stop
at item 23 and the result is a kappa over 23 items rather than an error.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

VERDICTS = ("correct", "wrong-algorithm", "not-crypto", "unsure")

#: `1  correct  looks fine` — number, verdict, optional free-text note. A trailing `# ...` comment
#: is the item's own reminder text, printed by the generator, and is not a note.
_LINE = re.compile(r"^\s*(\d+)\s+([A-Za-z-]+)\s*(.*)$")


def parse(answers: Path) -> dict[int, tuple[str, str]]:
    out: dict[int, tuple[str, str]] = {}
    for lineno, raw in enumerate(answers.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = _LINE.match(line)
        if not m:
            # A bare number with no verdict is an unfilled row, not an error.
            if re.fullmatch(r"\s*\d+\s*", line):
                continue
            raise SystemExit(f"{answers}:{lineno}: cannot parse {raw.strip()!r}")
        num, verdict, note = int(m.group(1)), m.group(2).strip().lower(), m.group(3).strip()
        if verdict not in VERDICTS:
            raise SystemExit(
                f"{answers}:{lineno}: {verdict!r} is not one of {VERDICTS}\n  in: {raw.strip()!r}"
            )
        out[num] = (verdict, note)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--packet", type=Path, default=Path("unwanted/paper_evidence/label_packet_min.csv")
    )
    ap.add_argument("--answers", type=Path, default=Path("unwanted/paper_evidence/ANSWERS.txt"))
    ap.add_argument("--out", type=Path, default=Path("unwanted/paper_evidence/labels_rater_b.csv"))
    args = ap.parse_args()

    rows = list(csv.DictReader(args.packet.open(encoding="utf-8")))
    answers = parse(args.answers)

    with args.out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["item", "token", "verdict", "note"])
        written = 0
        for i, r in enumerate(rows, start=1):
            if i not in answers:
                continue
            verdict, note = answers[i]
            w.writerow([r["item"], r["token"], verdict, note])
            written += 1

    print(f"{written} of {len(rows)} items labelled  ->  {args.out}")
    if written < len(rows):
        missing = [i for i in range(1, len(rows) + 1) if i not in answers]
        head = ", ".join(str(i) for i in missing[:15])
        print(f"still blank ({len(missing)}): {head}{' ...' if len(missing) > 15 else ''}")
    if written:
        print("\nnow run:  uv run python scripts/kappa.py")


if __name__ == "__main__":
    main()
