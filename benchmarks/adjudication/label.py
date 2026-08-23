"""Append labels to `labels.jsonl`, one JSON array of `[id, label, reason]` on stdin.

Small on purpose. The interesting parts of this method are the protocol and the blinding, and both
are upstream of here — by the time a label reaches this script the judgement has been made. What it
does add is the two fields a reader needs to weigh a label and cannot reconstruct later:

* `annotator` — who or what judged it. The labels in this repository were produced by a language
  model reading the blinded worksheet, and that is a threat to validity, so it is recorded per row
  rather than asserted once in a README.
* `cohort` — `calibration` for the first pass, whose findings were used to repair the classifier and
  the scanner, and `holdout` for draws made afterwards from items nobody had looked at. Without the
  field the two are indistinguishable in the file, and an in-sample figure quietly becomes an
  out-of-sample one.

    uv run python benchmarks/adjudication/label.py --cohort holdout <<'JSON'
    [["c1d67008376b", "USE", "hmac.New(sha256.New, key) computes a real HMAC"]]
    JSON

Appending, never rewriting: a label that turns out to be wrong is corrected by a later row and the
disagreement stays visible in the file. `score.py` takes the last row for an id.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALID = {"USE", "MENTION", "ABSENT", "AMBIGUOUS"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=HERE / "labels.jsonl")
    parser.add_argument("--annotator", default="claude-opus-5")
    parser.add_argument("--cohort", choices=["calibration", "holdout"], default="holdout")
    args = parser.parse_args()

    rows = json.loads(sys.stdin.read())
    bad = [r for r in rows if len(r) != 3 or r[1] not in VALID]
    if bad:
        raise SystemExit(f"{len(bad)} malformed row(s); first: {bad[0]!r}. Labels must be {VALID}.")

    with args.labels.open("a", encoding="utf-8") as fh:
        for ident, label, reason in rows:
            fh.write(
                json.dumps(
                    {
                        "id": ident,
                        "label": label,
                        "reason": reason,
                        "annotator": args.annotator,
                        "cohort": args.cohort,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    total = sum(1 for line in args.labels.read_text(encoding="utf-8").splitlines() if line.strip())
    print(f"appended {len(rows)} to cohort {args.cohort}; {total} labels in {args.labels.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
