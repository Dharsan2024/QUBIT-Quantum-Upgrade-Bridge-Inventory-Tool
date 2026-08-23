"""Print a batch of the blind worksheet for the annotator, and nothing else.

Deliberately dumb, and deliberately incapable of showing provenance: it reads `worksheet.json` and
never opens `key.json`. Blinding that depends on remembering not to look is not blinding.

    uv run python benchmarks/adjudication/show.py --start 0 --count 100
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
WIDTH = 118


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--worksheet", type=Path, default=HERE / "worksheet.json")
    parser.add_argument(
        "--unlabelled", type=Path, default=None, help="skip ids already labelled in this file"
    )
    args = parser.parse_args()

    items = json.loads(args.worksheet.read_text(encoding="utf-8"))
    if args.unlabelled and args.unlabelled.exists():
        done = set(json.loads(args.unlabelled.read_text(encoding="utf-8")))
        items = [i for i in items if i["id"] not in done]

    batch = items[args.start : args.start + args.count]
    for n, item in enumerate(batch, args.start + 1):
        print(f"\n#{n} {item['id']}  [{item['family']}]  {item['repository']}")
        print(f"   {item['path']}:{item['line']}")
        for line in item["context"]:
            print(f"   {line[:WIDTH]}")
    print(f"\n--- {len(batch)} items shown; {len(items)} remain in the worksheet ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
