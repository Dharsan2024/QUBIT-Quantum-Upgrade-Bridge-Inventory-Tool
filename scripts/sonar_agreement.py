"""QUBIT's detection agreement against sonar-cryptography's own Python test corpus.

Each file under sonar's `python/src/test/files/rules/detection` is a case sonar asserts it detects,
so running QUBIT over them is a direct comparison against the competitor's own ground truth --
without standing up a SonarQube instance, and using the competitor's taxonomy rather than one
chosen here.
"""

import collections
import csv
import json
import subprocess
from pathlib import Path

from qubit_migrate.transform.scanner_cli import cli_command

CORPUS = Path("qubit-v2/vendor/sonar-cryptography/python/src/test/files/rules/detection")
OUT = Path("qubit-v2/05-detection/detection_agreement.csv")

files = sorted(CORPUS.rglob("*.py"))
print(f"sonar python test files: {len(files)}")

# Fixed argv from `cli_command`, no shell, and the only path is this repository's own vendored
# corpus.
r = subprocess.run(  # noqa: S603 - fixed argv, no shell
    cli_command("scan", str(CORPUS), "--json"),
    capture_output=True,
    # `text=True` alone would decode with the Windows locale codec; a non-Latin-1 byte in a
    # snippet then raises inside the reader thread.
    text=True,
    encoding="utf-8",
    errors="replace",
    timeout=1800,
)
if r.returncode not in (0, 3):
    print("scan failed:", r.returncode)
    print(r.stdout[-1500:])
    print(r.stderr[-2500:])
    raise SystemExit(1)
data = json.loads(r.stdout)
assets = data.get("assets", [])
print(f"QUBIT detections: {len(assets)}")

by_file: dict[str, list[dict]] = collections.defaultdict(list)
for a in assets:
    by_file[Path((a.get("location") or {}).get("file_path", "?")).name].append(a)

rows = []
cat_total: collections.Counter[str] = collections.Counter()
cat_hit: collections.Counter[str] = collections.Counter()
for f in files:
    category = f.relative_to(CORPUS).parts[0]
    found = by_file.get(f.name, [])
    cat_total[category] += 1
    if found:
        cat_hit[category] += 1
    rows.append(
        {
            "category": category,
            "file": str(f.relative_to(CORPUS)).replace("\\", "/"),
            "sonar_detects": "yes",  # every file here is one of sonar's own assertions
            "qubit_detects": "yes" if found else "no",
            "qubit_findings": len(found),
            "qubit_algorithms": "|".join(sorted({str(a.get("algorithm", "")) for a in found})),
        }
    )

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", encoding="utf-8", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
    w.writeheader()
    w.writerows(sorted(rows, key=lambda r: (r["category"], r["file"])))

hits = sum(1 for r_ in rows if r_["qubit_detects"] == "yes")
print(f"\nagreement: {hits}/{len(files)} = {100 * hits / len(files):.1f}% of sonar's own cases")
print(f"written: {OUT}")
print("\nby sonar category:")
for c in sorted(cat_total):
    gap = " <- MISSED ENTIRELY" if cat_hit[c] == 0 else ""
    print(f"  {c:14} {cat_hit[c]:>2}/{cat_total[c]:<3}{gap}")
print("\nsonar cases QUBIT does not detect:")
for r_ in sorted(rows, key=lambda r: r["file"]):
    if r_["qubit_detects"] == "no":
        print(f"  {r_['file']}")
