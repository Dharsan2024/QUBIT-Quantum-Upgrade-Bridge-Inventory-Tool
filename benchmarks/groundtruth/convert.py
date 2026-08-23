"""Convert CryptoAPI-Bench's published ground truth from .xlsx into a checked-in CSV.

Run once. The CSV is the artifact the scoring harness reads, so a published precision figure rests
on an auditable text file in this repository rather than on a spreadsheet parse that happens
differently on somebody else's machine.

**Excel ate part of the ground truth, and this is where that is repaired.** The `Line number`
column holds comma-separated line lists, and for 18 of the 182 rows Excel silently parsed those as
dates: `9,12` became `2019-09-12`, `10,15` became `2020-10-15`. Reading the column naively yields
line numbers in the thousands and scores every one of those rows as a miss. The repair reads the
month and day back out, which reconstructs the original pair exactly, and the year is discarded as
the artifact it is. Rows repaired this way are flagged `line_repaired=True` so the effect of the
repair on any score can be measured rather than assumed.

    uv run python benchmarks/groundtruth/convert.py

Source: https://github.com/CryptoAPI-Bench/CryptoAPI-Bench (MIT), Afrose et al., SecDev 2019.
"""

from __future__ import annotations

import csv
import datetime
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
BENCH = REPO_ROOT / "git help" / "cryptoapi-bench"
XLSX = BENCH / "CryptoAPI-Bench_details.xlsx"
OUT = HERE / "cryptoapi_bench_truth.csv"


def _filenames(cell: object) -> list[str]:
    """Every java file a row names.

    Two quirks in the published sheet, both of which silently lose rows if ignored:

    * the 12 `...Corrected` rows -- the *secure* counterparts, and therefore the entire
      false-positive half of the benchmark -- omit the `.java` extension;
    * the 22 `Multiple java classes` rows put TWO filenames in one cell separated by a newline,
      because the misuse spans both files.

    Dropping either group would have cost 34 of 182 cases, and the first group is the half that
    measures precision.
    """
    if cell is None:
        return []
    names = []
    for part in str(cell).replace("\r", "\n").split("\n"):
        name = part.strip()
        if not name:
            continue
        names.append(name if name.endswith(".java") else f"{name}.java")
    return names


def _lines(cell: object) -> tuple[str, bool]:
    """The line list as written, and whether Excel had mangled it into a date."""
    if cell is None:
        return "", False
    if isinstance(cell, datetime.datetime):
        # `9,12` -> Sep 12. Month and day ARE the two original numbers; the year is Excel's
        # invention. This is exact for the two-number lists the sheet actually contains.
        return f"{cell.month},{cell.day}", True
    text = str(cell).strip()
    return ",".join(part.strip() for part in text.split(",") if part.strip()), False


def main() -> int:
    if not XLSX.exists():
        raise SystemExit(
            f"missing {XLSX}\n"
            "  clone it first:\n"
            "  git clone --depth 1 https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git "
            f'"{BENCH}"'
        )
    import openpyxl

    sheet = openpyxl.load_workbook(XLSX, data_only=True)["Vulnerabilities"]
    rows = list(sheet.iter_rows(values_only=True))

    # Locate each java file on disk so a score can be computed against a real path rather than a
    # basename that might be ambiguous.
    by_name: dict[str, list[Path]] = {}
    for path in (BENCH / "src").rglob("*.java"):
        by_name.setdefault(path.name, []).append(path)

    out: list[dict[str, object]] = []
    group = ""
    repaired = ambiguous = missing = 0
    for row in rows[1:]:
        if row[0]:
            group = str(row[0]).strip()
        if not row[1]:
            continue
        names = _filenames(row[1])
        lines, was_repaired = _lines(row[6])
        repaired += was_repaired

        paths = []
        for name in names:
            candidates = by_name.get(name, [])
            if len(candidates) > 1:
                ambiguous += 1
            if not candidates:
                missing += 1
                continue
            paths.append(candidates[0].relative_to(BENCH).as_posix())

        exists = str(row[3]).strip() if row[3] is not None else ""
        out.append(
            {
                "file": ";".join(names),
                "path": ";".join(paths),
                "group": group,
                "code_number": str(row[2] or "").strip(),
                "vulnerable": {"True": "true", "False": "false"}.get(exists, "unstated"),
                "type": str(row[4] or "").strip(),
                "method": str(row[5] or "").strip(),
                "lines": lines,
                "line_repaired": str(was_repaired).lower(),
                "note": str(row[7] or "").strip(),
            }
        )

    with OUT.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(out[0]))
        writer.writeheader()
        writer.writerows(out)

    vulnerable = sum(1 for r in out if r["vulnerable"] == "true")
    secure = sum(1 for r in out if r["vulnerable"] == "false")
    unstated = sum(1 for r in out if r["vulnerable"] == "unstated")
    print(f"wrote {OUT.relative_to(REPO_ROOT)}")
    print(f"  {len(out)} rows: {vulnerable} vulnerable, {secure} secure, {unstated} unstated")
    print(f"  {repaired} line lists repaired from Excel date mangling")
    if missing:
        print(f"  WARNING: {missing} rows name a file not present in the clone")
    if ambiguous:
        print(f"  NOTE: {ambiguous} basenames occur more than once; first match used")
    return 0


if __name__ == "__main__":
    sys.exit(main())
