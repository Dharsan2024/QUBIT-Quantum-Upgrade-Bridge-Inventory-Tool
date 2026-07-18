"""Crash-isolated scan worker (internal).

Scans a pre-enumerated list of source files starting at an index, appending one JSON record per
crypto finding to an output file and checkpointing the current index BEFORE each scan. tree-sitter
can segfault natively on pathological inputs (uncatchable in-process); the driver restarts this
worker at ``checkpoint + 1`` to skip the offending file. Run via:

    python -m qubit_risk.ml._scan_worker <repo> <list_file> <start_idx> <out_jsonl> <progress_file>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .harvest import _EXT_LANG, _context_window


def main() -> None:
    repo, list_file, start_idx, out_jsonl, progress_file = (
        sys.argv[1],
        sys.argv[2],
        int(sys.argv[3]),
        sys.argv[4],
        sys.argv[5],
    )
    from qubit_scanner import scan_paths

    files = Path(list_file).read_text(encoding="utf-8").splitlines()
    prog = Path(progress_file)
    with Path(out_jsonl).open("a", encoding="utf-8") as out:
        for i in range(start_idx, len(files)):
            prog.write_text(str(i), encoding="utf-8")  # checkpoint BEFORE the risky scan
            f = Path(files[i])
            try:
                res = scan_paths([f], repo=repo)
            except Exception:  # noqa: S112 - non-native error, skip file
                continue
            for asset in res.assets:
                rec = {
                    "text": _context_window(asset),
                    "algorithm": asset.algorithm,
                    "file_path": (asset.location.file_path or "") if asset.location else "",
                    "language": _EXT_LANG.get(f.suffix, "python"),
                }
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
    prog.write_text("-1", encoding="utf-8")  # sentinel: finished cleanly


if __name__ == "__main__":
    main()
