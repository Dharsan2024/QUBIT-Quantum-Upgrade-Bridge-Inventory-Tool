"""Regression: tree-sitter 0.26.0's binding heap-corrupts (non-deterministic SIGSEGV) while
processing QueryCursor matches on some real files. This vendored file (authlib
jose/rfc7518/jwe_algs.py) reliably crashed the scanner under 0.26.0; it must scan cleanly under the
pinned tree-sitter<0.26. Because the crash was a native segfault it can't be caught in-process — the
guard is running the scan in a subprocess and asserting it exits 0.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import subprocess
import sys
from pathlib import Path

from qubit_scanner import scan_paths

_FIXTURE = Path(__file__).parent / "fixtures" / "segfault_jwe_algs.py"


def test_tree_sitter_is_pinned_below_026() -> None:
    # 0.26.0 is the version with the heap-corruption bug; the pin must keep us off it.
    ver = importlib_metadata.version("tree-sitter")
    major, minor, *_ = (int(x) for x in ver.split("."))
    assert (major, minor) < (0, 26), f"tree-sitter {ver} reintroduces the segfault"


def test_scans_real_file_without_crashing() -> None:
    result = scan_paths([_FIXTURE], repo="regression")
    # It should complete and (this file uses hashlib.sha1) find at least one asset, no errors.
    assert result.stats.files_scanned >= 1
    assert not result.errors


def test_scan_survives_in_subprocess() -> None:
    """Native-crash guard: a fresh process must scan the fixture and exit 0 (not 139/SIGSEGV)."""
    code = (
        "from pathlib import Path; from qubit_scanner import scan_paths; "
        f"r = scan_paths([Path(r'{_FIXTURE}')], repo='x'); print(len(r.assets))"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=120)
    assert proc.returncode == 0, f"scan crashed with exit {proc.returncode}: {proc.stderr[-400:]!r}"
