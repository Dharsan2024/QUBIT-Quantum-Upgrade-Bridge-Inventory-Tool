"""The secret scanner must stay linear on files that look like one enormous secret.

Found by scanning OpenSSL (6,162 files) through the running app: the scan appeared to hang at 86%.
It was not hung -- it was inside `test/recipes/30-test_evp_data/`, OpenSSL's own ML-KEM and ML-DSA
test vectors, which are megabytes of unbroken hex.

Two separate costs, both quadratic, both on input that yields ZERO findings:

* `SECRET-HARDCODED-PW`'s optional identifier prefix `[A-Za-z0-9]+[_-]` -- at every offset the
  engine consumed the whole hex run, then backtracked one character at a time looking for a `_`
  or `-` that never comes. This one pattern took 22.34s of a 22.50s file scan.
* the line number for each match was `text.count("\\n", 0, m.start())`, an O(n) rescan per match,
  paid before any filter could discard it.

There are around twenty such files. The fix is a bounded prefix and a precomputed line index;
measured on the 1,292 KB vector file, 27.9s -> 0.75s.

Pathological input like this is exactly what a crypto scanner meets in the wild -- test vectors,
fixtures, embedded key tables -- so the guard belongs in the suite rather than in a comment.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from qubit_scanner.secrets.scanner import SecretScanner

#: A line shaped like OpenSSL's vectors: a short key, then a very long unbroken hex value.
_HEX_LINE = "Ciphertext = " + ("0123456789abcdef" * 96) + "\n"


@pytest.fixture
def vector_file(tmp_path: Path) -> Path:
    """~1.5 MB of hex, matching the real files' shape closely enough to reproduce the blowup."""
    path = tmp_path / "evppkey_ml_kem_vectors.txt"
    path.write_text(_HEX_LINE * 1000, encoding="utf-8")
    assert path.stat().st_size > 1_000_000, "the file must be big enough to expose the blowup"
    return path


def test_a_file_of_solid_hex_scans_in_linear_time(vector_file: Path) -> None:
    """Before the fix this took ~28s for a file this size, and found nothing.

    The threshold is deliberately loose. The point is the difference between seconds and half a
    minute per file -- across twenty files that is the difference between a scan finishing and a
    scan looking hung -- not a precise benchmark that would flake on a busy machine.
    """
    scanner = SecretScanner()

    started = time.time()
    findings = scanner.scan_file(vector_file)
    elapsed = time.time() - started

    assert elapsed < 5.0, (
        f"scanning {vector_file.stat().st_size // 1024} KB of hex took {elapsed:.1f}s — "
        "the quadratic backtracking is back"
    )
    assert findings == [], "solid hex test vectors are not secrets"


def test_cost_grows_roughly_linearly_with_size(tmp_path: Path) -> None:
    """Quadratic growth is the actual defect, so measure growth, not one absolute number.

    Doubling the input previously took ~4x the time. A linear scanner takes ~2x; the assertion
    allows a generous 3x so ordinary noise cannot fail it while a return to quadratic still does.
    """
    scanner = SecretScanner()

    small = tmp_path / "small.txt"
    small.write_text(_HEX_LINE * 250, encoding="utf-8")
    large = tmp_path / "large.txt"
    large.write_text(_HEX_LINE * 500, encoding="utf-8")

    started = time.time()
    scanner.scan_file(small)
    small_elapsed = max(time.time() - started, 1e-4)

    started = time.time()
    scanner.scan_file(large)
    large_elapsed = time.time() - started

    assert large_elapsed < small_elapsed * 3, (
        f"doubling the file took {large_elapsed / small_elapsed:.1f}x the time "
        f"({small_elapsed:.2f}s -> {large_elapsed:.2f}s) — that is superlinear"
    )


def test_a_real_hardcoded_password_is_still_found(tmp_path: Path) -> None:
    """The bound must not have cost any recall — including the prefixed form it exists for."""
    source = tmp_path / "config.py"
    source.write_text(
        'DB_PASSWORD = "sup3rs3cret!"\n'
        'password = "hunter2andmore"\n'
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(source)

    lines = {f.location.line for f in findings}
    assert 1 in lines, "the prefixed `DB_PASSWORD` form must still match"
    assert 2 in lines, "the bare `password` form must still match"
    assert findings, "a file of real credentials must not come back empty"
