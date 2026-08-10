"""HNDL exposure-surface scanner: secrets, tokens, PII (beyond crypto algorithms)."""

from __future__ import annotations

from pathlib import Path

from qubit_scanner import scan_paths
from qubit_scanner.secrets import SecretScanner


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_detects_github_token_and_pii(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        "GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'\n"
        "customer_email = 'alice.smith@acmecorp.io'\n",
    )
    result = scan_paths([tmp_path])
    by_type = {a.asset_type.value for a in result.assets}
    assert "secret" in by_type
    assert "sensitive-data" in by_type
    algos = {a.algorithm for a in result.assets}
    assert any("GitHub" in a for a in algos)
    assert any("email" in a for a in algos)


def test_secret_carries_hndl_narrative(tmp_path: Path) -> None:
    _write(tmp_path, "keys.py", "AWS = 'AKIAZZ12QW34ER56TY78'\n")
    result = scan_paths([tmp_path])
    secrets = [a for a in result.assets if a.asset_type.value == "secret"]
    assert secrets, "expected an AWS key detection"
    narrative = (secrets[0].evidence.context.extra or {}).get("hndl_narrative", "")
    assert "HNDL" in narrative or "harvest" in narrative.lower()


def test_placeholders_are_skipped(tmp_path: Path) -> None:
    # "EXAMPLE" / example email are placeholders — must NOT be flagged (precision).
    _write(
        tmp_path,
        "readme.md",
        "Set your key like AKIAIOSFODNN7EXAMPLE0\ncontact us at test@example.com\n",
    )
    result = scan_paths([tmp_path])
    assert not [a for a in result.assets if a.asset_type.value in ("secret", "sensitive-data")]


def test_secret_scanner_skips_binary_suffix(tmp_path: Path) -> None:
    p = _write(tmp_path, "data.bin", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
    assert SecretScanner().scan_file(p) == []


def test_crypto_detection_still_works(tmp_path: Path) -> None:
    # Regression: adding the secret pass must not break crypto-algorithm detection.
    _write(tmp_path, "h.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    result = scan_paths([tmp_path])
    assert any(a.algorithm == "MD5" for a in result.assets)
