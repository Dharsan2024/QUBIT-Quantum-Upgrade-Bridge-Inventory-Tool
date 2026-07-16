from __future__ import annotations

from pathlib import Path

from qubit_core import Location, redaction
from qubit_scanner import Detection, normalize, scan_paths


def test_normalize_resolves_canonical_and_verdict() -> None:
    det = Detection(
        rule_id="PY-HASHLIB-MD5",
        raw_algorithm="MD5",
        usage_context="hash",
        location=Location(file_path="a.py", line=1),
        evidence_snippet="h = hashlib.md5()",
    )
    asset = normalize(det)
    assert asset.algorithm == "MD5"
    assert asset.quantum_vulnerable.vulnerable is True
    assert asset.fingerprint is not None and len(asset.fingerprint) == 16


def test_normalize_unknown_algorithm_kept_not_dropped() -> None:
    det = Detection(
        rule_id="X",
        raw_algorithm="MysteryCipher",
        location=Location(file_path="a.py", line=1),
    )
    asset = normalize(det)
    assert asset.algorithm.startswith("UNKNOWN(")
    assert asset.confidence.value == "low"


def test_normalize_redacts_evidence() -> None:
    det = Detection(
        rule_id="X",
        raw_algorithm="RSA",
        key_size=2048,
        location=Location(file_path="a.py", line=1),
        evidence_snippet=(
            'priv = "-----BEGIN RSA PRIVATE KEY-----\\nAAAA\\n-----END RSA PRIVATE KEY-----"'
        ),
    )
    asset = normalize(det)
    assert not redaction.contains_private_key(asset.evidence.snippet)


def test_scan_paths_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "h = hashlib.md5(x)\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    res = scan_paths([tmp_path])
    algos = {a.algorithm for a in res.assets}
    assert "MD5" in algos
    assert "RSA-2048" in algos
    assert res.stats.files_scanned == 1
    assert res.stats.assets == 2
    # every asset carries a fingerprint and a quantum verdict
    assert all(a.fingerprint for a in res.assets)


def test_scan_paths_ignores_venv_and_git(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "junk.py").write_text("import hashlib\nhashlib.md5()\n", encoding="utf-8")
    (tmp_path / "real.py").write_text("import hashlib\nhashlib.md5()\n", encoding="utf-8")
    res = scan_paths([tmp_path])
    assert res.stats.files_scanned == 1  # only real.py, .venv skipped


def test_occurrence_disambiguates_duplicate_findings(tmp_path: Path) -> None:
    (tmp_path / "d.py").write_text(
        "import hashlib\nhashlib.md5()\nhashlib.md5()\n", encoding="utf-8"
    )
    res = scan_paths([tmp_path])
    fps = {a.fingerprint for a in res.assets}
    assert len(fps) == len(res.assets)  # no fingerprint collisions for repeated findings
