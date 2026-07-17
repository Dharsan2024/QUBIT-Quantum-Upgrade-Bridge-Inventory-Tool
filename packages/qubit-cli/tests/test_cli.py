from __future__ import annotations

import json
from pathlib import Path

from qubit_cli import app
from typer.testing import CliRunner

runner = CliRunner()


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "h = hashlib.md5(x)\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    return tmp_path


def test_version() -> None:
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "QUBIT" in res.stdout


def test_scan_finds_assets(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan", str(_make_repo(tmp_path))])
    assert res.exit_code == 0
    assert "RSA-2048" in res.stdout
    assert "MD5" in res.stdout


def test_scan_json_output(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan", str(_make_repo(tmp_path)), "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    algos = {a["algorithm"] for a in data["assets"]}
    assert {"RSA-2048", "MD5"} <= algos
    assert data["stats"]["assets"] == 2


def test_scan_writes_cbom(tmp_path: Path) -> None:
    out = tmp_path / "cbom.json"
    res = runner.invoke(app, ["scan", str(_make_repo(tmp_path)), "--cbom", str(out)])
    assert res.exit_code == 0
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert len(doc["components"]) == 2


def test_scan_empty_dir_exits_3(tmp_path: Path) -> None:
    (tmp_path / "readme.txt").write_text("no code here", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 3


def test_scan_missing_path_exits_1(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert res.exit_code == 1


def test_cbom_evidence_omitted_by_default(tmp_path: Path) -> None:
    out = tmp_path / "cbom.json"
    runner.invoke(app, ["scan", str(_make_repo(tmp_path)), "--cbom", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert all("evidence" not in c for c in doc["components"])


def test_rules_lint_ok() -> None:
    res = runner.invoke(app, ["rules", "lint"])
    assert res.exit_code == 0
    assert "OK" in res.stdout


def test_rules_list() -> None:
    res = runner.invoke(app, ["rules", "list"])
    assert res.exit_code == 0
    assert "PY-HASHLIB-MD5" in res.stdout
