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


def _db_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'qubit.db').as_posix()}"


# ---------------------------------------------------------------------------
# Existing scan / rules tests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# New: project subcommand
# ---------------------------------------------------------------------------


def test_project_create_and_list(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    res = runner.invoke(app, ["project", "create", "MyProject", "--db", url])
    assert res.exit_code == 0, res.output
    assert "Created" in res.output
    assert "MyProject" in res.output

    res2 = runner.invoke(app, ["project", "list", "--db", url])
    assert res2.exit_code == 0, res2.output
    assert "MyProject" in res2.output


def test_project_delete(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    runner.invoke(app, ["project", "create", "ToDelete", "--db", url])
    res = runner.invoke(app, ["project", "delete", "ToDelete", "--yes", "--db", url])
    assert res.exit_code == 0, res.output
    assert "Deleted" in res.output

    # Confirm it no longer appears in list
    list_res = runner.invoke(app, ["project", "list", "--db", url])
    assert "ToDelete" not in list_res.output


def test_project_delete_nonexistent(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    res = runner.invoke(app, ["project", "delete", "ghost", "--yes", "--db", url])
    assert res.exit_code == 1


# ---------------------------------------------------------------------------
# New: db subcommand
# ---------------------------------------------------------------------------


def test_db_upgrade_and_current(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    res = runner.invoke(app, ["db", "upgrade", "--db", url])
    assert res.exit_code == 0, res.output
    assert "done" in res.output

    # alembic current writes via its logging handler; just verify it exits cleanly.
    res2 = runner.invoke(app, ["db", "current", "--db", url])
    assert res2.exit_code == 0, res2.output


# ---------------------------------------------------------------------------
# New: cbom subcommand (export + validate)
# ---------------------------------------------------------------------------


def test_cbom_export_and_validate(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_repo(repo)

    # Use the API directly to create project + scan so we have DB rows
    import re

    from qubit_core import asset_to_row
    from qubit_core.db import Base, ProjectRow, get_engine, session_factory
    from qubit_scanner import scan_paths

    engine = get_engine(url)
    Base.metadata.create_all(engine)
    sf = session_factory(engine)
    from qubit_core.db import ScanRow
    from qubit_core.schemas import utcnow

    with sf() as session:
        slug = re.sub(r"[^a-z0-9]+", "-", "cbom-test").strip("-")
        proj = ProjectRow(name="cbom-test", slug=slug, root_path=str(repo))
        session.add(proj)
        session.flush()
        scan = ScanRow(
            project_id=proj.id,
            seq=1,
            status="running",
            targets=[str(repo)],
            scanners=["code"],
            stats={},
            started_at=utcnow(),
        )
        session.add(scan)
        session.flush()
        result = scan_paths([repo])
        rows = [asset_to_row(a, scan_id=scan.id, project_id=proj.id) for a in result.assets]
        session.add_all(rows)
        scan.status = "succeeded"
        scan.finished_at = utcnow()
        session.commit()

    out = tmp_path / "cbom.json"
    res = runner.invoke(
        app,
        ["cbom", "export", "-p", "cbom-test", "-o", str(out), "--validate", "--db", url],
    )
    assert res.exit_code == 0, res.output
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["specVersion"] == "1.7"
    assert len(doc["components"]) >= 2

    # validate subcommand on the exported file
    val_res = runner.invoke(app, ["cbom", "validate", str(out)])
    assert val_res.exit_code == 0, val_res.output
    assert "OK" in val_res.output


def test_cbom_validate_invalid_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a cbom"}', encoding="utf-8")
    res = runner.invoke(app, ["cbom", "validate", str(bad)])
    assert res.exit_code == 1


def test_cbom_validate_missing_file(tmp_path: Path) -> None:
    res = runner.invoke(app, ["cbom", "validate", str(tmp_path / "nonexistent.json")])
    assert res.exit_code == 1
