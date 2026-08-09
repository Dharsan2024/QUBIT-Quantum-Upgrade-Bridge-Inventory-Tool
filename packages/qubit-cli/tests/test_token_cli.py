"""`qubit serve token create|list|revoke` (doc 05 §5.2 / §6.6)."""

from __future__ import annotations

from pathlib import Path

from qubit_cli import app
from typer.testing import CliRunner

runner = CliRunner()


def _db_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'qubit.db').as_posix()}"


def test_token_create_prints_raw_once(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    res = runner.invoke(app, ["serve", "token", "create", "ci", "--scope", "rw", "--db", url])
    assert res.exit_code == 0, res.output
    assert "Created" in res.output
    assert "ci" in res.output
    # A urlsafe token is ~43 chars; just assert something token-like was printed.
    assert "Bearer" in res.output


def test_token_create_rejects_bad_scope(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    res = runner.invoke(app, ["serve", "token", "create", "x", "--scope", "admin", "--db", url])
    assert res.exit_code == 1
    assert "scope must be one of" in res.output


def test_token_create_rejects_duplicate_name(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    runner.invoke(app, ["serve", "token", "create", "dup", "--db", url])
    res = runner.invoke(app, ["serve", "token", "create", "dup", "--db", url])
    assert res.exit_code == 1
    assert "already exists" in res.output


def test_token_list_shows_created(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    runner.invoke(app, ["serve", "token", "create", "reader", "--scope", "ro", "--db", url])
    res = runner.invoke(app, ["serve", "token", "list", "--db", url])
    assert res.exit_code == 0, res.output
    assert "reader" in res.output
    assert "active" in res.output


def test_token_revoke(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    runner.invoke(app, ["serve", "token", "create", "temp", "--db", url])
    res = runner.invoke(app, ["serve", "token", "revoke", "temp", "--db", url])
    assert res.exit_code == 0, res.output
    assert "Revoked" in res.output

    listed = runner.invoke(app, ["serve", "token", "list", "--db", url])
    assert "revoked" in listed.output


def test_token_revoke_unknown_fails(tmp_path: Path) -> None:
    url = _db_url(tmp_path)
    res = runner.invoke(app, ["serve", "token", "revoke", "ghost", "--db", url])
    assert res.exit_code == 1
    assert "no active token" in res.output
