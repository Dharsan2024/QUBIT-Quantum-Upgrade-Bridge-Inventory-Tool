"""The migrate CLI must open the database `QUBIT_DB_URL` names.

Its own docstring claimed to honour that variable while calling `default_db_url()` directly, which
returns the user-data-dir path unconditionally. So every invocation wrote to the operator's real
database whatever the environment said.

Not cosmetic. The evaluation runs each arm in a fresh process against its own isolated database;
without this every arm would have written to the live one — contaminating each other AND the
operator's data — and the isolation the whole design rests on would have been notional.
`qubit_cli.main` and `qubit_cli.commands.risk` already resolved it this way; this module was the
one that did not.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def _resolved_url(monkeypatch: pytest.MonkeyPatch, url: str | None) -> str:
    import qubit_migrate.cli as cli

    if url is None:
        monkeypatch.delenv("QUBIT_DB_URL", raising=False)
    else:
        monkeypatch.setenv("QUBIT_DB_URL", url)
    importlib.reload(cli)
    session = cli.session_factory()
    try:
        return str(session.get_bind().url)
    finally:
        session.close()


def test_the_env_var_is_honoured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "isolated.db"
    resolved = _resolved_url(monkeypatch, f"sqlite:///{target.as_posix()}")
    assert target.as_posix() in resolved, resolved


def test_it_falls_back_to_the_user_data_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control. Without it the test above would pass if the CLI always used a temp path."""
    resolved = _resolved_url(monkeypatch, None)
    assert "qubit.db" in resolved
    assert "isolated.db" not in resolved


def test_two_arms_do_not_share_a_database(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The property the evaluation depends on: each arm's process gets its own database."""
    a = _resolved_url(monkeypatch, f"sqlite:///{(tmp_path / 'arm-a.db').as_posix()}")
    b = _resolved_url(monkeypatch, f"sqlite:///{(tmp_path / 'arm-b.db').as_posix()}")
    assert a != b
    assert "arm-a.db" in a
    assert "arm-b.db" in b
