"""Programmatic Alembic driver — brings an existing database up to the current schema head.

``Base.metadata.create_all()`` (used at API startup) only creates tables that don't exist yet;
it can NEVER retroactively fix a constraint on a table that already exists — e.g. an
``ON DELETE`` clause fixed in a model never takes effect for a database that was created before
the fix shipped. That gap is exactly how ``jobs.project_id`` kept its original ``NO ACTION`` FK
in already-deployed databases even after the model was corrected to ``ondelete="CASCADE"``,
making ``DELETE /projects/{id}`` 500 for any project with a job history. This module makes
``qubit_api`` startup apply pending migrations automatically so a fix like that actually reaches
installations that already have data, not just brand-new ones.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.engine import Engine


def _alembic_config(db_url: str) -> Config:
    """Build a Config pointed at qubit-core's migration scripts, with the URL passed via
    ``attributes`` (read by ``alembic/env.py::_get_url``) rather than an env var, so concurrent
    or sequential calls with different URLs (e.g. many tests in one pytest process) never race
    or leak into unrelated code that reads ``QUBIT_DB_URL`` directly."""
    alembic_dir = Path(__file__).resolve().parents[1] / "alembic"
    cfg = Config()
    cfg.set_main_option("script_location", str(alembic_dir))
    cfg.attributes["db_url"] = db_url
    return cfg


def has_alembic_history(engine: Engine) -> bool:
    """True if this database was previously created/migrated by Alembic (has data worth
    preserving), as opposed to being brand new."""
    return inspect(engine).has_table("alembic_version")


def upgrade_to_head(db_url: str) -> None:
    """Apply any pending migrations. Idempotent — a no-op once the database is at head."""
    command.upgrade(_alembic_config(db_url), "head")


def stamp_head(db_url: str) -> None:
    """Mark a database that was just built via ``create_all()`` as already at the latest
    revision — it already has today's schema, so replaying every migration would be redundant
    (and for SQLite, batch-mode table rebuilds are not free)."""
    command.stamp(_alembic_config(db_url), "head")


__all__ = ["has_alembic_history", "stamp_head", "upgrade_to_head"]
