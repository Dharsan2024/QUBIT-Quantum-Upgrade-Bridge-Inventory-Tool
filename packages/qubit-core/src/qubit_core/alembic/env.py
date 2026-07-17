"""Alembic migration environment — wired to the qubit-core ORM models.

The DB URL is resolved (in order of priority):
1. The ``QUBIT_DB_URL`` environment variable.
2. The ``sqlalchemy.url`` in alembic.ini (used only when running ``alembic``
   directly from the CLI outside of the ``qubit db`` command).
3. The default offline SQLite path from ``qubit_core.db.session.default_db_url()``.

All sub-packages that add tables (qubit-migrate, qubit-risk) import and extend
``Base`` from ``qubit_core.db`` so that a single Alembic ``target_metadata``
captures every table.
"""

from __future__ import annotations

import contextlib
import os
from logging.config import fileConfig

# Import Base and all model modules so their tables are registered.
import qubit_core.db.models  # noqa: F401
from alembic import context
from qubit_core.db import Base
from sqlalchemy import engine_from_config, pool

# Attempt to pull in extended tables from sibling packages if installed.
# These imports are best-effort — the packages may not be installed yet.
with contextlib.suppress(ImportError):
    import qubit_migrate.db_models  # noqa: F401
with contextlib.suppress(ImportError):
    import qubit_risk.db_models  # noqa: F401

# ---------------------------------------------------------------------------
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    """Resolve the DB URL from the environment or alembic.ini."""
    env_url = os.getenv("QUBIT_DB_URL")
    if env_url:
        return env_url
    ini_url = config.get_main_option("sqlalchemy.url")
    if ini_url and ini_url != "driver://user:pass@localhost/dbname":
        return ini_url
    # Fall back to the default offline SQLite path.
    from qubit_core.db.session import default_db_url

    return default_db_url()


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL)."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations with a live DB connection."""
    cfg_section = config.get_section(config.config_ini_section) or {}
    cfg_section["sqlalchemy.url"] = _get_url()
    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Render item-type comments in migration scripts for readability.
            render_as_batch=True,  # required for SQLite ALTER TABLE support
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
