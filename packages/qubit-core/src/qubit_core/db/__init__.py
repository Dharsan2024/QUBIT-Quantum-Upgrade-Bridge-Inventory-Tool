"""QUBIT database layer: SQLAlchemy 2.x models + engine/session factory.

The DB is the source of truth. SQLite is the default (WAL mode, so a reader API and a writer job
thread coexist); PostgreSQL is an optional swap via the SQLAlchemy URL.
"""

from typing import TYPE_CHECKING, Any

from .models import ApiToken, AssetRow, Base, Job, ProjectRow, RiskRun, ScanRow
from .session import default_db_url, get_engine, session_factory
from .tokens import (
    CreatedToken,
    create_token,
    has_any_tokens,
    hash_token,
    list_tokens,
    resolve_token,
    revoke_token,
)

__all__ = [
    "ApiToken",
    "AssetRow",
    "Base",
    "CreatedToken",
    "Job",
    "ProjectRow",
    "RiskRun",
    "ScanRow",
    "create_token",
    "default_db_url",
    "get_engine",
    "has_alembic_history",
    "has_any_tokens",
    "hash_token",
    "list_tokens",
    "resolve_token",
    "revoke_token",
    "session_factory",
    "stamp_head",
    "upgrade_to_head",
]

# `.migrate` imports Alembic, which costs ~0.28s — and it was imported eagerly here purely to
# re-export the three schema functions below. Because almost everything in the monorepo imports
# `qubit_core` (the scanner, the CLI, the API, the migration orchestrator), that cost was paid on
# EVERY process start, including each rescan subprocess the migration validator spawns per patch.
# Only `qubit db …`, the API's startup migration, and one test ever call them.
#
# Deferred with PEP 562 so the public surface is byte-for-byte unchanged: `from qubit_core.db import
# upgrade_to_head` still works, `__all__` still advertises it, and Alembic is imported on the first
# actual attribute access instead of at import time.
if TYPE_CHECKING:  # let type checkers and IDEs resolve them statically
    from .migrate import has_alembic_history, stamp_head, upgrade_to_head

_LAZY_MIGRATE_EXPORTS = frozenset({"has_alembic_history", "stamp_head", "upgrade_to_head"})


def __getattr__(name: str) -> Any:
    if name in _LAZY_MIGRATE_EXPORTS:
        from . import migrate

        return getattr(migrate, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
