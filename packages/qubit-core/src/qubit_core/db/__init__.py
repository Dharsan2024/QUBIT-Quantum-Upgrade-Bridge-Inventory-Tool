"""QUBIT database layer: SQLAlchemy 2.x models + engine/session factory.

The DB is the source of truth. SQLite is the default (WAL mode, so a reader API and a writer job
thread coexist); PostgreSQL is an optional swap via the SQLAlchemy URL.
"""

from .migrate import has_alembic_history, stamp_head, upgrade_to_head
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
