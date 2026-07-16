"""QUBIT database layer: SQLAlchemy 2.x models + engine/session factory.

The DB is the source of truth. SQLite is the default (WAL mode, so a reader API and a writer job
thread coexist); PostgreSQL is an optional swap via the SQLAlchemy URL.
"""

from .models import AssetRow, Base, ProjectRow, ScanRow
from .session import default_db_url, get_engine, session_factory

__all__ = [
    "AssetRow",
    "Base",
    "ProjectRow",
    "ScanRow",
    "default_db_url",
    "get_engine",
    "session_factory",
]
