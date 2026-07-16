"""Engine factory and session maker, with the SQLite pragmas that make a reader API and a writer
job thread coexist (WAL + busy_timeout). PostgreSQL URLs skip the SQLite-only pragmas.
"""

from __future__ import annotations

from pathlib import Path

from platformdirs import user_data_dir
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def default_db_url() -> str:
    """SQLite URL under the OS user-data dir. ``~`` is NOT used (SQLAlchemy would not expand it)."""
    data_dir = Path(user_data_dir("qubit", appauthor=False))
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(data_dir / 'qubit.db').as_posix()}"


def _apply_sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


def get_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """Create an Engine. SQLite gets WAL + busy_timeout so concurrent read/write works."""
    url = url or default_db_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, echo=echo, future=True, connect_args=connect_args)
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _apply_sqlite_pragmas)
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


__all__ = ["default_db_url", "get_engine", "session_factory"]
