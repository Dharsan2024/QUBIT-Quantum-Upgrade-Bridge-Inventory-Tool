"""Engine factory and session maker, with the SQLite pragmas that make a reader API and a writer
job thread coexist (WAL + busy_timeout). PostgreSQL URLs skip the SQLite-only pragmas.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

from platformdirs import user_data_dir
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import OperationalError
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
    # SQLite allows exactly one writer at a time even under WAL, and a bulk migration job commits
    # once per task in a loop that can run for minutes against real, complex code. 5000ms was
    # measured against exactly that: five real repositories (paramiko, forge, gliderlabs/ssh,
    # java-jwt, ruby-jwt) scanned and migrated through the running app at once produced a genuine
    # `sqlite3.OperationalError: database is locked` on `INSERT INTO jobs` -- a user clicking
    # "Build plan" on one project while another project's migration job was mid-run got a bare 500
    # with no job created. This is the connection-level backstop; `commit_with_retry` and
    # `retry_write_on_lock` below are the second line of defense for the specific user-facing
    # writes that produced the 500.
    cur.execute("PRAGMA busy_timeout=20000")
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


def _retry_on_lock(session: Session, attempt_fn, *, attempts: int) -> None:
    """Shared loop behind `commit_with_retry` and `retry_write_on_lock`. See both for why this
    exists; not exported on its own because every caller needs to pick which retry SHAPE fits
    what it is retrying, not just "retry a thing".
    """
    for attempt in range(attempts):
        try:
            attempt_fn()
            return
        except OperationalError as exc:
            if "database is locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            session.rollback()
            # Full jitter, not fixed backoff: several requests colliding on the SAME lock should
            # not retry in lockstep and collide again on the same schedule.
            time.sleep(random.uniform(0, 0.25 * (2**attempt)))  # noqa: S311 -- retry jitter, not crypto


def commit_with_retry(session: Session, *new_objects: object, attempts: int = 5) -> None:
    """Add ``new_objects`` and commit, retried on SQLite's transient "database is locked".

    For the common shape: a handful of freshly-constructed rows, `session.add()`-ed once, then
    one `commit()`. `run_plan`'s job row is this shape. A `build_plan`-sized operation -- many
    objects added across a loop with intermediate `flush()` calls of its own, any of which could
    be where the lock is hit -- is a different shape; see `retry_write_on_lock` for that one.

    Second line of defense behind ``PRAGMA busy_timeout`` (`_apply_sqlite_pragmas`): the pragma
    already makes SQLite itself wait before raising, but a caller can still lose the race under
    sustained contention -- measured live, driving the running app against five real repositories
    at once: a click on "Build plan" for one project, while a bulk migration for another was
    mid-run inserting per-task rows in a loop, got a bare 500 on `INSERT INTO jobs` with no job
    created and (at the time) no error shown to the user either. That happened on a user-facing
    button click, which gets one retry budget worth spending; a background job's own internal
    per-task commits are not wrapped here; they already sit behind the same busy_timeout, and
    losing one to contention is what the migration's own per-task failure handling is for.

    `new_objects` are re-``add``-ed on every attempt, not just the first. Confirmed empirically,
    not assumed: `Session.rollback()` EXPUNGES a still-pending (never-committed) object -- it is
    no longer in `session.new` afterwards -- so a bare retried `commit()` with nothing re-added
    silently commits an EMPTY transaction and reports success. A first version of this helper did
    exactly that; it would have turned "the job failed to create" into "the job silently vanished
    with no error at all", which is a worse bug than the one it was written to fix.
    """

    def attempt() -> None:
        for obj in new_objects:
            session.add(obj)
        session.commit()

    _retry_on_lock(session, attempt, attempts=attempts)


def retry_write_on_lock(session: Session, fn, *, attempts: int = 5):
    """Call ``fn()`` (a whole mutating operation, including its own commit), redone from scratch
    on SQLite's transient "database is locked".

    For an operation like `MigrationOrchestrator.build_plan`: many rows added across a loop with
    several of its OWN intermediate `flush()` calls, any one of which could be where a concurrent
    writer's lock is hit, followed by its own final `commit()`. Re-adding a fixed list of objects
    (`commit_with_retry`'s shape) is not enough here -- a flush partway through the loop can fail
    before later objects even exist -- so the correct unit of retry is the WHOLE call. Safe to redo
    because `session.rollback()` discards every uncommitted row from the failed attempt first, and
    the operation reads from already-committed data (scanned assets), so calling it again from a
    clean session produces the same result, not a duplicate.
    """
    result = None

    def attempt() -> None:
        nonlocal result
        result = fn()

    _retry_on_lock(session, attempt, attempts=attempts)
    return result


__all__ = [
    "commit_with_retry",
    "default_db_url",
    "get_engine",
    "retry_write_on_lock",
    "session_factory",
]
