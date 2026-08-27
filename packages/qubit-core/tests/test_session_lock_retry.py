"""SQLite write-lock contention, found by driving the running app against real load.

Scanning and migrating five real repositories (paramiko, forge, gliderlabs/ssh, java-jwt,
ruby-jwt) through the desktop app at once -- clicking "Build plan" on one project while another
project's bulk migration was mid-run, committing once per task in a loop that can run for minutes
-- produced a genuine `sqlite3.OperationalError: database is locked` on two user-facing writes:
job creation (`run_plan`) and plan creation (`build_plan`). Both got a bare 500 with nothing
written, from real, unmodified, previously-unscanned code the app had never seen before.

These tests force the SAME failure deterministically: a background thread holds a real
`BEGIN IMMEDIATE` write lock while the connection under test uses a busy_timeout far too short to
outlast it, so `session.commit()`/`session.flush()` is guaranteed to raise mid-operation rather
than merely hoping load happens to line up right.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from qubit_core.db.session import commit_with_retry, retry_write_on_lock
from sqlalchemy import Column, Integer, String, create_engine, event, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


class Row(Base):
    __tablename__ = "row"
    id = Column(Integer, primary_key=True)
    name = Column(String)


def _short_timeout_pragmas(dbapi_conn, _record) -> None:
    """A busy_timeout far shorter than the lock-holder's hold time, so contention definitely
    raises `OperationalError` instead of the connection simply waiting it out -- what actually
    exercises the retry loop, as opposed to a test that passes only because nothing failed."""
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=300")
    cur.close()


@pytest.fixture
def locked_db(tmp_path: Path):
    """A real SQLite file with another connection holding its write lock for ~1.2s in the
    background -- long enough to outlast the 300ms busy_timeout above at least once.
    """
    db_path = tmp_path / "locktest.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _short_timeout_pragmas)
    Base.metadata.create_all(engine)

    def hold_lock() -> None:
        locker = Session(engine)
        locker.execute(text("BEGIN IMMEDIATE"))
        locker.add(Row(id=999, name="locker"))
        locker.flush()
        time.sleep(1.2)
        locker.commit()
        locker.close()

    thread = threading.Thread(target=hold_lock)
    thread.start()
    time.sleep(0.3)  # let the locker acquire the write lock before the test proceeds
    yield engine
    thread.join()


def _all_rows(engine) -> list[tuple[int, str]]:
    with Session(engine) as s:
        return sorted((r.id, r.name) for r in s.query(Row).all())


def test_without_retry_the_write_is_simply_lost(locked_db) -> None:
    """Establishes the failure this whole file exists to fix: a bare commit under contention
    doesn't just raise, it can raise and then quietly accept a retry that writes nothing.
    """
    session = Session(locked_db)
    obj = Row(id=1, name="alpha")
    session.add(obj)
    with pytest.raises(OperationalError, match="database is locked"):
        session.commit()

    session.rollback()
    assert obj not in session, "the object should be expunged by rollback (this is the trap)"
    session.commit()  # "succeeds" -- there is nothing left to commit
    assert (1, "alpha") not in _all_rows(locked_db), (
        "a bare rollback-then-recommit silently drops the write instead of retrying it"
    )


def test_commit_with_retry_survives_contention_and_keeps_the_object(locked_db) -> None:
    """The fixed shape for `run_plan`'s job row: a handful of fresh objects, retried as a unit."""
    session = Session(locked_db)
    job_like = Row(id=1, name="job")

    commit_with_retry(session, job_like, attempts=10)

    assert _all_rows(locked_db) == [(1, "job"), (999, "locker")]


def test_commit_with_retry_reraises_once_attempts_are_exhausted(locked_db) -> None:
    """A real, non-transient failure (or one that outlasts a reasonable retry budget) must still
    surface as an error -- retrying forever silently would trade one bad failure mode for another.
    """
    session = Session(locked_db)
    with pytest.raises(OperationalError, match="database is locked"):
        commit_with_retry(session, Row(id=1, name="x"), attempts=1)


def test_retry_write_on_lock_redoes_a_multi_step_operation_without_duplicating(locked_db) -> None:
    """The fixed shape for `build_plan`: several objects added across intermediate `flush()`
    calls of its own, followed by a final commit -- any one of which could be where the lock is
    hit. The correct unit of retry is the WHOLE operation, redone from a clean rollback; this pins
    that a genuinely failed-then-retried multi-step write lands exactly once, not zero or twice.
    """
    session = Session(locked_db)
    call_count = 0

    def build_several_rows() -> str:
        nonlocal call_count
        call_count += 1
        a = Row(id=1, name="alpha")
        session.add(a)
        session.flush()
        b = Row(id=2, name="beta")
        session.add(b)
        session.flush()
        session.commit()
        return "built"

    result = retry_write_on_lock(session, build_several_rows, attempts=10)

    assert result == "built"
    assert call_count > 1, "the fixture's lock was never actually hit, so this proves nothing"
    assert _all_rows(locked_db) == [(1, "alpha"), (2, "beta"), (999, "locker")]


def test_retry_write_on_lock_reraises_once_attempts_are_exhausted(locked_db) -> None:
    session = Session(locked_db)

    def always_locked() -> None:
        session.add(Row(id=1, name="x"))
        session.commit()

    with pytest.raises(OperationalError, match="database is locked"):
        retry_write_on_lock(session, always_locked, attempts=1)


def test_a_clean_write_with_no_contention_is_unaffected(tmp_path: Path) -> None:
    """The common case -- no lock in sight -- must not be slowed or changed by either helper."""
    db_path = tmp_path / "clean.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    session = Session(engine)

    commit_with_retry(session, Row(id=1, name="a"))
    result = retry_write_on_lock(
        session,
        lambda: (session.add(Row(id=2, name="b")), session.commit(), "ok")[-1],
    )

    assert result == "ok"
    assert _all_rows(engine) == [(1, "a"), (2, "b")]
