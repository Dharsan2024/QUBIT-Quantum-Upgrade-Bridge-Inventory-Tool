"""Learning must never be able to fail the migration that produced it.

The learning store is a side benefit: a validated rewrite is remembered so the next identical
finding is grounded in it. It writes counters, and counters are the least important thing in the
system -- which is exactly why they must not be able to take anything down with them.

They could. Once several findings were prepared at once, SQLite write contention became real, and a
`learned_outcomes` hit-count bump lost the race with "database is locked". The bump was a pending
ORM change, so the failure did not surface at the bump: it surfaced at the next autoflush, deep
inside unrelated work, leaving the Session dead for everything after it. A run that had already
prepared 133 of 143 findings on the certbot corpus was reported as FAILED at 93%. The patches were
generated, validated and stored. The run was thrown away over a counter.
"""

from __future__ import annotations

import uuid

from qubit_core.db import Base
from qubit_core.db.models import LearnedOutcome
from qubit_core.schemas import utcnow
from qubit_migrate.transform import learn
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session


def _session_with_outcome() -> tuple[Session, LearnedOutcome]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    row = LearnedOutcome(
        id=uuid.uuid4(),
        rule_id="py-weakhash-01",
        language="python",
        shape_key="hashlib.md5(ARG)",
        outcome="passed",
        hunk_before="hashlib.md5(data)",
        hunk_after="hashlib.sha256(data)",
        reasoning="",
        failure_reason="",
        hit_count=0,
        created_at=utcnow(),
    )
    session.add(row)
    session.commit()
    return session, row


def test_a_locked_database_does_not_raise_out_of_touch(monkeypatch) -> None:
    """The bump is attempted, briefly retried, and then given up on."""
    session, row = _session_with_outcome()
    before = row.hit_count

    def always_locked() -> None:
        raise OperationalError("flush", {}, Exception("database is locked"))

    monkeypatch.setattr(session, "flush", always_locked)
    learn.touch(session, row)  # must not raise
    monkeypatch.undo()
    assert row.hit_count in (before, before + 1), "the count is either written or dropped, not torn"


def test_the_session_is_usable_after_a_dropped_bump(monkeypatch) -> None:
    """The point of `expire` over leaving the change pending.

    A pending change that could not be written flushes again at the next query -- so the failure
    reappears somewhere unrelated, which is precisely the bug. Discarding it leaves the Session
    clean and the object attached, so the caller carries on.
    """
    session, row = _session_with_outcome()

    def always_locked() -> None:
        raise OperationalError("flush", {}, Exception("database is locked"))

    monkeypatch.setattr(session, "flush", always_locked)
    learn.touch(session, row)
    monkeypatch.undo()

    # The query that would previously have raised, carrying an error about a table the caller
    # never touched.
    assert session.get(LearnedOutcome, row.id) is not None
    session.commit()


def test_a_successful_bump_is_written_immediately() -> None:
    """Not left pending. The write happening HERE is what keeps a later, unrelated query from
    being the thing that discovers the database was busy."""
    session, row = _session_with_outcome()
    learn.touch(session, row)

    assert row.hit_count == 1
    assert row.last_used_at is not None
    # Visible to a second session only after commit; what matters here is that it is no longer a
    # pending change waiting to ambush an autoflush.
    assert not session.dirty, "the bump must not still be pending after touch()"
