"""Exercises qubit_core.db.migrate against a REAL Alembic migration chain — not just a database
built fresh from the current models. create_all() always produces today's schema, so a test that
only ever uses create_all() can never catch "the model was fixed but the migration wasn't", which
is exactly how jobs.project_id kept its broken FK (NO ACTION instead of CASCADE) in every
already-existing database despite the model source saying otherwise. These tests build a database
at an OLD revision first, the way a real upgrade actually encounters it.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from qubit_core.db import get_engine, has_alembic_history, session_factory, upgrade_to_head
from sqlalchemy import inspect, text

_PRE_FIX_REVISION = "fd0d98569dd7"  # the head immediately before 29c500adeb13


def _alembic_config(db_url: str) -> Config:
    alembic_dir = Path(__file__).resolve().parents[1] / "src" / "qubit_core" / "alembic"
    cfg = Config()
    cfg.set_main_option("script_location", str(alembic_dir))
    cfg.attributes["db_url"] = db_url
    return cfg


def test_has_alembic_history_distinguishes_fresh_from_existing(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"
    engine = get_engine(url)
    assert has_alembic_history(engine) is False

    command.stamp(_alembic_config(url), "head")
    # has_alembic_history reads from a fresh inspector, so it must see the just-created table —
    # not a cached view from before the stamp.
    assert has_alembic_history(get_engine(url)) is True


def test_upgrade_to_head_fixes_a_database_created_at_the_old_revision(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    cfg = _alembic_config(url)

    # Build the database the way a real pre-fix installation actually got one: migrated up to
    # the revision that existed before 29c500adeb13, NOT created fresh from today's models.
    command.upgrade(cfg, _PRE_FIX_REVISION)

    engine = get_engine(url)
    insp = inspect(engine)
    fk_before = insp.get_foreign_keys("jobs")[0]
    assert fk_before["options"].get("ondelete") is None  # the pre-fix bug, reproduced

    project_id, job_id = uuid.uuid4(), uuid.uuid4()
    sf = session_factory(engine)
    with sf() as s:
        s.execute(
            text(
                "INSERT INTO projects (id, name, slug, settings, created_at, updated_at) "
                "VALUES (:id, 'p', 'p', '{}', datetime('now'), datetime('now'))"
            ),
            {"id": project_id.hex},
        )
        s.execute(
            text(
                "INSERT INTO jobs (id, kind, status, project_id, progress, stage, message, "
                "payload, created_at) VALUES (:id, 'scan', 'succeeded', :pid, 0, '', '', '{}', "
                "datetime('now'))"
            ),
            {"id": job_id.hex, "pid": project_id.hex},
        )
        s.commit()

    # Confirm the bug is real on this pre-fix database before fixing it: deleting the project
    # must fail with a FK violation (this is the exact 500 users hit).
    with sf() as s:
        s.execute(text("PRAGMA foreign_keys=ON"))
        raised = False
        try:
            s.execute(text("DELETE FROM projects WHERE id = :id"), {"id": project_id.hex})
            s.commit()
        except Exception:  # asserting a DB-level integrity error; exception type is driver-specific
            raised = True
            s.rollback()
        assert raised, "expected the pre-fix schema to reject this delete"

    # Now apply the fix.
    upgrade_to_head(url)

    engine = get_engine(url)
    insp = inspect(engine)
    fk_after = insp.get_foreign_keys("jobs")[0]
    assert fk_after["options"].get("ondelete") == "CASCADE"

    # Data survived the table rebuild.
    sf = session_factory(engine)
    with sf() as s:
        assert s.execute(text("SELECT COUNT(*) FROM jobs")).scalar() == 1
        assert s.execute(text("SELECT COUNT(*) FROM projects")).scalar() == 1

        # And the delete that used to 500 now cascades cleanly.
        s.execute(text("DELETE FROM projects WHERE id = :id"), {"id": project_id.hex})
        s.commit()

    with sf() as s:
        assert s.execute(text("SELECT COUNT(*) FROM projects")).scalar() == 0
        assert s.execute(text("SELECT COUNT(*) FROM jobs")).scalar() == 0, (
            "job row should have cascade-deleted with its project, not been orphaned"
        )
