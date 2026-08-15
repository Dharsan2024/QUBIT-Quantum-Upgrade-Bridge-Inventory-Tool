"""fix_jobs_project_id_cascade

``jobs.project_id`` was created (revision efae907d39c1) without ``ondelete="CASCADE"``. The
qubit_core.db.models.Job model was later corrected to declare it, but that fix was never
migrated — Base.metadata.create_all() only creates missing tables, it never alters an existing
one's constraints — so any database created before this migration still 500s on
DELETE /projects/{id} for a project with a job history (which is effectively every project that
has run a scan). This migration is the actual fix; the model change alone was not enough.

Uses raw SQL rather than Alembic's batch mode: batch mode's ``drop_constraint`` requires a name
to match against, and the original FK was created unnamed (SQLite doesn't name constraints
unless asked to); its ``copy_from`` alternative was tried and, empirically, silently dropped the
``ondelete`` clause from the rebuilt table (verified against a scratch copy of a real database —
the resulting DDL had a plain ``FOREIGN KEY(project_id) REFERENCES projects (id)`` with no
``ON DELETE CASCADE`` despite it being present on the ``copy_from`` Table definition). The classic
SQLite "rebuild the table" sequence below is explicit and was verified end-to-end (row counts,
data, indexes, and the actual cascade-delete behavior) against a live database copy before this
migration was applied to any real database.

Revision ID: 29c500adeb13
Revises: fd0d98569dd7
Create Date: 2026-08-15 14:53:28.682225

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "29c500adeb13"
down_revision: str | Sequence[str] | None = "fd0d98569dd7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    "id, kind, status, project_id, ref_id, progress, stage, message, "
    "payload, result, error, created_at, started_at, finished_at"
)


def _rebuild(fk_clause: str) -> None:
    op.execute("PRAGMA foreign_keys=OFF")
    op.execute(
        f"""
        CREATE TABLE jobs_new (
            id CHAR(32) NOT NULL,
            kind VARCHAR(16) NOT NULL,
            status VARCHAR(12) NOT NULL,
            project_id CHAR(32),
            ref_id CHAR(32),
            progress FLOAT NOT NULL,
            stage VARCHAR(64) NOT NULL,
            message VARCHAR(256) NOT NULL,
            payload JSON NOT NULL,
            result JSON,
            error VARCHAR,
            created_at DATETIME NOT NULL,
            started_at DATETIME,
            finished_at DATETIME,
            PRIMARY KEY (id),
            {fk_clause}
        )
        """
    )
    # _COLUMNS is a fixed module-level constant, not user input — no injection risk.
    op.execute(f"INSERT INTO jobs_new ({_COLUMNS}) SELECT {_COLUMNS} FROM jobs")  # noqa: S608
    op.execute("DROP TABLE jobs")
    op.execute("ALTER TABLE jobs_new RENAME TO jobs")
    op.execute("CREATE INDEX ix_jobs_project_id ON jobs (project_id)")
    op.execute("CREATE INDEX ix_jobs_status ON jobs (status)")
    op.execute("PRAGMA foreign_keys=ON")


def upgrade() -> None:
    """Upgrade schema: rebuild jobs.project_id's FK with ON DELETE CASCADE."""
    _rebuild("FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE")


def downgrade() -> None:
    """Downgrade schema: restore the original NO ACTION behavior."""
    _rebuild("FOREIGN KEY(project_id) REFERENCES projects (id)")
