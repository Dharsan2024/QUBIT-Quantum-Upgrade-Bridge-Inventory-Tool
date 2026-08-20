"""scope_migration_plans_to_project

``MigrationOrchestrator.build_plan`` selected EVERY vulnerable, risk-scored asset in the database —
across every project and every historical scan — and the plan it produced recorded no scope at all
(``scope_json`` was left ``{}`` on every plan ever built). The Migration Hub then showed whichever
plan happened to be newest, so after scanning a project you were looking at a queue assembled from
some other project's assets, and the project you had just scanned appeared nowhere. These two
columns give a plan the project (and optionally the single scan) it was built from.

Both are nullable. Plans built before this revision genuinely had no scope, and inventing one for
them would be a fabrication — NULL says "unscoped, built across everything", which is the truth.

Uses ``ALTER TABLE ... ADD COLUMN`` rather than the table-rebuild dance revision 29c500adeb13
needed: SQLite permits a ``REFERENCES`` clause on ADD COLUMN when the default is NULL, as it is
here.

On SQLite that ALTER is issued as raw SQL rather than through ``op.add_column``. Alembic splits a
``Column`` carrying a ``ForeignKey`` into an ADD COLUMN plus a separate ADD CONSTRAINT, and the
SQLite dialect raises ``NotImplementedError`` on the second half — even though the single statement
SQLite actually needs is legal and works. Other dialects take the ordinary ``op.add_column`` path.

Verified on a copy of a real 24-plan database before shipping — the DDL carries the ``ON DELETE
CASCADE``, and deleting a project really does remove its plans (checked by row count, not by reading
the DDL, because 29c500adeb13's notes record a case where the clause was present in the definition
and absent in behaviour).

Revision ID: a1c7e4b90f21
Revises: 29c500adeb13
Create Date: 2026-08-20 18:40:11.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1c7e4b90f21"
down_revision: str | Sequence[str] | None = "29c500adeb13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema: add the project/scan scope columns to migration_plans."""
    if op.get_bind().dialect.name == "sqlite":
        # One statement per column, each legal on SQLite because the implied default is NULL.
        op.execute(
            "ALTER TABLE migration_plans ADD COLUMN project_id CHAR(32) "
            "REFERENCES projects (id) ON DELETE CASCADE"
        )
        op.execute(
            "ALTER TABLE migration_plans ADD COLUMN scan_id CHAR(32) "
            "REFERENCES scans (id) ON DELETE SET NULL"
        )
    else:
        op.add_column(
            "migration_plans",
            sa.Column(
                "project_id",
                sa.Uuid(),
                sa.ForeignKey("projects.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )
        op.add_column(
            "migration_plans",
            sa.Column(
                "scan_id",
                sa.Uuid(),
                sa.ForeignKey("scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    op.create_index("ix_migration_plans_project_id", "migration_plans", ["project_id"])
    op.create_index("ix_migration_plans_scan_id", "migration_plans", ["scan_id"])


def downgrade() -> None:
    """Downgrade schema: drop the scope columns."""
    op.drop_index("ix_migration_plans_scan_id", table_name="migration_plans")
    op.drop_index("ix_migration_plans_project_id", table_name="migration_plans")
    op.drop_column("migration_plans", "scan_id")
    op.drop_column("migration_plans", "project_id")
