"""restore the ON DELETE rules migration_plans' model already declares

Schema drift, and it broke a user-visible feature outright. `MigrationPlan` declares
`project_id` with `ondelete="CASCADE"` and `scan_id` with `ondelete="SET NULL"`, but the table was
created before those were added and no migration ever rewrote the constraints -- so the live
database carried both foreign keys with **no rule at all**, and unnamed. SQLite enforces that
literally: deleting a project that has ever been migrated fails with

    sqlalchemy.exc.IntegrityError: (sqlite3.IntegrityError) FOREIGN KEY constraint failed
    [SQL: DELETE FROM projects WHERE projects.id = ?]

which is exactly what the Settings cleanup button hit -- 33 projects, none deletable. Every other
child of `projects` (assets, jobs, scans) already cascaded, so from the outside the failure looked
arbitrary: projects without a plan deleted, projects with one did not.

The constraints are unnamed in the live schema, so there is nothing for `drop_constraint` to take
hold of. SQLite has no `ALTER TABLE ... DROP CONSTRAINT` either, so the table is rebuilt: batch mode
with an explicit `copy_from` recreates it from the definition below and copies the rows. The whole
table is restated rather than just the one constraint, because a rebuild that named only
`project_id` would silently drop `scan_id`'s rule as well.

Revision ID: c4a17b9e2d05
Revises: b5e21f7a3c94
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c4a17b9e2d05"
down_revision = "b5e21f7a3c94"
branch_labels = None
depends_on = None

#: The table as it exists BEFORE this migration -- what `copy_from` needs in order to know which
#: columns to carry across. Mirrors the live schema exactly, including the unnamed foreign keys.
_BEFORE = sa.Table(
    "migration_plans",
    sa.MetaData(),
    sa.Column("id", sa.CHAR(32), primary_key=True, nullable=False),
    sa.Column("created_at", sa.DateTime(), nullable=False),
    sa.Column("scope_json", sa.JSON(), nullable=False),
    sa.Column("config_json", sa.JSON(), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("stats_json", sa.JSON(), nullable=False),
    sa.Column("project_id", sa.CHAR(32), sa.ForeignKey("projects.id"), nullable=True),
    sa.Column("scan_id", sa.CHAR(32), sa.ForeignKey("scans.id"), nullable=True),
    sa.Column(
        "tenant_id",
        sa.CHAR(32),
        sa.ForeignKey("tenants.id", ondelete="CASCADE", name="fk_migration_plans_tenant_id"),
        nullable=False,
    ),
)


def _rebuild(project_rule: str | None, scan_rule: str | None) -> None:
    with op.batch_alter_table("migration_plans", copy_from=_BEFORE, schema=None) as batch:
        batch.create_foreign_key(
            "fk_migration_plans_project_id_projects",
            "projects",
            ["project_id"],
            ["id"],
            ondelete=project_rule,
        )
        batch.create_foreign_key(
            "fk_migration_plans_scan_id_scans",
            "scans",
            ["scan_id"],
            ["id"],
            ondelete=scan_rule,
        )


def upgrade() -> None:
    _rebuild(project_rule="CASCADE", scan_rule="SET NULL")


def downgrade() -> None:
    _rebuild(project_rule=None, scan_rule=None)
