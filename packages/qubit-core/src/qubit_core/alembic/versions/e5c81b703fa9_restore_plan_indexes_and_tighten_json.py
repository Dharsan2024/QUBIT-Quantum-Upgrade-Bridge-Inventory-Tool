"""restore migration_plans' three indexes and tighten the JSON ledgers to NOT NULL

Six pending operations, reported by `alembic check` against a database already stamped at
`a4c72e91b8d3`. Two unrelated causes, both of them "the model says one thing and the chain never
said it to the database".

**The three indexes were deleted by a migration, not forgotten.** `a1c7e4b90f21` created
`ix_migration_plans_project_id` and `ix_migration_plans_scan_id`; `d4b7c25e8f19` created
`ix_migration_plans_tenant_id`. `c4a17b9e2d05` then rebuilt the table with
`op.batch_alter_table("migration_plans", copy_from=_BEFORE)`, and an explicit `copy_from`
REPLACES the reflection that would otherwise have rediscovered them -- batch mode recreates
exactly what the passed `Table` carries, and `_BEFORE` lists columns and foreign keys and no
`Index` at all. The rebuilt table was therefore created bare. Measured on the live database:
`migration_plans` holds exactly one index, `sqlite_autoindex_migration_plans_1`, the implicit
primary key, while its siblings (`migration_tasks`, `migration_patches`,
`migration_measurements`, `migration_units`) all still carry theirs.

That costs real time on the hot path. `POST /migrate/plan` looks up an existing plan by
`scan_id AND tenant_id` before building a new one -- the guard against a double-click producing
two identical plans -- and the twin harness issues exactly that lookup once per repository.
`EXPLAIN QUERY PLAN` on a copy of the live database: `SCAN migration_plans` over all 66 rows,
41 distinct scans. `GET /migrate/plans` and `delete_project`'s plan sweep are the same shape on
`tenant_id` and `project_id`.

Recreated with plain `op.create_index` rather than batch mode on purpose. `CREATE INDEX` is
legal on SQLite as-is, and a batch rebuild of this particular table would have to reflect it
first -- which is where the two standing `SAWarning: SQL-parsed foreign key constraint ... could
not be located in PRAGMA foreign_keys` come from. Those warnings are NOT a missing constraint.
`c4a17b9e2d05`'s `_BEFORE` declares unnamed `ForeignKey("projects.id")`/`ForeignKey("scans.id")`
columns AND its `_rebuild` adds named ones over the same columns, so the rebuilt DDL emits both:
`PRAGMA foreign_key_list(migration_plans)` returns five rows for three relationships, and
SQLAlchemy's reflector cannot match the SQL-parsed pair against the pragma rows one-to-one. The
rules the model asks for are present and enforced -- `project_id` CASCADE, `scan_id` SET NULL,
`tenant_id` CASCADE -- so the duplicates are cosmetic and rebuilding the table to drop them
would risk live data to silence a log line.

**The three NOT NULL columns are step three of a three-step pattern that stopped at step one.**
`f2c8d41a90e3` (`migration_patches.cost_json`) and `a7d3e91c4f26` (`migration_tasks.spend_json`)
each added a nullable column deliberately, so existing rows would read as "nothing recorded"
rather than as "cost nothing"; `a4c72e91b8d3` created `migration_measurements.stage_outcomes`
nullable in the same spirit. All three models declare `Mapped[dict[str, Any]]`, which is NOT
NULL, and no follow-up ever tightened them. The backfill that the pattern owes them is here.

`{}` is the right fill, and it is what the readers already assume: `analysis.verified_accept`
does `getattr(row, "stage_outcomes", None) or {}`, `orchestrator._record_measurement` does
`task.spend_json or {}`, and the call-ledger charge does `dict(task.spend_json or {})`. NULL and
`{}` were never distinguished by any consumer, so collapsing them loses nothing.

On this installation the backfill is a no-op and the constraint is the whole change: 0 of 597
`stage_outcomes`, 0 of 271 `cost_json` and 0 of 2,385 `spend_json` rows are NULL, because every
writer has always gone through the ORM and its `default=dict`. The UPDATEs run anyway -- an
installation that predates any of the three columns is exactly the case the constraint would
otherwise fail on, and that is the case this migration exists to serve.

Revision ID: e5c81b703fa9
Revises: a4c72e91b8d3
Create Date: 2026-09-04 00:00:00.000000

"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5c81b703fa9"
down_revision: str | Sequence[str] | None = "a4c72e91b8d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The JSON ledgers whose models say NOT NULL. `{}` is the fill because it is what every reader
#: already coerces a missing value to -- see the module docstring.
_JSON_COLUMNS = (
    ("migration_measurements", "stage_outcomes"),
    ("migration_patches", "cost_json"),
    ("migration_tasks", "spend_json"),
)

#: The indexes `c4a17b9e2d05`'s `copy_from` rebuild dropped.
_PLAN_INDEXES = (
    ("ix_migration_plans_project_id", "project_id"),
    ("ix_migration_plans_scan_id", "scan_id"),
    ("ix_migration_plans_tenant_id", "tenant_id"),
)


def _reflect_column(table: str, column: str) -> dict[str, Any] | None:
    """The reflected column, or None if the table or the column is absent.

    Every migration in this chain guards this way, and here it earns it twice over: a database
    built by `Base.metadata.create_all()` and then `stamp_head()`ed already has today's schema,
    so an unguarded `alter_column`/`create_index` would fail on exactly the databases that never
    needed this revision.
    """
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return None
    for col in inspector.get_columns(table):
        if col["name"] == column:
            return col
    return None


def _set_nullable(table: str, column: str, *, nullable: bool) -> None:
    """Flip one column's NOT NULL, skipping what is already in the wanted state.

    Batch mode because SQLite has no `ALTER COLUMN`: the table is rebuilt from its own
    reflection, which -- unlike the `copy_from` route that cost `migration_plans` its indexes
    above -- carries the existing indexes and `ondelete` rules across. `d4b7c25e8f19` verified
    that distinction on a scratch database before relying on it, and this revision re-verified
    it on a copy of the live database: `migration_tasks` kept `ix_migration_tasks_plan_id` and
    all three CASCADE rules, `migration_patches` kept its task CASCADE, and
    `migration_measurements` kept its four indexes and its `SET NULL`.
    """
    col = _reflect_column(table, column)
    if col is None or bool(col["nullable"]) is nullable:
        return  # absent, or already in the state being asked for
    with op.batch_alter_table(table, schema=None) as batch:
        batch.alter_column(column, existing_type=sa.JSON(), nullable=nullable)


def upgrade() -> None:
    """Upgrade schema."""
    # Backfill BEFORE tightening. A NOT NULL added over even one NULL row aborts the rebuild and
    # rolls the whole migration back, and the rows at risk are the oldest ones -- written before
    # each column existed -- which is precisely the population an upgrade has to survive.
    for table, column in _JSON_COLUMNS:
        if _reflect_column(table, column) is None:
            continue
        target = sa.table(table, sa.column(column, sa.JSON()))
        op.execute(target.update().where(sa.column(column).is_(None)).values(**{column: {}}))

    for table, column in _JSON_COLUMNS:
        _set_nullable(table, column, nullable=False)

    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("migration_plans"):
        existing = {ix["name"] for ix in inspector.get_indexes("migration_plans")}
        for name, column in _PLAN_INDEXES:
            if name not in existing:
                op.create_index(name, "migration_plans", [column])


def downgrade() -> None:
    """Downgrade schema.

    The constraints and the indexes come back off, which is the whole of what `upgrade()` changed
    about the schema. The backfill is deliberately not undone: nothing distinguishes a row this
    migration filled from one an ORM insert wrote as `{}` on its own, so re-NULLing would have to
    guess, and here it would guess wrong on all 3,253 rows that were already `{}`.
    """
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("migration_plans"):
        existing = {ix["name"] for ix in inspector.get_indexes("migration_plans")}
        for name, _column in reversed(_PLAN_INDEXES):
            if name in existing:
                op.drop_index(name, table_name="migration_plans")

    for table, column in reversed(_JSON_COLUMNS):
        _set_nullable(table, column, nullable=True)
