"""add_task_resolution

Separates "QUBIT could not migrate this" from "there was nothing to migrate".

Both outcomes park a task in `deferred`, because the FSM's terminal states all mean "a patch was
applied and verified" and claiming that for a file nothing touched would be a lie. The cost of
sharing one state was that four genuinely-satisfied conditions were reported as failures:

    already migrated by an earlier patch to this file
    already remediated by an earlier task in this plan
    no bump needed - this dependency already pins a PQC-capable version
    nothing left for <codemod> to change

On the polyglot corpus that is 6 of 18 "failures" -- a third of the reported failure rate -- and on
a real repository it is worse, because a plan over 266 tasks routinely has many findings sharing one
file and many pins already at the floor. A migration tool that reports finished work as broken is
not merely noisy: it tells the operator to go and fix something that is already correct.

`resolution` records WHY a task is parked. NULL for every existing row and for every task that never
parked, so this is additive and needs no backfill: readers treat NULL on a deferred task as the
conservative "unresolved", which is what those rows already meant.

Revision ID: d5b2f39c71ae
Revises: c3f81ad4e2b7
Create Date: 2026-08-22 09:40:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d5b2f39c71ae"
down_revision: str | None = "c3f81ad4e2b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "migration_tasks",
        sa.Column("resolution", sa.String(length=32), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("migration_tasks", "resolution")
