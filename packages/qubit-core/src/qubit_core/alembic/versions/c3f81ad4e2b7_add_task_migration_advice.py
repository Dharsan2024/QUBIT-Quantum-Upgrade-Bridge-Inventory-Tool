"""add_task_migration_advice

A task QUBIT cannot patch previously showed "manual change" and nothing else — an algorithm name and
a line number, with the reader left to work out what the code does, what it should become, and what
breaks on the way. These columns hold the other half: model-written guidance for that specific
finding, generated from the real file and cached so it is written once and read many times.

Nullable, because most tasks never need it: a task with a working codemod is answered by its patch.

Revision ID: c3f81ad4e2b7
Revises: a1c7e4b90f21
Create Date: 2026-08-21 12:05:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3f81ad4e2b7"
down_revision: str | Sequence[str] | None = "a1c7e4b90f21"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema: add the advice columns to migration_tasks."""
    op.add_column("migration_tasks", sa.Column("advice_text", sa.Text(), nullable=True))
    op.add_column(
        "migration_tasks", sa.Column("advice_model", sa.String(length=128), nullable=True)
    )
    op.add_column("migration_tasks", sa.Column("advice_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema: drop the advice columns."""
    op.drop_column("migration_tasks", "advice_at")
    op.drop_column("migration_tasks", "advice_model")
    op.drop_column("migration_tasks", "advice_text")
