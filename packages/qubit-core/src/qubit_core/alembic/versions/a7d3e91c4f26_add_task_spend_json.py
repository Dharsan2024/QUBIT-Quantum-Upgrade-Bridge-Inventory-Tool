"""add_task_spend_json

Revision ID: a7d3e91c4f26
Revises: f2c8d41a90e3
Create Date: 2026-08-28 00:00:00.000000

Model requests and tokens a TASK has consumed, accumulated across every attempt.

`migration_patches.cost_json` (revision `f2c8d41a90e3`) records what a successful patch cost, and
that is not the same question. A finding that exhausts its repair budget and fails produces no patch
row at all, so its spend had nowhere to live -- and those are the expensive attempts. Measured on
this installation while adding the ledger: three findings spent ten requests and 44,502 tokens
between them and produced nothing, of which only two were recorded, because the third never reached
a patch. Losing exactly the failures biases the efficiency figure in the flattering direction, which
is the one direction an efficiency claim must not be biased in.

Nullable-additive with a `{}` default, so existing rows read as "nothing recorded" rather than as
"cost nothing" -- different claims, and the empty dict is honest about which one it is.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7d3e91c4f26"
down_revision: str | Sequence[str] | None = "f2c8d41a90e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("migration_tasks")}
    if "spend_json" not in columns:
        op.add_column("migration_tasks", sa.Column("spend_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("migration_tasks")}
    if "spend_json" in columns:
        with op.batch_alter_table("migration_tasks") as batch:
            batch.drop_column("spend_json")
