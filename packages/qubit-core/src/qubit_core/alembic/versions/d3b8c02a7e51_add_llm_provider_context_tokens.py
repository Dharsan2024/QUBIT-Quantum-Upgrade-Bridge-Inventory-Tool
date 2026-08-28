"""add_llm_provider_context_tokens

Revision ID: d3b8c02a7e51
Revises: c1a7e5f3b902
Create Date: 2026-08-27 00:00:00.000000

A separate migration rather than an edit to `c1a7e5f3b902`, which has already been applied to a
real database: editing an applied revision would leave that database without the column while
Alembic still reported it at head.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3b8c02a7e51"
down_revision: str | Sequence[str] | None = "c1a7e5f3b902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable-additive, so no backfill: NULL means "the provider never told us", and the caller
    # falls back to `MigrateConfig.llm_context_tokens` exactly as it did before this column
    # existed. Same nullable-additive style as `d5b2f39c71ae` / `a4c9f2e6b813`.
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("llm_provider_config"):
        return
    existing = {c["name"] for c in inspector.get_columns("llm_provider_config")}
    if "context_tokens" not in existing:
        op.add_column(
            "llm_provider_config", sa.Column("context_tokens", sa.Integer(), nullable=True)
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("llm_provider_config", "context_tokens")
