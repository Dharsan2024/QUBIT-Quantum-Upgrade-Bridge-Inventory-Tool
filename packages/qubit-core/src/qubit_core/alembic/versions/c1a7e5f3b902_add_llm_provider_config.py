"""add_llm_provider_config

Revision ID: c1a7e5f3b902
Revises: e2f6b94c17da
Create Date: 2026-08-27 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1a7e5f3b902"
down_revision: str | Sequence[str] | None = "e2f6b94c17da"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # checkfirst by hand: an install whose schema came from `Base.metadata.create_all()` at API
    # startup already has this table, and re-creating it would abort the upgrade -- same pattern
    # `f1a4c8e29d06` (threat-intel tables) already established for a brand-new table.
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("llm_provider_config"):
        op.create_table(
            "llm_provider_config",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("provider", sa.String(), nullable=False),
            sa.Column("base_url", sa.String(), nullable=True),
            sa.Column("model", sa.String(), nullable=True),
            sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=True),
            sa.Column("api_key_last4", sa.String(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("llm_provider_config")
