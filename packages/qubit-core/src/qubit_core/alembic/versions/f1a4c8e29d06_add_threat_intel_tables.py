"""add_threat_intel_tables

Revision ID: f1a4c8e29d06
Revises: a4c9f2e6b813
Create Date: 2026-08-26 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a4c8e29d06"
down_revision: str | Sequence[str] | None = "a4c9f2e6b813"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # checkfirst by hand: an install whose schema came from `Base.metadata.create_all()` at API
    # startup already has these tables, and re-creating them would abort the upgrade.
    inspector = sa.inspect(op.get_bind())

    if not inspector.has_table("threat_intel_config"):
        op.create_table(
            "threat_intel_config",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("check_interval_hours", sa.Integer(), nullable=False),
            sa.Column("last_checked_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )

    if not inspector.has_table("threat_intel_snapshots"):
        op.create_table(
            "threat_intel_snapshots",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("source_id", sa.String(length=64), nullable=False),
            sa.Column("source_url", sa.String(length=512), nullable=False),
            sa.Column("fetched_at", sa.DateTime(), nullable=False),
            sa.Column("content_hash", sa.String(length=64), nullable=True),
            sa.Column("excerpt", sa.Text(), nullable=False),
            sa.Column("fetch_error", sa.String(length=512), nullable=True),
            sa.Column("changed_from_previous", sa.Boolean(), nullable=False),
            sa.Column("reviewed", sa.Boolean(), nullable=False),
            sa.Column("reviewed_at", sa.DateTime(), nullable=True),
            sa.Column("reviewer_note", sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        with op.batch_alter_table("threat_intel_snapshots", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_threat_intel_snapshots_source_id"), ["source_id"], unique=False
            )
            batch_op.create_index(
                batch_op.f("ix_threat_intel_snapshots_fetched_at"), ["fetched_at"], unique=False
            )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("threat_intel_snapshots", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_threat_intel_snapshots_fetched_at"))
        batch_op.drop_index(batch_op.f("ix_threat_intel_snapshots_source_id"))
    op.drop_table("threat_intel_snapshots")
    op.drop_table("threat_intel_config")
