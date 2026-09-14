"""add_learned_patches_table

Revision ID: b2e1f8a9c4d3
Revises: d5b2f39c71ae
Create Date: 2026-08-24 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2e1f8a9c4d3"
down_revision: str | Sequence[str] | None = "d5b2f39c71ae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # `checkfirst` semantics by hand: an installation whose database was built by
    # `Base.metadata.create_all()` at API startup already has this table, and re-creating it would
    # abort the upgrade. Only genuinely-missing tables are created here.
    if not sa.inspect(op.get_bind()).has_table("learned_patches"):
        op.create_table(
            "learned_patches",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("rule_id", sa.String(length=64), nullable=False),
            sa.Column("language", sa.String(length=32), nullable=False),
            sa.Column("algorithm", sa.String(length=64), nullable=True),
            sa.Column("snippet_key", sa.String(length=64), nullable=False),
            sa.Column("snippet_before", sa.Text(), nullable=False),
            sa.Column("snippet_after", sa.Text(), nullable=False),
            sa.Column("source_model", sa.String(length=128), nullable=True),
            sa.Column("hit_count", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("rule_id", "snippet_key", name="uq_learned_patch_key"),
        )
        with op.batch_alter_table("learned_patches", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_learned_patches_rule_id"), ["rule_id"], unique=False
            )
            batch_op.create_index(
                batch_op.f("ix_learned_patches_snippet_key"), ["snippet_key"], unique=False
            )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("learned_patches", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_learned_patches_snippet_key"))
        batch_op.drop_index(batch_op.f("ix_learned_patches_rule_id"))

    op.drop_table("learned_patches")
