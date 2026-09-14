"""add_learned_outcomes_table

The experience base beside the line cache. `learned_patches` only ever stored single-line fixes
whose line count did not change, so the multi-statement rewrites the generator prompt actually
asks for taught it nothing: measured on this project's own store, 59 accepted LLM patches produced
21 entries. This table records hunks, failures and the model's own reasoning, keyed by a
structural shape rather than an exact string.

Revision ID: e7a3c02f1b48
Revises: b2e1f8a9c4d3
Create Date: 2026-08-25 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7a3c02f1b48"
down_revision: str | Sequence[str] | None = "b2e1f8a9c4d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())

    # `checkfirst` semantics by hand, for the same reason the previous revision needed them: an
    # installation whose database was built by `Base.metadata.create_all()` at API startup already
    # has this table, and re-creating it aborts the upgrade.
    if not inspector.has_table("learned_outcomes"):
        op.create_table(
            "learned_outcomes",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("rule_id", sa.String(length=64), nullable=False),
            sa.Column("language", sa.String(length=32), nullable=False),
            sa.Column("algorithm", sa.String(length=64), nullable=True),
            sa.Column("shape_key", sa.String(length=64), nullable=False),
            sa.Column("outcome", sa.String(length=16), nullable=False),
            sa.Column("hunk_before", sa.Text(), nullable=False),
            sa.Column("hunk_after", sa.Text(), nullable=False),
            sa.Column("reasoning", sa.Text(), nullable=False),
            sa.Column("failure_reason", sa.Text(), nullable=False),
            sa.Column("source_model", sa.String(length=128), nullable=True),
            sa.Column("hit_count", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_learned_outcomes_rule_id", "learned_outcomes", ["rule_id"])
        op.create_index("ix_learned_outcomes_language", "learned_outcomes", ["language"])
        op.create_index("ix_learned_outcomes_shape_key", "learned_outcomes", ["shape_key"])
        op.create_index("ix_learned_outcomes_outcome", "learned_outcomes", ["outcome"])
        op.create_index("ix_learned_outcomes_created_at", "learned_outcomes", ["created_at"])

    # Rows written before the language key was validated carry the rule's `multi` rather than the
    # file's language. `get_experience_for_rule` filters on the file language, so those rows could
    # never be retrieved for grounding - dead from the moment they were written, and 17 of the 21
    # rows in this installation are in that state. There is no way to recover which language each
    # one came from, so they are marked `unknown`: still usable for EXACT line reuse, which does
    # not filter on language, and no longer pretending to be a language that lookups ask for.
    if inspector.has_table("learned_patches"):
        op.execute(
            sa.text("UPDATE learned_patches SET language = 'unknown' WHERE language = 'multi'")
        )


def downgrade() -> None:
    """Downgrade schema."""
    if sa.inspect(op.get_bind()).has_table("learned_outcomes"):
        op.drop_table("learned_outcomes")
