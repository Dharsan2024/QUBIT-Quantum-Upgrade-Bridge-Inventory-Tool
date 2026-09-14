"""add_learned_outcome_is_unwinnable

Revision ID: b8d3f01c62a5
Revises: f1a4c8e29d06
Create Date: 2026-08-27 00:00:00.000000

Whether a recorded failure was QUBIT's own gap rather than the model's ceiling used to be
re-derived after the fact by matching three substrings against the free-text failure message
(`learn._UNWINNABLE_MARKERS`). That was provably incomplete — the router's own detour message says
"ships no rule that recognises", which none of the markers match — so a whole class of
self-inflicted failures was counted against the model in the reliability gate that decides whether
to attempt a rewrite at all.

The callers producing these rejections know exactly why they are failing, so the fact is now stated
at write time instead of guessed at read time.

NULL for every existing row, and no backfill: re-running the old substring match here would just
persist the same incomplete guess as though it were authoritative. Readers treat NULL as "not
stated" and fall back to the legacy match, which is what those rows have always been judged by.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8d3f01c62a5"
down_revision: str | Sequence[str] | None = "f1a4c8e29d06"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # checkfirst by hand: an install whose schema came from `Base.metadata.create_all()` at API
    # startup already has this column, and adding it twice would abort the upgrade.
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("learned_outcomes"):
        return
    columns = {col["name"] for col in inspector.get_columns("learned_outcomes")}
    if "is_unwinnable" not in columns:
        op.add_column(
            "learned_outcomes",
            sa.Column("is_unwinnable", sa.Boolean(), nullable=True),
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("learned_outcomes", "is_unwinnable")
