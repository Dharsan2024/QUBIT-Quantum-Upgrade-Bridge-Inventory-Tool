"""add_patch_cost_json

Revision ID: f2c8d41a90e3
Revises: e4f19a6c83b7
Create Date: 2026-08-28 00:00:00.000000

What a patch cost the attached model: calls, prompt and completion tokens, seconds, and which
engine answered.

QUBIT's claim about an LLM is an efficiency claim -- deterministic codemods first, replay what has
already been validated, send an excerpt rather than a whole file, refuse an engine that has never
succeeded at a pairing. Every part of that was unmeasurable, because nothing counted the spend:
both engines report usage in their own responses (`prompt_eval_count`/`eval_count` from Ollama,
`usage` from an OpenAI-compatible endpoint) and QUBIT read the answer text and discarded the rest.

It matters most where the budget is smallest. A free tier is rationed in REQUESTS PER DAY --
measured on this installation: 1,000/day on Groq -- and a single patch can cost up to fourteen of
them. A tool that cannot count its own requests cannot pace them, cannot prioritise them, and
cannot explain why it ran out.

Nullable-additive with a default of `{}`, so existing rows read as "nothing recorded" rather than
as "cost nothing" -- those are different claims and the empty dict is honest about which one it is.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f2c8d41a90e3"
down_revision: str | Sequence[str] | None = "e4f19a6c83b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("migration_patches")}
    if "cost_json" not in columns:
        op.add_column(
            "migration_patches",
            sa.Column("cost_json", sa.JSON(), nullable=True),
        )


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("migration_patches")}
    if "cost_json" in columns:
        with op.batch_alter_table("migration_patches") as batch:
            batch.drop_column("cost_json")
