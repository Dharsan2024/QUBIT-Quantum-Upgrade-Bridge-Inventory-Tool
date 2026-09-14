"""add_llm_engine_pool

Revision ID: b5e21f7a3c94
Revises: a7d3e91c4f26
Create Date: 2026-08-28 00:00:00.000000

Any number of attachable engines, instead of the two slots `llm_provider_config` allows.

Two slots is a real ceiling on the thing QUBIT is trying to be good at. A hosted free tier is
rationed per PROJECT -- measured on this installation: Groq allows 1,000 requests/day and 8,000
tokens/minute, and two Google keys belonging to the same project share one quota while a different
model on the same key gets its own. The way to have more capacity is therefore not a better model,
it is MORE INDEPENDENT TIERS -- and with two slots a third key had nowhere to go.

Additive and non-destructive: `llm_provider_config` is left exactly as it is, and an install that
never adds a pooled engine behaves as it always has. The orchestrator reads both, so the primary
and backup keep working while the pool grows beside them.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b5e21f7a3c94"
down_revision: str | Sequence[str] | None = "a7d3e91c4f26"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if "llm_engines" in inspector.get_table_names():
        return
    op.create_table(
        "llm_engines",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        # Fernet ciphertext, never serialised outward. Same treatment as `llm_provider_config`.
        sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("api_key_last4", sa.String(length=8), nullable=False, server_default=""),
        # The provider's EFFECTIVE per-request allowance, which on a free tier is a rate limit far
        # below the model's advertised context window.
        sa.Column("context_tokens", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if "llm_engines" in inspector.get_table_names():
        op.drop_table("llm_engines")
