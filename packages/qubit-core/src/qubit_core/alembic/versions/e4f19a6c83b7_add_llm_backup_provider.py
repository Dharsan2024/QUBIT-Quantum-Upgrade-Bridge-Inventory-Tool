"""add_llm_backup_provider

Revision ID: e4f19a6c83b7
Revises: d3b8c02a7e51
Create Date: 2026-08-27 00:00:00.000000

A second OpenAI-compatible endpoint, tried when the primary refuses the request. Free tiers cap
tokens per minute, and that cap -- not the model's context window -- is the practical limit on how
much of a repository can be migrated in one sitting.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e4f19a6c83b7"
down_revision: str | Sequence[str] | None = "d3b8c02a7e51"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    ("backup_base_url", sa.String()),
    ("backup_model", sa.String()),
    ("backup_api_key_encrypted", sa.LargeBinary()),
    ("backup_api_key_last4", sa.String()),
    ("backup_context_tokens", sa.Integer()),
)


def upgrade() -> None:
    """Upgrade schema."""
    # All nullable-additive, so no backfill: NULL means "no backup configured", which is the
    # correct state for every existing install. Same style as `d5b2f39c71ae` / `a4c9f2e6b813`.
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("llm_provider_config"):
        return
    existing = {c["name"] for c in inspector.get_columns("llm_provider_config")}
    for name, type_ in _COLUMNS:
        if name not in existing:
            op.add_column("llm_provider_config", sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    for name, _ in reversed(_COLUMNS):
        op.drop_column("llm_provider_config", name)
