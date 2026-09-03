"""add learned_rules: migration rules QUBIT derived and then proved

A finding the hand-written pack does not cover used to resolve to written guidance, which reads as
a refusal for anything that is in fact migratable. `transform.synthesized` derives a rule for those
from QUBIT's own knowledge base; this table keeps the ones whose patch passed validation, so the
next occurrence is answered from a rule that has already been shown to work rather than derived
again from scratch.

Only validated derivations are written here. An unvalidated rule is a guess, and persisting guesses
would let one bad derivation poison every later finding that matches it.

Revision ID: d7b3f1c68a42
Revises: c4a17b9e2d05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.types import JSON, Uuid

revision = "d7b3f1c68a42"
down_revision = "c4a17b9e2d05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "learned_rules",
        sa.Column("id", Uuid, primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            Uuid,
            sa.ForeignKey("tenants.id", ondelete="CASCADE", name="fk_learned_rules_tenant_id"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(96), nullable=False),
        sa.Column("language", sa.String(32), nullable=False),
        sa.Column("family", sa.String(64), nullable=False),
        sa.Column("usage_context", sa.String(32), nullable=False),
        sa.Column("target_algorithm", sa.String(64), nullable=False),
        sa.Column("rule_json", JSON, nullable=False),
        sa.Column("source_model", sa.String(128), nullable=True),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "rule_id", name="uq_learned_rule_key"),
    )
    op.create_index("ix_learned_rules_tenant_id", "learned_rules", ["tenant_id"])
    op.create_index("ix_learned_rules_rule_id", "learned_rules", ["rule_id"])
    op.create_index("ix_learned_rules_family", "learned_rules", ["family"])


def downgrade() -> None:
    op.drop_index("ix_learned_rules_family", table_name="learned_rules")
    op.drop_index("ix_learned_rules_rule_id", table_name="learned_rules")
    op.drop_index("ix_learned_rules_tenant_id", table_name="learned_rules")
    op.drop_table("learned_rules")
