"""create_tenants

Revision ID: c9e5a71b3d84
Revises: b8d3f01c62a5
Create Date: 2026-08-27 00:10:00.000000

The first half of self-hosted multi-team isolation: the table that teams are rows in, plus the one
default tenant every existing install's data belongs to.

This is the first migration in the chain that INSERTS a literal value rather than moving data
between columns. The id is bound through `sa.Uuid()` rather than formatted into the SQL by hand,
because SQLite stores a UUID as 32 hex characters while PostgreSQL uses a native UUID type — the
type's own bind processor knows which, and a hand-written literal would be right on exactly one of
them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from qubit_core.db.models import DEFAULT_TENANT_ID, DEFAULT_TENANT_SLUG

# revision identifiers, used by Alembic.
revision: str = "c9e5a71b3d84"
down_revision: str | Sequence[str] | None = "b8d3f01c62a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("slug", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("slug"),
            sa.UniqueConstraint("name"),
        )
        with op.batch_alter_table("tenants", schema=None) as batch_op:
            batch_op.create_index(batch_op.f("ix_tenants_slug"), ["slug"], unique=True)

    # Seed the default tenant. Idempotent: an install whose schema came from
    # `Base.metadata.create_all()` may already have had it created by `ensure_default_tenant`.
    tenants = sa.table(
        "tenants",
        sa.column("id", sa.Uuid()),
        sa.column("slug", sa.String()),
        sa.column("name", sa.String()),
        sa.column("created_at", sa.DateTime()),
    )
    bind = op.get_bind()
    already = bind.execute(
        sa.select(sa.func.count()).select_from(tenants).where(tenants.c.id == DEFAULT_TENANT_ID)
    ).scalar()
    if not already:
        op.execute(
            tenants.insert().values(
                id=DEFAULT_TENANT_ID,
                slug=DEFAULT_TENANT_SLUG,
                name="Default",
                created_at=sa.func.now(),
            )
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("tenants", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tenants_slug"))
    op.drop_table("tenants")
