"""add_tenant_id_to_scoped_tables

Revision ID: d4b7c25e8f19
Revises: c9e5a71b3d84
Create Date: 2026-08-27 00:20:00.000000

Every table holding a team's data gains a NOT NULL `tenant_id`, and every existing row is assigned
to the default tenant.

**This backfill is a deliberate departure from the rest of this chain**, which has always argued
that NULL means "genuinely unknown, and inventing a value would be a fabrication" (see
a4c9f2e6b813, d5b2f39c71ae, a1c7e4b90f21). The reasoning does not carry over here. A row with no
tenant is not honestly-unknown data — it is data no token can ever reach again, because every query
filters by tenant. And there is nothing ambiguous to preserve: an install that has only ever had one
operator token has only ever had one team, so "which team does this project belong to" has exactly
one answer. Leaving it NULL would destroy access to real data in order to avoid stating something
already true.

Three steps per table (add nullable, backfill, enforce NOT NULL + FK), driven through Alembic's
batch mode. Batch mode is used deliberately and was verified first: 29c500adeb13's docstring records
that batch mode's `copy_from` route silently dropped an `ondelete` clause, so before relying on it
here the reflection-based route (no `copy_from`) was tested on a scratch database with the exact
shape of `scans` — `project_id`'s ON DELETE CASCADE, the named `uq_scans_project_seq` constraint,
the rows and the existing indexes all survived the rebuild intact. The defect is specific to
`copy_from`; plain reflection is sound.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from qubit_core.db.models import DEFAULT_TENANT_ID

# revision identifiers, used by Alembic.
revision: str = "d4b7c25e8f19"
down_revision: str | Sequence[str] | None = "c9e5a71b3d84"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Tables whose rows belong to exactly one team.
#:
#: `risk_runs` and the `migration_units`/`migration_tasks`/`migration_patches`/`migration_events`/
#: `migration_dependency_edges` chain are deliberately absent: each is reachable in one join from a
#: table listed here (`scans`, `migration_plans`), which is the same one-hop boundary the codebase
#: already uses for project scoping. `threat_intel_config`/`threat_intel_snapshots` are absent
#: because they are genuinely install-wide — a cache of public NIST reference pages, not team data.
_TABLES = (
    "api_tokens",
    "scans",
    "assets",
    "jobs",
    "migration_plans",
    "learned_patches",
    "learned_outcomes",
)


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    for table in _TABLES:
        inspector = sa.inspect(bind)
        if not inspector.has_table(table):
            continue
        if "tenant_id" in {col["name"] for col in inspector.get_columns(table)}:
            continue  # already present via Base.metadata.create_all()

        op.add_column(table, sa.Column("tenant_id", sa.Uuid(), nullable=True))

        target = sa.table(table, sa.column("tenant_id", sa.Uuid()))
        op.execute(target.update().values(tenant_id=DEFAULT_TENANT_ID))

        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column("tenant_id", existing_type=sa.Uuid(), nullable=False)
            batch_op.create_foreign_key(
                f"fk_{table}_tenant_id", "tenants", ["tenant_id"], ["id"], ondelete="CASCADE"
            )
            batch_op.create_index(batch_op.f(f"ix_{table}_tenant_id"), ["tenant_id"])

    # The learning stores key on the tenant too: the same rule and line in two teams are two
    # separate lessons, and sharing one row between them would serve one team's source code to
    # the other as prompt grounding.
    inspector = sa.inspect(bind)
    if inspector.has_table("learned_patches"):
        names = {c["name"] for c in inspector.get_unique_constraints("learned_patches")}
        if "uq_learned_patch_key" in names:
            with op.batch_alter_table("learned_patches", schema=None) as batch_op:
                batch_op.drop_constraint("uq_learned_patch_key", type_="unique")
                batch_op.create_unique_constraint(
                    "uq_learned_patch_key", ["tenant_id", "rule_id", "snippet_key"]
                )


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("learned_patches"):
        with op.batch_alter_table("learned_patches", schema=None) as batch_op:
            batch_op.drop_constraint("uq_learned_patch_key", type_="unique")
            batch_op.create_unique_constraint("uq_learned_patch_key", ["rule_id", "snippet_key"])

    for table in reversed(_TABLES):
        inspector = sa.inspect(op.get_bind())
        if not inspector.has_table(table):
            continue
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(batch_op.f(f"ix_{table}_tenant_id"))
            batch_op.drop_constraint(f"fk_{table}_tenant_id", type_="foreignkey")
            batch_op.drop_column("tenant_id")
