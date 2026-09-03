"""add_regime_to_plan_and_patch

Revision ID: f3b91d5e08a7
Revises: e8a2b47c19f3
Create Date: 2026-09-02 00:00:00.000000

Which regulatory regime a plan was built under, and which one each patch was generated against.

Without this the targets in a stored plan are unexplainable after the fact. The regimes genuinely
disagree, and the disagreement is not the one usually described:

* BSI TR-02102 REQUIRES hybrid key exchange during the transition.
* ANSSI requires it too, but raises a standalone PQC KEM as an ADVISORY rather than a failure.
* CNSA 2.0 does NOT forbid hybrid. It forbids a hybrid whose ML-KEM component is below the 1024
  grade -- so `X25519MLKEM768`, the industry default that browsers actually ship, fails CNSA 2.0
  on the 768, not on the hybrid.

So `ML-KEM-1024` and `X25519MLKEM768` are each correct and each wrong, depending on jurisdiction.
A reviewer reading a stored plan cannot tell a deliberate choice from a mistake unless the plan
records which regulator it was answering.

Denormalised onto the patch as well as the plan, deliberately. A plan's regime can be changed and
its patches regenerated; a patch carrying only a foreign key would then claim to have been built
under a policy it never saw. An evidence record has to describe the run that produced it, not the
current state of its parent.

Nullable with no default, and NULL means "no regime configured" -- the shipped default. That is a
different claim from "the default regime was chosen", and writing `nist-civil` into rows for an
install that never chose it would fabricate a decision nobody made.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3b91d5e08a7"
down_revision: str | Sequence[str] | None = "e8a2b47c19f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("migration_plans", "migration_patches")


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    for table in _TABLES:
        columns = {c["name"] for c in inspector.get_columns(table)}
        if "regime" not in columns:
            op.add_column(table, sa.Column("regime", sa.String(length=32), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    for table in _TABLES:
        columns = {c["name"] for c in inspector.get_columns(table)}
        if "regime" in columns:
            with op.batch_alter_table(table) as batch:
                batch.drop_column("regime")
