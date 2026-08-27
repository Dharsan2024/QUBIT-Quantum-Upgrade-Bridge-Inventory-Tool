"""The default tenant: created on demand, identical on every install.

QUBIT is single-team until someone deliberately makes it otherwise. That install still needs one
real `tenants` row to hang its data off, and it has to exist before the first request — every
project, scan and token carries a NOT NULL `tenant_id` with SQLite foreign keys enforced
(`session.py` sets ``PRAGMA foreign_keys=ON``), so a missing row is a hard insert failure, not a
silent NULL.

Two entry points can create the schema without ever running an Alembic migration body — the API's
``Base.metadata.create_all()`` path for fresh installs, and the CLI's token commands, which build
their own engine directly — so seeding cannot live in the migration alone.
"""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import DEFAULT_TENANT_ID, DEFAULT_TENANT_SLUG, Tenant


def ensure_default_tenant(session: Session) -> Tenant:
    """Return the default tenant, creating it if this install has never had one.

    Idempotent and safe to call on every startup. The `IntegrityError` path covers two processes
    racing the same fresh database — the desktop launcher starts the API while the CLI may already
    be minting a token — where both see "no row" and both insert.
    """
    existing = session.get(Tenant, DEFAULT_TENANT_ID)
    if existing is not None:
        return existing

    tenant = Tenant(id=DEFAULT_TENANT_ID, slug=DEFAULT_TENANT_SLUG, name="Default")
    session.add(tenant)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raced = session.get(Tenant, DEFAULT_TENANT_ID)
        if raced is None:
            raise
        return raced
    return tenant


__all__ = ["ensure_default_tenant"]
