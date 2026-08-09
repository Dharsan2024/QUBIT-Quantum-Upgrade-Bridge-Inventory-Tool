"""API-token lifecycle helpers (doc 05 §6.6).

The raw token is generated with ``secrets.token_urlsafe`` and returned to the caller once; only its
sha256 hex is persisted in ``api_tokens.token_hash``. Lookup is by hash, so the stored value is
never reversible. These helpers are shared by the CLI (``qubit serve token …``) and the API auth
dependency so there is one implementation of hashing + scope semantics.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..schemas import utcnow
from .models import ApiToken

VALID_SCOPES = ("ro", "rw")


def hash_token(raw: str) -> str:
    """Return the sha256 hex of a raw token (the value stored + looked up)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CreatedToken:
    """A freshly minted token. ``raw`` is shown to the user ONCE and never stored."""

    name: str
    scopes: str
    raw: str


def create_token(session: Session, name: str, scopes: str = "rw") -> CreatedToken:
    """Mint a new token, persist its hash, and return the raw value once.

    Raises ``ValueError`` on an invalid scope or a duplicate name.
    """
    if scopes not in VALID_SCOPES:
        raise ValueError(f"scope must be one of {VALID_SCOPES}, got {scopes!r}")
    existing = session.scalar(select(ApiToken).where(ApiToken.name == name))
    if existing is not None:
        raise ValueError(f"a token named {name!r} already exists")
    raw = secrets.token_urlsafe(32)
    row = ApiToken(name=name, token_hash=hash_token(raw), scopes=scopes)
    session.add(row)
    session.commit()
    return CreatedToken(name=name, scopes=scopes, raw=raw)


def list_tokens(session: Session) -> list[ApiToken]:
    """Return all tokens (including revoked), newest first."""
    return list(session.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())).all())


def revoke_token(session: Session, name: str) -> bool:
    """Revoke a token by name. True if a live token was revoked; False if none/already revoked."""
    row = session.scalar(select(ApiToken).where(ApiToken.name == name))
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    session.commit()
    return True


def resolve_token(session: Session, raw: str) -> ApiToken | None:
    """Look up a live (non-revoked) token by its raw value; touch ``last_used_at`` (throttled).

    Returns the matching ``ApiToken`` row or ``None`` if unknown/revoked.
    """
    row = session.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
    if row is None or row.revoked_at is not None:
        return None
    # Throttle last_used writes to at most ~1/min to avoid a write per request. SQLite reads
    # DateTime back tz-naive, so normalize a naive value to UTC before subtracting from the
    # tz-aware utcnow() (else "can't subtract offset-naive and offset-aware datetimes").
    now = utcnow()
    last = row.last_used_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    if last is None or (now - last).total_seconds() > 60:
        row.last_used_at = now
        session.commit()
    return row


def has_any_tokens(session: Session) -> bool:
    """True if at least one token row exists (used to decide dev-token bootstrap fallback)."""
    return session.scalar(select(ApiToken.id).limit(1)) is not None


__all__ = [
    "VALID_SCOPES",
    "CreatedToken",
    "create_token",
    "has_any_tokens",
    "hash_token",
    "list_tokens",
    "resolve_token",
    "revoke_token",
]
