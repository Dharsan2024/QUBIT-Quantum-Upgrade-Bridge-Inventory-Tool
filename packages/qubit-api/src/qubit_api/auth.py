"""Bearer-token authentication with DB-backed tokens + scopes (doc 05 §6.6).

Every request carries `Authorization: Bearer <raw>`. The raw token is resolved against the
`api_tokens` table (sha256-hash lookup, revocation-aware, `last_used_at` touched). Two scopes exist:
`ro` (read-only) may call read endpoints only; `rw` may also mutate.

**Bootstrap fallback (backward-compatible):** when the `api_tokens` table is EMPTY, the single
`settings.api_token` is honored as an implicit `rw` token so a fresh install (and the existing test
suite) works before any token is minted — this mirrors the design's "first start" behavior. Once any
token exists in the DB, the dev fallback is disabled and only real DB tokens authenticate.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from qubit_core.db import has_any_tokens, resolve_token
from sqlalchemy.orm import Session

from .deps import get_session, get_settings
from .settings import Settings

security = HTTPBearer()

router = APIRouter(tags=["auth"])


@dataclass(frozen=True)
class Principal:
    """The authenticated caller: a token name + its scopes."""

    name: str
    scopes: str  # "ro" | "rw"


def authenticate(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[Session, Depends(get_session)],
) -> Principal:
    """Resolve the bearer token to a Principal, or raise 401.

    DB tokens win; if the table is empty, settings.api_token is honored as an implicit rw token.
    """
    raw = creds.credentials

    if has_any_tokens(session):
        row = resolve_token(session, raw)
        if row is None:
            raise _unauthorized()
        return Principal(name=row.name, scopes=row.scopes)

    # Bootstrap: no DB tokens yet → honor the single dev token as rw.
    if secrets.compare_digest(raw, settings.api_token):
        return Principal(name="bootstrap-dev-token", scopes="rw")
    raise _unauthorized()


def verify_token(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
    """Any valid token (ro or rw). Use as a router-level dependency for read access."""
    return principal


def require_rw(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
    """Require a write-scope (rw) token; a ro token gets 403. Use on mutating routes."""
    if principal.scopes != "rw":
        raise _forbidden()
    return principal


# Methods that never mutate state — a ro token may call these; everything else needs rw.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def enforce_scope_by_method(
    request: Request,
    principal: Annotated[Principal, Depends(authenticate)],
) -> Principal:
    """App-level guard: authenticate every request, and require rw for any non-safe HTTP method.

    Registered once as a global dependency so EVERY mutating route (current or future) is covered
    without editing each route — a ro token is confined to reads, an rw token may mutate.
    """
    if request.method.upper() not in _SAFE_METHODS and principal.scopes != "rw":
        raise _forbidden()
    return principal


def _forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This operation requires a read-write (rw) token.",
    )


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/auth/whoami")
def whoami(principal: Annotated[Principal, Depends(authenticate)]) -> dict[str, str]:
    """Return the current token's name + scopes (doc 05 §5.1)."""
    return {"name": principal.name, "scopes": principal.scopes}
