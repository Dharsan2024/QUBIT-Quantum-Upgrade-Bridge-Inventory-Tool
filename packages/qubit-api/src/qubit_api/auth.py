from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .deps import get_settings
from .settings import Settings

security = HTTPBearer()

router = APIRouter(tags=["auth"])


def verify_token(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Verify the bearer token matches the single hardcoded API token.

    Returns the token scopes ("rw" for the single hardcoded token).
    """
    if not secrets.compare_digest(creds.credentials, settings.api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "rw"


@router.get("/auth/whoami")
def whoami(scopes: Annotated[str, Depends(verify_token)]) -> dict[str, str]:
    """Return the current token's scopes (doc 05 §5.1)."""
    return {"name": "hardcoded-dev-token", "scopes": scopes}
