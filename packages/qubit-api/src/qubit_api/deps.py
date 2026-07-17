from __future__ import annotations

from collections.abc import Generator

from fastapi import Request
from sqlalchemy.orm import Session

from .settings import Settings


def get_settings(request: Request) -> Settings:
    """Return the settings the app was created with (stored on app.state by create_app).

    Reads from app.state rather than constructing a fresh ``Settings()`` so the instance passed to
    ``create_app(settings)`` is authoritative everywhere — including auth (previously a cached fresh
    Settings() silently ignored the passed token).
    """
    settings: Settings = request.app.state.settings
    return settings


def get_session(request: Request) -> Generator[Session, None, None]:
    session_factory = request.app.state.session_factory
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
