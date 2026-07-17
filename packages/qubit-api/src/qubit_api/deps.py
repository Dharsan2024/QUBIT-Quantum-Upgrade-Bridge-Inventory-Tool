from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from fastapi import Request
from sqlalchemy.orm import Session

from .settings import Settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def get_session(request: Request) -> Generator[Session, None, None]:
    session_factory = request.app.state.session_factory
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
