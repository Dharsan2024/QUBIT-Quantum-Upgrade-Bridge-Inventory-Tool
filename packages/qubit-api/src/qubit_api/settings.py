from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from qubit_core.db import default_db_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QUBIT_", extra="ignore")

    db_url: str = Field(default_factory=default_db_url)
    api_token: str = "qubit-dev-token-do-not-use-in-prod"  # noqa: S105 — dev default; override via QUBIT_API_TOKEN
    api_prefix: str = "/api/v1"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8787
    create_schema_on_startup: bool = True
    # Optional: absolute path to the dashboard's built `dist/`. When set (and present), the API
    # serves the dashboard SPA at `/` so `qubit serve` is the whole app in one native process —
    # no container, so the scanner can read local paths (X:\...) and clone git repos.
    dashboard_dist: str | None = None
