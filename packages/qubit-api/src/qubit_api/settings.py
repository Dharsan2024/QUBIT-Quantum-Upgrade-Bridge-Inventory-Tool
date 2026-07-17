from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from qubit_core.db import default_db_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QUBIT_", extra="ignore")

    db_url: str = Field(default_factory=default_db_url)
    api_token: str = "qubit-dev-token-do-not-use-in-prod"
    api_prefix: str = "/api/v1"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8787
    create_schema_on_startup: bool = True

