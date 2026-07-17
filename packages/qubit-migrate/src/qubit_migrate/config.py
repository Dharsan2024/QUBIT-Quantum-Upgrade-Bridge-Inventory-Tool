"""MigrateConfig — pydantic-settings (doc 03 §2)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class MigrateConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QUBIT_MIGRATE_",
        env_file=".env",
        extra="ignore",
    )

    model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    fallback_model: str = "qwen2.5-coder:1.5b-instruct-q4_K_M"
    max_repair_rounds: int = 2
    min_confidence: float = 0.5
    # validation sandbox
    no_docker: bool = False  # set True to skip stages 3-4


__all__ = ["MigrateConfig"]
