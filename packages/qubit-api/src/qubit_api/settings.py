from __future__ import annotations

import os
from pathlib import Path

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

    # Server-level confinement for scan targets, as an os.pathsep-separated list of directories.
    #
    # Empty (the default) means unconfined, which is correct for the DESKTOP app: pointing it at any
    # local path is the entire point of running the scanner natively. But an API reachable by anyone
    # other than its operator must be confinable, because a scan target is otherwise any path the
    # process can read — `POST /projects/{id}/scans` with `/etc` or `C:\Users` would happily
    # inventory
    # it. Setting this makes every target, in every project, resolve inside one of these roots or be
    # refused. Deployments should set it; a project's own `root_path` narrows further, it does not
    # replace this.
    scan_roots: str = ""

    # Requests per minute per client IP, applied to mutating verbs only (see RateLimitMiddleware).
    # Reads are left alone so a dashboard polling `/scans` is never throttled. 0 disables the limit.
    rate_limit_per_minute: int = 120

    def scan_root_paths(self) -> list[Path]:
        """`scan_roots` parsed into resolved directories. Empty list means unconfined."""
        if not self.scan_roots.strip():
            return []
        return [
            Path(part).expanduser().resolve()
            for part in self.scan_roots.split(os.pathsep)
            if part.strip()
        ]
