from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from qubit_core.db import (
    Base,
    get_engine,
    has_alembic_history,
    session_factory,
    stamp_head,
    upgrade_to_head,
)

from .routers import assets_router, meta_router, projects_router, registry_router, scans_router
from .routers.jobs import router as jobs_router
from .routers.migrate import router as migrate_router
from .routers.recommendation import router as recommendation_router
from .routers.risk import router as risk_router
from .settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .jobs.bus import EventBus
    from .jobs.runner import JobRunner

    sf = app.state.session_factory
    bus = EventBus()
    runner = JobRunner(sf, bus)
    app.state.event_bus = bus
    app.state.job_runner = runner

    # Crash recovery: nothing may stay stuck in queued/running after a kill -9 (M2 acceptance).
    runner.recover_orphaned()

    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="QUBIT API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings  # authoritative app-wide (auth reads this, not a fresh Settings)
    engine = get_engine(settings.db_url)
    app.state.engine = engine
    app.state.session_factory = session_factory(engine)

    if settings.create_schema_on_startup:
        # create_all() only creates missing tables — it can never retroactively fix a constraint
        # on a table that already exists (e.g. an ON DELETE clause corrected in a later model
        # change). A database that already has Alembic history needs the actual migrations
        # applied to receive fixes like that; a brand-new one gets today's schema for free from
        # create_all() and just needs to be stamped so future migrations know where to start.
        if has_alembic_history(engine):
            upgrade_to_head(settings.db_url)
        else:
            Base.metadata.create_all(engine)
            stamp_head(settings.db_url)

    # CORS: the desktop app's WebView loads the dashboard from tauri://localhost (or
    # http://tauri.localhost on Windows WebView2), which is a DIFFERENT origin from the API on
    # 127.0.0.1:8787. Without these headers the browser blocks every request and the window shows
    # "Failed to fetch" even though the API is healthy. Allow the tauri + localhost dev origins.
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^(tauri://localhost|https?://tauri\.localhost|http://(localhost|127\.0\.0\.1)(:\d+)?)$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from fastapi import Depends

    from .auth import enforce_scope_by_method
    from .auth import router as auth_router

    # One guard on every data router: authenticates the bearer token AND enforces scope-by-method
    # (a `ro` token may only read; any mutating verb needs `rw`). Covers current + future routes.
    guard = [Depends(enforce_scope_by_method)]

    app.include_router(meta_router, prefix=settings.api_prefix)
    app.include_router(auth_router, prefix=settings.api_prefix)
    app.include_router(registry_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(projects_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(scans_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(assets_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(jobs_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(risk_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(migrate_router, prefix=settings.api_prefix, dependencies=guard)
    app.include_router(recommendation_router, prefix=settings.api_prefix, dependencies=guard)

    _mount_dashboard(app, settings)
    return app


def _mount_dashboard(app: FastAPI, settings: Settings) -> None:
    """Serve the dashboard SPA at `/` when a built dist is configured + present (native app mode).

    Mounted last so it never shadows `/api/*`. An SPA fallback returns index.html for any
    non-API path so client-side routes (e.g. /inventory) work on refresh.
    """
    from pathlib import Path

    if not settings.dashboard_dist:
        return
    dist = Path(settings.dashboard_dist)
    index = dist / "index.html"
    if not index.is_file():
        return

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    # Hashed asset files (JS/CSS) under /assets, served with correct content types.
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa(full_path: str) -> FileResponse:
        # Serve a real static file if it exists (favicon, etc.); otherwise the SPA shell.
        candidate = dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(index))
