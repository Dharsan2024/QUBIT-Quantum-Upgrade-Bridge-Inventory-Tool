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

    # Rate limiting on mutating verbs only (reads are never throttled — the dashboard polls them).
    # Added before the auth guard so an unauthenticated flood is rejected without touching the DB.
    from .ratelimit import RateLimitMiddleware

    app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)

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

    from fastapi import Response
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    # Hashed asset files (JS/CSS) under /assets, served with correct content types.
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    dist_root = dist.resolve()

    # The page the API serves is told where its API is, at request time.
    #
    # Otherwise the base is baked in at BUILD time: `qubit-desktop.bat` sets VITE_API_BASE=/api/v1,
    # but only when it has to build, so a `dist/` produced by any other command keeps whatever
    # default it was compiled with — `http://127.0.0.1:8787`. That is a hard failure the moment the
    # port differs, and it does: 8787 sits inside the range Windows reserves for Hyper-V/WSL
    # (`netsh int ipv4 show excludedportrange protocol=tcp` reported 8695-8794 on the dev machine),
    # so binding it fails outright with WinError 10013 and the launcher has to move.
    #
    # Injecting it here is exact rather than heuristic: only the page actually served BY the API
    # gets the marker, so the Vite dev server and `vite preview` — where the API is on another
    # origin — are untouched and keep their own configuration. A RELATIVE base is used because
    # page and API share an origin by construction here, which makes it port-agnostic.
    _MARKER = b'<script>window.__QUBIT_API_BASE__="/api/v1";</script>'

    def _index_with_api_base() -> Response:
        html = index.read_bytes()
        if _MARKER not in html:
            # Before any other script runs, so the client reads it during module initialization.
            if b"<head>" in html:
                html = html.replace(b"<head>", b"<head>" + _MARKER, 1)
            else:
                html = _MARKER + html
        return Response(content=html, media_type="text/html")

    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa(full_path: str) -> Response:
        # Serve a real static file if it exists (favicon, etc.); otherwise the SPA shell.
        #
        # SECURITY: `full_path` is attacker-controlled and arrives URL-DECODED. The HTTP layer
        # normalizes a literal `/../`, but it does NOT normalize a percent-encoded one, so
        # `GET /%2e%2e%2fSECRET.txt` used to reach `dist / "../SECRET.txt"` and this route — which
        # is deliberately unauthenticated, because it serves the login shell — happily returned any
        # file the process could read. That was confirmed by probing a running app, and it is the
        # `qubit serve` desktop mode's default posture, so it was reachable in the shipping config.
        # Resolving the candidate and requiring it to stay under `dist` is the fix; anything outside
        # falls through to the SPA shell rather than erroring, which is also what a genuine
        # client-side route needs.
        if full_path:
            candidate = (dist_root / full_path).resolve()
            if candidate.is_file() and candidate.is_relative_to(dist_root):
                return FileResponse(str(candidate))
        return _index_with_api_base()
