from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from qubit_core.db import (
    Base,
    get_engine,
    has_alembic_history,
    session_factory,
    stamp_head,
    upgrade_to_head,
)
from sqlalchemy.exc import OperationalError

from .routers import assets_router, meta_router, projects_router, registry_router, scans_router
from .routers.jobs import router as jobs_router
from .routers.llm_provider import router as llm_provider_router
from .routers.migrate import router as migrate_router
from .routers.recommendation import router as recommendation_router
from .routers.risk import router as risk_router
from .routers.threat_intel import router as threat_intel_router
from .settings import Settings

logger = logging.getLogger(__name__)

# Poll granularity for the opt-in threat-intel background check, not the check interval itself
# (that's ThreatIntelConfig.check_interval_hours, user-set, minimum 1 hour). Waking this often
# just means "due" is noticed within 15 minutes of the configured interval elapsing.
_THREAT_INTEL_POLL_SECONDS = 900


async def _threat_intel_poll_loop(sf) -> None:
    """Runs a threat-intel check when the user has opted in and the configured interval has
    elapsed. This is the one deliberate exception to QUBIT's offline stance (see
    ``qubit_risk.threat_intel``), so a failure here — DNS down, NIST unreachable, whatever — must
    never take the app down with it; it just tries again next poll."""
    from qubit_core.db.models import ThreatIntelConfig
    from qubit_core.schemas import utcnow
    from qubit_risk.threat_intel import check_now

    while True:
        await asyncio.sleep(_THREAT_INTEL_POLL_SECONDS)
        try:
            with sf() as session:
                config = session.get(ThreatIntelConfig, 1)
                if not config or not config.enabled:
                    continue
                elapsed = (
                    None
                    if config.last_checked_at is None
                    else (utcnow() - config.last_checked_at).total_seconds()
                )
                if elapsed is not None and elapsed < config.check_interval_hours * 3600:
                    continue
                check_now(session, config)
                session.commit()
        except Exception:
            logger.exception("threat_intel: background check failed")


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

    poll_task = asyncio.create_task(_threat_intel_poll_loop(sf))

    yield

    poll_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await poll_task


#: The single inline script the API adds to the dashboard page it serves, and its CSP hash.
#:
#: Kept together and derived from one another on purpose. They are two halves of one decision, and
#: while they lived apart the policy blocked the script for the entire life of the feature:
#: `script-src 'self'` refused the API's own inline script, so `window.__QUBIT_API_BASE__` was
#: never defined and the client worked only by falling back to a default that happened to be
#: right. Measured in the running desktop app — the variable was `null` and every cold start
#: logged three CSP errors.
API_BASE_SCRIPT = b'window.__QUBIT_API_BASE__="/api/v1";'
API_BASE_SCRIPT_HASH = (
    "sha256-" + base64.b64encode(hashlib.sha256(API_BASE_SCRIPT).digest()).decode()
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="QUBIT API", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(OperationalError)
    async def _busy_database(_request: Request, exc: OperationalError) -> JSONResponse:
        """Turn "database is locked" into an honest 503 instead of a bare 500, everywhere.

        SQLite allows exactly one writer. A migration generating in the background holds the write
        lock in bursts, so ANY concurrent write — saving Settings, deleting a scan, renaming a
        project — can lose the race and exhaust `PRAGMA busy_timeout` (20s). The hot paths retry
        (`retry_write_on_lock` / `commit_with_retry`), but a retry budget can still be spent, and
        the failure then reached the user as "500 Internal Server Error" with nothing to act on.

        Measured: a queue of overlapping generations produced exactly that, and it read as the
        model failing when the database was simply busy. One handler covers every endpoint, which
        is safer than wrapping each write site individually. Anything that is NOT a lock error is
        re-raised untouched — a schema or constraint fault is a real bug and must not be dressed
        up as transient.
        """
        if "database is locked" not in str(exc).lower():
            raise exc
        logger.warning("write lock contention on %s: answering 503", _request.url.path)
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "The database is busy with another operation and this request could not get a "
                    "turn to write. Nothing was changed — try again in a moment."
                )
            },
            headers={"Retry-After": "5"},
        )

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

        # Every scoped table has a NOT NULL tenant_id, so the default team's row must exist before
        # the first request. Seeded here rather than only in the migration, because the
        # `create_all()` branch above never runs a migration body — a fresh desktop install would
        # otherwise fail its first project insert on a foreign-key violation.
        from qubit_core.db.tenants import ensure_default_tenant

        with app.state.session_factory() as session:
            ensure_default_tenant(session)

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

    # Baseline response hardening. The API serves the dashboard itself in desktop mode, so these
    # headers land on the HTML a real browser engine renders, not only on JSON.
    #
    # Measured absent against the running app: no X-Content-Type-Options, X-Frame-Options,
    # Content-Security-Policy or Referrer-Policy on any response. Cheap to add and each closes a
    # concrete class: MIME sniffing turning a scanned file's contents into script, the window being
    # framed by another origin, injected script reaching the network, and the token-bearing URL
    # leaking through Referer.
    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # `connect-src` has to allow the loopback origin the dashboard was served from, whatever
        # port the launcher managed to bind. 'self' covers it because the page and the API share an
        # origin in desktop mode. No 'unsafe-eval'; the bundle does not need it.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            # The API injects ONE inline script (see `API_BASE_SCRIPT`). `script-src 'self'`
            # blocked it -- the API's own policy refusing the API's own script -- so
            # `window.__QUBIT_API_BASE__` was never defined and the client only worked by falling
            # back to a default that happened to be right.
            #
            # A HASH rather than 'unsafe-inline': this permits exactly those bytes and nothing
            # else, so an injection anywhere else in the page is still refused. Derived from the
            # script itself, so the two cannot drift apart again.
            f"script-src 'self' '{API_BASE_SCRIPT_HASH}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self' http://127.0.0.1:* http://localhost:*; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        return response

    # Rate limiting on mutating verbs only (reads are never throttled — the dashboard polls them).
    # Added before the auth guard so an unauthenticated flood is rejected without touching the DB.
    from .ratelimit import RateLimitMiddleware

    app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)

    from fastapi import Depends

    from .auth import enforce_scope_by_method, require_operator_tenant
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
    operator_guard = [*guard, Depends(require_operator_tenant)]
    app.include_router(threat_intel_router, prefix=settings.api_prefix, dependencies=operator_guard)
    app.include_router(llm_provider_router, prefix=settings.api_prefix, dependencies=operator_guard)

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
    _MARKER = b"<script>" + API_BASE_SCRIPT + b"</script>"

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
