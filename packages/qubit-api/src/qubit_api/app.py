from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from qubit_core.db import Base, get_engine, session_factory

from .routers import assets_router, meta_router, projects_router, registry_router, scans_router
from .routers.jobs import router as jobs_router
from .routers.risk import router as risk_router
from .settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    from qubit_core.db import Job

    from .jobs.bus import EventBus
    from .jobs.runner import JobRunner

    sf = app.state.session_factory
    bus = EventBus()
    runner = JobRunner(sf, bus)
    app.state.event_bus = bus
    app.state.job_runner = runner

    # Crash recovery
    with sf() as session:
        session.query(Job).filter(Job.status.in_(["queued", "running"])).update(
            {"status": "failed", "error": "interrupted by server restart"},
            synchronize_session=False,
        )
        session.commit()

    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="QUBIT API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings  # authoritative app-wide (auth reads this, not a fresh Settings)
    engine = get_engine(settings.db_url)
    app.state.engine = engine
    app.state.session_factory = session_factory(engine)

    if settings.create_schema_on_startup:
        Base.metadata.create_all(engine)

    from fastapi import Depends

    from .auth import router as auth_router
    from .auth import verify_token

    app.include_router(meta_router, prefix=settings.api_prefix)
    app.include_router(auth_router, prefix=settings.api_prefix)
    app.include_router(
        registry_router, prefix=settings.api_prefix, dependencies=[Depends(verify_token)]
    )
    app.include_router(
        projects_router, prefix=settings.api_prefix, dependencies=[Depends(verify_token)]
    )
    app.include_router(
        scans_router, prefix=settings.api_prefix, dependencies=[Depends(verify_token)]
    )
    app.include_router(
        assets_router, prefix=settings.api_prefix, dependencies=[Depends(verify_token)]
    )
    app.include_router(
        jobs_router, prefix=settings.api_prefix, dependencies=[Depends(verify_token)]
    )
    app.include_router(
        risk_router, prefix=settings.api_prefix, dependencies=[Depends(verify_token)]
    )
    return app
