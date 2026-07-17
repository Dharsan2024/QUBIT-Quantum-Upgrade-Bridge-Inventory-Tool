from __future__ import annotations

from fastapi import APIRouter
from qubit_core import __version__ as core_version
from qubit_scanner import __version__ as scanner_version

from qubit_api import __version__

router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "db": "ok", "version": __version__}


@router.get("/version")
def version() -> dict[str, str]:
    return {
        "qubit-api": __version__,
        "qubit-core": core_version,
        "qubit-scanner": scanner_version,
    }

