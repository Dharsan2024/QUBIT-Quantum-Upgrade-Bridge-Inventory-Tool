from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field
from qubit_core import CryptoAsset


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int = Field(default=50, le=200)
    offset: int = 0


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    root_path: str | None = None
    description: str | None = None


class ProjectPatch(BaseModel):
    root_path: str | None = None
    description: str | None = None
    settings: dict[str, object] | None = None


class ProjectOut(BaseModel):
    id: UUID
    name: str
    slug: str
    root_path: str | None = None
    description: str | None = None
    settings: dict[str, object] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class ScannerName(StrEnum):
    """Which scanners a scan should run.

    This is deliberately NOT `SourceScanner`, which the request model used to declare. That enum
    labels where an *asset* came from; this one selects which *scanners execute*, and the two
    vocabularies genuinely differ: `network` is not a filesystem scanner, key material is reported
    by the cert scanner, and the secret and dependency scanners have no provenance member of their
    own.
    Typing the request as `SourceScanner` meant the API accepted selections it could not act on
    (`network`, `key`) while being unable to name two scanners that run by default.

    Kept in lockstep with `qubit_scanner.SCANNER_NAMES` by a test, since that is the module which
    actually dispatches on these names.
    """

    code = "code"
    config = "config"
    cert = "cert"
    secret = "secret"  # noqa: S105 — a scanner name, not a credential
    dependency = "dependency"


class ScanCreate(BaseModel):
    targets: list[str] = Field(min_length=1)
    # Default to every scanner. The previous default named only code+config, but the value was
    # discarded before reaching the scanner, so every API scan silently ran the full set anyway —
    # this makes the declared default match the behaviour that was always in effect.
    scanners: list[ScannerName] = Field(default_factory=lambda: list(ScannerName))
    label: str | None = None
    run_risk: bool = True


class ScanOut(BaseModel):
    id: UUID
    project_id: UUID
    seq: int
    label: str | None = None
    status: str
    targets: list[str]
    scanners: list[str]
    stats: dict[str, object]
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class AssetBatchRequest(BaseModel):
    """Externally-discovered assets to ingest — currently the hybrid bridge's TLS probe."""

    assets: list[CryptoAsset] = Field(min_length=1)
    project: str = "bridge"
    label: str | None = None
    targets: list[str] = Field(default_factory=list)


class AssetBatchResponse(BaseModel):
    project_id: UUID
    scan_id: UUID
    ingested: int


class JobRef(BaseModel):
    """Handle for the background job executing a scan, so a client knows what to poll."""

    id: UUID
    kind: str


class ScanCreateResponse(BaseModel):
    scan: ScanOut
    # Was hardcoded to `None`, so an asynchronous API never handed back the handle to its own work:
    # a client had no way to know a job existed, let alone which one to poll. Populated whenever the
    # scan was dispatched to the job runner; `None` means the scan already ran inline and `scan` is
    # final.
    job: JobRef | None = None
    # This used to read "Synchronous scan execution is enabled in M1; JobRunner lands in M2", which
    # was simply untrue — the runner is wired up and executes scans off the request path. A client
    # that believed it would read `status: "running"` and 0 assets and conclude the scan had found
    # nothing, when the correct action is to poll.
    warning: str


class CryptoAssetOut(CryptoAsset):
    project_id: UUID
    fingerprint: str


class TrendPoint(BaseModel):
    scan_id: UUID
    seq: int
    finished_at: datetime | None = None
    total: int
    vulnerable: int
    median_risk: float | None = None
    negative_mosca: int
