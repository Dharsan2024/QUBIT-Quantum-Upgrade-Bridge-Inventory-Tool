from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field
from qubit_core import CryptoAsset, SourceScanner


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


class ScanCreate(BaseModel):
    targets: list[str] = Field(min_length=1)
    scanners: list[SourceScanner] = Field(
        default_factory=lambda: [SourceScanner.code, SourceScanner.config]
    )
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


class ScanCreateResponse(BaseModel):
    scan: ScanOut
    job: None = None
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
