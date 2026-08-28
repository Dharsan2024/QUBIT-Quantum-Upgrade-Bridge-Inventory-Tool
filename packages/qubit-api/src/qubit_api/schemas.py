from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, Field
from qubit_core import CryptoAsset


def _ensure_utc(value: datetime | None) -> datetime | None:
    """Attach UTC to a naive datetime on the way out of the API.

    Every QUBIT timestamp is UTC (`utcnow()` returns tz-aware UTC), but SQLite has no timezone
    type: SQLAlchemy writes the value and reads it back NAIVE, and Pydantic then serializes it
    with no offset — `2026-08-18T19:14:21.430354`. JavaScript parses a datetime with no offset as
    LOCAL time, so on a UTC+5:30 machine the dashboard showed a scan created one minute ago as
    "6 h ago", and every relative time in the app was wrong by the viewer's UTC offset.

    Fixed here rather than in the front-end because an API that emits ambiguous timestamps is the
    actual defect — any other consumer (a SIEM, a spreadsheet) would misread them the same way.
    Fixed here rather than in the database because SQLite cannot store the offset at all, so a
    column migration would not change anything.
    """
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


UtcDateTime = Annotated[datetime, AfterValidator(_ensure_utc)]


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
    created_at: UtcDateTime
    updated_at: UtcDateTime


class ProjectScanRef(BaseModel):
    """The scan a project overview card is reporting on."""

    id: UUID
    seq: int
    status: str
    targets: list[str] = Field(default_factory=list)
    created_at: UtcDateTime
    assets: int = 0


class ProjectPlanRef(BaseModel):
    """The project's newest migration plan, if it has one."""

    id: UUID
    status: str
    tasks: int = 0
    units: int = 0
    #: Deterministic, offline codemod available — press Generate and read a one-line diff.
    with_codemod: int = 0
    #: A rule with a target and constraints, but the patch comes from a local LLM.
    with_llm_rule: int = 0
    #: No rule matches; the change is made by hand.
    manual: int = 0
    automatable: int = 0
    created_at: UtcDateTime
    scan_id: UUID | None = None
    #: True when a scan has landed since this plan was built, so the queue no longer reflects
    #: what the project currently looks like. The app says so rather than showing a stale queue
    #: as though it were current.
    stale: bool = False

    # ── Live progress ────────────────────────────────────────────────────────
    # `tasks` and the three rule-kind counts above describe what the plan was BUILT as; they never
    # move once it exists. These describe where the work has actually GOT to, which is what lets
    # the Migration Hub separate a migration still in flight from one that is done. Derived from
    # the tasks' own FSM states, so they cannot drift from the queue the operator sees.
    #: Written to disk: `applied`, `verifying` and `verified`.
    written: int = 0
    #: Written AND proven by a rescan.
    verified: int = 0
    #: Prepared and waiting to be written: a diff exists and has not been rejected.
    prepared: int = 0
    #: Not yet attempted, or attempted and still to be retried. What is left to do.
    outstanding: int = 0
    #: Resolved by a written remediation procedure rather than an edit QUBIT can make.
    guided: int = 0
    #: Nothing left to migrate — an earlier patch covered it, or it already met the PQC floor.
    satisfied: int = 0


class ProjectOverview(BaseModel):
    """One project's headline numbers, for the project-wise landing on every tab.

    Exists so the app does not have to fetch every scan and every asset just to draw a grid of
    project cards — the counts are aggregated in SQL, and a project with 872 assets costs the
    same as one with 4.
    """

    id: UUID
    name: str
    slug: str
    description: str | None = None
    created_at: UtcDateTime
    scans: int = 0
    latest_scan: ProjectScanRef | None = None
    assets: int = 0
    vulnerable: int = 0
    shor: int = 0
    grover: int = 0
    mean_risk: float | None = None
    max_risk: float | None = None
    top_algorithms: list[str] = Field(default_factory=list)
    plan: ProjectPlanRef | None = None


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


class NetworkScanCreate(BaseModel):
    """Live TLS/SSH enumeration + hybrid-PQC group probe.

    `authorized` maps to the scanner's own authorization contract, not to an API permission:
    loopback and RFC1918 targets are always allowed, and this flag is the operator asserting they
    are entitled to probe a PUBLIC host, which additionally has to appear in the scan allowlist.
    It defaults to False so the dangerous direction requires an explicit act.
    """

    targets: list[str] = Field(min_length=1, description="Hosts or IPs to probe.")
    ports: list[int] = Field(default_factory=lambda: [443])
    probe_pqc: bool = Field(
        default=True, description="Also probe the 3 standardized hybrid PQC groups."
    )
    authorized: bool = Field(
        default=False, description="Assert authorization to scan a non-RFC1918 target."
    )
    label: str | None = None
    run_risk: bool = True


class VaultScanCreate(BaseModel):
    """HashiCorp Vault transit/PKI enumeration.

    The token is used for this scan and then dropped: it is never written to the job payload, the
    scan row, or any response. See `qubit_api.jobs.secrets`.
    """

    addr: str = Field(description="Vault address, e.g. http://127.0.0.1:8200")
    token: str = Field(description="Token with read access to the transit/pki mounts.")
    mount_transit: str = "transit"
    mount_pki: str = "pki"
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
    started_at: UtcDateTime | None = None
    finished_at: UtcDateTime | None = None
    created_at: UtcDateTime


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
    finished_at: UtcDateTime | None = None
    total: int
    vulnerable: int
    median_risk: float | None = None
    negative_mosca: int


class ThreatIntelSourceOut(BaseModel):
    """One entry of the fixed, curated allowlist — not user-editable, just displayed."""

    id: str
    url: str
    label: str
    note: str


class ThreatIntelConfigOut(BaseModel):
    enabled: bool
    check_interval_hours: int
    last_checked_at: UtcDateTime | None = None
    sources: list[ThreatIntelSourceOut]


class ThreatIntelConfigPatch(BaseModel):
    """Both fields optional so a client can flip just the toggle without re-sending the interval."""

    enabled: bool | None = None
    check_interval_hours: int | None = Field(default=None, ge=1, le=24 * 30)


class ThreatIntelSnapshotOut(BaseModel):
    id: UUID
    source_id: str
    source_url: str
    fetched_at: UtcDateTime
    content_hash: str | None = None
    excerpt: str
    fetch_error: str | None = None
    changed_from_previous: bool
    reviewed: bool
    reviewed_at: UtcDateTime | None = None
    reviewer_note: str | None = None


LlmProvider = Literal["ollama", "openai-compatible"]


class LlmProviderConfigOut(BaseModel):
    """Never carries the decrypted key -- only whether one is saved, and its last 4 characters so
    a user can recognise which key is active without QUBIT ever decrypting it for a response.
    """

    provider: LlmProvider
    base_url: str | None = None
    model: str | None = None
    api_key_configured: bool
    api_key_last4: str | None = None
    #: The selected model's real context window, read from the provider. None when unknown, in
    #: which case generation falls back to `MigrateConfig.llm_context_tokens`.
    context_tokens: int | None = None
    #: The optional SECOND endpoint, tried when the primary refuses a request. Same
    #: never-the-plaintext-key rule as above.
    backup_base_url: str | None = None
    backup_model: str | None = None
    backup_api_key_configured: bool = False
    backup_api_key_last4: str | None = None
    backup_context_tokens: int | None = None
    updated_at: UtcDateTime


class LlmProviderConfigPatch(BaseModel):
    """Every field optional so a client can, e.g., change only the model without re-sending the
    key. ``api_key`` omitted means "keep the existing one"; an empty string clears it.
    """

    provider: LlmProvider | None = None
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    backup_base_url: str | None = None
    backup_model: str | None = None
    backup_api_key: str | None = None


class LlmProviderVerifyResult(BaseModel):
    ok: bool
    detail: str


class LlmEngineIn(BaseModel):
    """An engine being attached to the pool.

    The key comes in and is never returned: `LlmEngineOut` carries only its last four characters,
    which is enough for an operator to tell two keys for the same model apart and not enough to be
    a leak.
    """

    label: str = Field(min_length=1, max_length=128)
    base_url: str = Field(min_length=1, max_length=512)
    model: str = Field(min_length=1, max_length=128)
    api_key: str = Field(min_length=1)
    #: The provider's EFFECTIVE per-request allowance. On a free tier this is a rate limit well
    #: below the model's advertised context window, and using the window instead earns a 413.
    context_tokens: int | None = Field(default=None, ge=1)
    enabled: bool = True


class LlmEngineOut(BaseModel):
    """A pooled engine as reported back. Never carries the key."""

    id: UUID
    label: str
    base_url: str
    model: str
    api_key_last4: str
    context_tokens: int | None
    enabled: bool


class LlmEnginePatch(BaseModel):
    """Change one pooled engine. Omitted fields are left alone."""

    label: str | None = Field(default=None, min_length=1, max_length=128)
    context_tokens: int | None = Field(default=None, ge=1)
    #: Rest a key whose quota is spent without re-entering it tomorrow.
    enabled: bool | None = None


class LlmProviderModelsOut(BaseModel):
    """What the CONFIGURED provider actually offers right now, read live from it.

    Read live rather than shipped as a hardcoded list on purpose: free-tier model lineups rotate
    (providers add and delist models on their own schedule), so a list compiled into QUBIT would
    be wrong within months and would send a user to configure a model that no longer exists.
    """

    models: list[str]
    #: "" when the list came back fine; otherwise why it could not be read, so the UI can say
    #: "couldn't reach the provider" instead of silently showing an empty dropdown.
    error: str = ""


class ThreatIntelReviewRequest(BaseModel):
    note: str | None = None
