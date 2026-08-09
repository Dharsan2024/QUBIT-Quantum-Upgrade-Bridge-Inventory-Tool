from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
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


@router.get("/meta/migration-kb")
def migration_kb() -> dict[str, Any]:
    """Return the versioned migration knowledge base (E5).

    Lists every vulnerable-algorithm → PQC-target mapping with library requirements
    and guidance prose. The KB version + file hash can be cross-referenced with
    engine-version records for reproducibility.
    """
    try:
        from qubit_migrate.kb import kb_file_hash, load_migration_kb

        kb = load_migration_kb()
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"Migration KB unavailable: {exc}") from exc

    return {
        "version": kb.version,
        "file_hash_sha256": kb_file_hash(),
        "entry_count": len(kb.entries),
        "entries": [e.model_dump() for e in kb.entries],
    }


@router.get("/meta/agility-policy")
def agility_policy() -> dict[str, Any]:
    """Return the active crypto agility policy (E2).

    Shows the organisation's PQC migration stance: defaults per usage-context
    bucket and any sensitivity/context overrides. Editing the policy is a
    params-file change (git-reviewed), not a runtime mutation.
    """
    try:
        from qubit_migrate.agility import load_agility_policy, policy_file_hash

        policy = load_agility_policy()
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"Agility policy unavailable: {exc}") from exc

    return {
        "version": policy.version,
        "file_hash_sha256": policy_file_hash(),
        "defaults": {k: v.model_dump() for k, v in policy.defaults.items()},
        "overrides": [o.model_dump() for o in policy.overrides],
    }
