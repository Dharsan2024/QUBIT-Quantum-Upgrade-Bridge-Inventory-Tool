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


@router.get("/health/deps")
def health_deps() -> dict[str, Any]:
    """Report optional-dependency reachability so the app can prompt the user to start them.

    Docker (migration sandbox) and Ollama (LLM patch tier) are OPTIONAL — scanning + risk +
    template migration all work without them — so this never fails; it just reports up/down.
    Anonymous (no auth): the boot screen calls it before a token is set.
    """
    import shutil
    import subprocess
    import urllib.request

    def _docker_up() -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            return (
                subprocess.run(
                    ["docker", "info"],  # noqa: S607
                    capture_output=True,
                    timeout=4,
                ).returncode
                == 0
            )
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _ollama_up() -> bool:
        try:
            with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3) as r:
                return r.status == 200
        except Exception:
            return False

    return {
        "api": "ok",
        "docker": _docker_up(),
        "ollama": _ollama_up(),
    }


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
