"""E1 — Per-asset algorithm recommendation endpoint (doc 08 §2, E1).

GET /assets/{aid}/recommendation
  Returns an AssetRecommendation: target algorithm, library requirement, rationale,
  and provenance (rule | kb | agility-policy).

Resolution priority:
  1. migration rule match (qubit_migrate.transform.rules.match_rule)
  2. KB lookup by algorithm family + usage_context
  3. agility-policy resolve_target()
  4. No recommendation if asset is not quantum-vulnerable
"""
from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from qubit_core import row_to_asset
from sqlalchemy.orm import Session

from ..deps import get_session
from ..services import require_asset

router = APIRouter(tags=["recommendation"])


class AssetRecommendation(BaseModel):
    """Read model: per-asset PQC recommendation (E1, doc 08 §2)."""

    asset_id: UUID
    current: dict[str, Any]
    target: dict[str, Any]
    library: dict[str, Any]
    rationale: str
    source: str  # "rule" | "kb" | "agility-policy"
    confidence: float


def _family_from_algorithm(algorithm: str) -> str:
    """Extract the algorithm family from a canonical name like 'RSA-2048' → 'RSA'."""
    return algorithm.split("-")[0].upper() if algorithm else "UNKNOWN"


@router.get("/assets/{asset_id}/recommendation", response_model=AssetRecommendation)
def get_asset_recommendation(
    asset_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> AssetRecommendation:
    """Return the PQC migration recommendation for a single cryptographic asset (E1).

    The recommendation is assembled from (in priority order):
    1. A matching migration rule (`source="rule"`).
    2. The migration knowledge base (`source="kb"`).
    3. The agility policy defaults/overrides (`source="agility-policy"`).

    Returns 404 if the asset is not found or not quantum-vulnerable (no action needed).
    """
    row = require_asset(session, asset_id)
    asset = row_to_asset(row)

    # Not vulnerable → no recommendation needed
    if not asset.quantum_vulnerable.vulnerable:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset is not quantum-vulnerable; no recommendation applies.",
        )

    current = {
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "usage_context": asset.usage_context.value,
        "quantum_vulnerable": asset.quantum_vulnerable.vulnerable,
        "attack": asset.quantum_vulnerable.attack.value,
    }
    family = _family_from_algorithm(asset.algorithm)
    uc = asset.usage_context.value

    # --- 1. Try migration rule ---
    try:
        from qubit_migrate.transform.rules import load_rules, match_rule

        rule = match_rule(asset, load_rules())
        if rule is not None:
            tgt = rule.target
            lib: dict = tgt.get("library") or {}
            lib_name = lib.get("name", "") if isinstance(lib, dict) else str(lib)
            lib_ver = lib.get("min_version", "") if isinstance(lib, dict) else ""
            pqc = tgt.get("pqc_target") or tgt.get("algorithm", "")
            mode = "hybrid" if "hybrid" in pqc.lower() else "pure"
            return AssetRecommendation(
                asset_id=asset.id,
                current=current,
                target={"algorithm": pqc, "mode": mode, "parameter_set": pqc},
                library={"name": lib_name, "min_version": lib_ver},
                rationale=rule.semantic_note or f"Apply {rule.title}",
                source="rule",
                confidence=(
                    asset.confidence.value  # type: ignore[attr-defined]
                    if hasattr(asset.confidence, "value")
                    else 1.0
                ),
            )
    except Exception:  # pragma: no cover  # noqa: S110
        pass  # fall through to KB

    # --- 2. Try migration KB ---
    try:
        from qubit_migrate.kb import lookup_kb

        kb_entry = lookup_kb(family, uc)
        if kb_entry is not None:
            py_lib = kb_entry.library.python
            return AssetRecommendation(
                asset_id=asset.id,
                current=current,
                target=kb_entry.target.model_dump(),
                library={
                    "name": py_lib.name if py_lib else "",
                    "min_version": py_lib.min_version if py_lib else "",
                },
                rationale=kb_entry.guidance,
                source="kb",
                confidence=0.9,
            )
    except Exception:  # pragma: no cover  # noqa: S110
        pass  # fall through to agility policy

    # --- 3. Agility policy fallback ---
    try:
        from qubit_migrate.agility import resolve_target

        policy_target = resolve_target(asset)
        if policy_target is not None:
            return AssetRecommendation(
                asset_id=asset.id,
                current=current,
                target=policy_target.model_dump(),
                library={},
                rationale=policy_target.rationale or "Derived from crypto agility policy defaults.",
                source="agility-policy",
                confidence=0.7,
            )
    except Exception:  # pragma: no cover  # noqa: S110
        pass

    # No recommendation possible
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No recommendation available for algorithm '{asset.algorithm}' in context '{uc}'.",
    )


__all__ = ["AssetRecommendation", "router"]
