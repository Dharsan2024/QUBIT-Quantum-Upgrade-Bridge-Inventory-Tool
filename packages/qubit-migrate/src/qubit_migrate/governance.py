"""Governance Policy Evaluation (E4)."""

import hashlib
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from qubit_core.db import AssetRow
from sqlalchemy.orm import Session

from .state.models import MigrationTask, PatchProposal


def _load_policy() -> tuple[list[dict[str, Any]], str]:
    policy_path = Path(__file__).parent / "params" / "governance_policy.yaml"
    content = policy_path.read_bytes()
    h = hashlib.sha256(content).hexdigest()
    data = yaml.safe_load(content)
    return data.get("gates", []), h


def _get_required_approvals(asset: AssetRow, gates: list[dict[str, Any]]) -> int:
    # We map asset.sensitivity down to strings if present.
    # Currently CryptoAsset might not have a strong 'sensitivity' field out of the box,
    # but if it does, we match. If not, default fallback.
    asset_sens = getattr(asset, "sensitivity", None)
    if hasattr(asset_sens, "value"):
        asset_sens = asset_sens.value

    for gate in gates:
        match = gate.get("match", {})
        if match.get("default"):
            return gate.get("require", {}).get("approvals", 1)

        sens_list = match.get("sensitivity", [])
        if asset_sens and asset_sens in sens_list:
            return gate.get("require", {}).get("approvals", 1)

    return 1


def evaluate_gate(task: MigrationTask, session: Session) -> dict[str, Any]:
    """Evaluate if the task meets the governance policy to be applied."""
    gates, policy_hash = _load_policy()

    asset_row = session.get(AssetRow, task.asset_id)
    if not asset_row:
        return {"status": "blocked", "required": 1, "current": 0, "reason": "Asset not found"}

    required = _get_required_approvals(asset_row, gates)

    # Count approved patches for this task
    approved_patches = [p for p in task.patches if p.status == "approved"]
    
    # We can also check events if we want strict multi-approval (different actors),
    # but the PatchProposal 'status' == 'approved' implies it passed review.
    # M1 only technically stores 1 patch active at a time for apply,
    # but if multiple patches were approved, they might count. 
    # For now, count unique patches that are approved, or maybe just check if any patch is approved.
    current = len(approved_patches)

    status = "passed" if current >= required else "blocked"
    return {
        "status": status,
        "required": required,
        "current": current,
        "policy_hash": policy_hash,
    }


def check_governance(task_id: UUID, session: Session) -> None:
    """Raises ValueError if governance gate is blocked."""
    task = session.get(MigrationTask, task_id)
    if not task:
        raise ValueError("Task not found")

    gate = evaluate_gate(task, session)
    if gate["status"] == "blocked":
        req = gate["required"]
        cur = gate["current"]
        raise ValueError(
            f"Governance gate blocked: requires {req} approval(s), has {cur}."
        )
