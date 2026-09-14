"""Governance Policy Evaluation (E4)."""

import hashlib
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from qubit_core.db import AssetRow
from sqlalchemy.orm import Session

from .state.models import MigrationTask


def _load_policy() -> tuple[list[dict[str, Any]], str]:
    policy_path = Path(__file__).parent / "params" / "governance_policy.yaml"
    content = policy_path.read_bytes()
    h = hashlib.sha256(content).hexdigest()
    data = yaml.safe_load(content)
    return data.get("gates", []), h


def _get_required_approvals(asset: AssetRow, gates: list[dict[str, Any]]) -> int:
    # AssetRow.sensitivity is a plain str column (e.g. "phi"/"public"/"unknown"); coerce enum-likes
    # (a StrEnum's .value) defensively, but it is normally already a string.
    raw_sens: Any = getattr(asset, "sensitivity", None)
    asset_sens: str | None = raw_sens.value if hasattr(raw_sens, "value") else raw_sens

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

    # DISTINCT approvers, not a raw row count. `review_patch` takes an `actor` and now records it
    # on the patch as `approved_by`; a multi-approval gate exists specifically so ONE person
    # cannot be the whole control, and counting rows instead of people let them be exactly that:
    # approve, defer, regenerate, approve again -- two "approved" `PatchProposal` rows, one actor,
    # satisfying a 2-approval PHI/financial gate (`governance_policy.yaml`) alone.
    #
    # `None` (a patch approved before `approved_by` existed) is excluded from the set rather than
    # counted as a distinct approver of its own -- an unknown approver is not evidence of a second
    # real one, and treating it as one would make the fix a no-op for exactly the rows it exists
    # to stop trusting blindly.
    approvers = {p.approved_by for p in task.patches if p.status == "approved" and p.approved_by}
    current = len(approvers)

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
        raise ValueError(f"Governance gate blocked: requires {req} approval(s), has {cur}.")
