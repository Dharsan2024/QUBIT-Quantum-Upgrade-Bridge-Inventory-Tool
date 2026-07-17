"""MigrationEvent audit writer (doc 03 §4.2)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .models import MigrationEvent, MigrationTask


def write_event(
    session: Session,
    task: MigrationTask,
    *,
    from_state: str | None,
    to_state: str,
    actor: str = "system",
    detail: dict[str, Any] | None = None,
) -> MigrationEvent:
    """Append an audit event for a task state transition."""
    ev = MigrationEvent(
        task_id=task.id,
        from_state=from_state,
        to_state=to_state,
        actor=actor,
        detail_json=detail or {},
    )
    session.add(ev)
    return ev


__all__ = ["write_event"]
