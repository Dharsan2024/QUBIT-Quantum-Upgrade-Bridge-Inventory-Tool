"""Migration FSM — transition table, guards, and public-status projection (doc 03 §4.3, §6.5)."""

from __future__ import annotations

from typing import Literal

# All 12 internal states
MigrateState = Literal[
    "pending",
    "ready",
    "generating",
    "proposed",
    "approved",
    "applied",
    "verifying",
    "verified",
    "apply_failed",
    "failed",
    "rejected",
    "deferred",
]

# Binding 4-value public enum (CryptoAsset.migration.status)
PublicStatus = Literal["pending", "planned", "patched", "verified"]

# Map internal → public (single authority — doc 03 §4.3)
_PUBLIC: dict[str, PublicStatus] = {
    "pending": "pending",
    "ready": "planned",
    "generating": "planned",
    "proposed": "planned",
    "approved": "planned",
    "applied": "patched",
    "verifying": "patched",
    "verified": "verified",
    "apply_failed": "patched",
    "failed": "pending",
    "rejected": "pending",
    "deferred": "pending",
}

# Valid transitions: {from_state: {event: to_state}}
_TRANSITIONS: dict[str, dict[str, str]] = {
    "pending": {"prerequisites_done": "ready"},
    "ready": {"generate": "generating", "defer": "deferred"},
    "generating": {
        "validation_passed": "proposed",
        "generators_exhausted": "failed",
        "defer": "deferred",
    },
    "proposed": {
        "approve": "approved",
        "reject": "rejected",
        "defer": "deferred",
    },
    "approved": {"apply": "applied", "defer": "deferred"},
    "applied": {
        "verify_pass": "verified",
        "verify_fail": "apply_failed",
    },
    "verifying": {
        "verify_pass": "verified",
        "verify_fail": "apply_failed",
    },
    "verified": {},  # terminal (no transitions out)
    "apply_failed": {"revert": "ready", "defer": "deferred"},
    "failed": {"retry": "ready", "defer": "deferred"},
    "rejected": {"regenerate": "ready", "defer": "deferred"},
    "deferred": {"resume": "ready"},
}


class InvalidTransition(Exception):
    """Raised when an illegal state transition is attempted."""


def transition(current: str, event: str) -> str:
    """Return the next state for ``event`` from ``current``.

    Raises ``InvalidTransition`` if the transition is not allowed —
    never silently coerced (doc 03 §6.5).
    """
    allowed = _TRANSITIONS.get(current, {})
    if event not in allowed:
        raise InvalidTransition(
            f"No transition '{event}' from state '{current}'. "
            f"Allowed events: {sorted(allowed)}"
        )
    return allowed[event]


def to_public_status(state: str) -> PublicStatus:
    """Project internal FSM state → binding 4-value migration.status.

    This is the ONLY writer of CryptoAsset.migration.status (doc 03 §4.3).
    """
    result = _PUBLIC.get(state)
    if result is None:
        raise ValueError(f"Unknown state: {state!r}")
    return result


def valid_events(state: str) -> list[str]:
    """Return the list of valid event names from ``state``."""
    return sorted(_TRANSITIONS.get(state, {}).keys())


__all__ = [
    "InvalidTransition",
    "MigrateState",
    "PublicStatus",
    "to_public_status",
    "transition",
    "valid_events",
]
