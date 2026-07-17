"""Additive effort estimation table (doc 03 §6.2)."""

from __future__ import annotations

from dataclasses import dataclass, field

from qubit_core import CryptoAsset


@dataclass
class EffortEstimate:
    points: int  # Fibonacci: 1, 2, 3, 5, 8, 13
    hours_low: float
    hours_high: float
    drivers: list[str] = field(default_factory=list)


_FIBONACCI = [1, 2, 3, 5, 8, 13]


def _snap_to_fibonacci(n: int) -> int:
    """Round up to the nearest Fibonacci number (cap at 13)."""
    for f in _FIBONACCI:
        if n <= f:
            return f
    return _FIBONACCI[-1]


def estimate_effort(
    asset: CryptoAsset,
    *,
    fan_out: int = 0,
    rule_kind: str | None = None,
    has_tests: bool = True,
    language: str = "python",
    data_compat: str | None = None,
    cross_service: bool = False,
    library_pinned: bool = False,
    enclosing_loc: int = 0,
) -> EffortEstimate:
    """Compute effort estimate per the additive table in doc 03 §6.2."""
    drivers: list[str] = []
    total = 0

    # Base by rule kind
    if rule_kind is None:
        total += 8
        drivers.append("no rule matched (+8)")
    elif "config" in (rule_kind or ""):
        total += 1
        drivers.append("config-only rule (+1)")
    elif "sig" in (rule_kind or "") or "sign" in (rule_kind or ""):
        total += 2
        drivers.append("sig swap (+2)")
    else:
        # KEM semantic change (e.g. RSA-enc → KEM+DEM)
        total += 3
        drivers.append("KEM semantic change (+3)")

    # Modifiers
    if enclosing_loc > 50:
        total += 1
        drivers.append(f"enclosing fn >{50} LOC (+1)")
    if fan_out >= 3:
        total += 1
        drivers.append(f"fan-out {fan_out} (+1)")
    if library_pinned:
        total += 1
        drivers.append("library pinned in lockfile (+1)")
    if not has_tests:
        total += 2
        drivers.append("no test suite (+2)")
    if language == "java":
        total += 2
        drivers.append("Java toolchain (+2)")
    if cross_service:
        total += 3
        drivers.append("cross-service edge (+3)")
    if data_compat == "reencrypt_required":
        total += 3
        drivers.append("reencrypt_required (+3)")
    elif data_compat == "dual_read":
        total += 2
        drivers.append("dual_read (+2)")

    points = _snap_to_fibonacci(total)
    return EffortEstimate(
        points=points,
        hours_low=points * 0.5,
        hours_high=points * 1.5,
        drivers=drivers,
    )


__all__ = ["EffortEstimate", "estimate_effort"]
