"""CNSA 2.0 migration-timeline policy: evaluate a scanned asset inventory against NSA's
Commercial National Security Algorithm Suite 2.0 migration milestones (2025 -> 2035).

Ported/adapted from csnp/tls-analyzer's `internal/analyzer/cnsa2.go` (MIT) — see
docs/design/07-ecosystem-factcheck.md §11. That reference documents a bug it had to fix: milestone
status and a stricter "is everything compliant" check were conflated and gave contradictory
verdicts for the same scan. This module deliberately answers only the milestone question — "is the
required algorithm class present at all" — never the stricter one; a caller wanting the stricter
pass can build it from the same asset list.

Milestones not yet due (``as_of`` before their deadline) score 100 regardless of current evidence —
CNSA 2.0 milestones are forward-looking deadlines, not retroactive requirements, matching the
reference's `not-applicable` treatment of future milestones.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from qubit_core import CryptoAsset, QuantumAttack

from .config import RiskConfig

_STATUS_SCORE = {
    "compliant": 100.0,
    "partial": 60.0,
    "in-progress": 40.0,
    "non-compliant": 0.0,
}


@dataclass(frozen=True)
class MilestoneResult:
    name: str
    deadline: date
    is_due: bool
    status: str  # compliant | partial | in-progress | non-compliant
    weight: int
    score_contribution: float  # 100 if not yet due, else derived from `status`
    evidence: str


@dataclass(frozen=True)
class CNSA2Report:
    as_of: date
    milestones: list[MilestoneResult]
    overall_score: float
    current_phase: str
    next_deadline: date | None
    days_to_next_deadline: int | None
    next_action: str


def evaluate_cnsa2(
    assets: list[CryptoAsset], cfg: RiskConfig, *, as_of: date | None = None
) -> CNSA2Report:
    """Evaluate ``assets`` (a scan's asset inventory) against the CNSA 2.0 milestone table."""
    as_of = as_of or date.today()
    policy = cfg.cnsa2_milestones

    ev = _evidence(assets, policy)

    results: list[MilestoneResult] = []
    for m in policy["milestones"]:
        deadline = date.fromisoformat(m["deadline"])
        is_due = as_of >= deadline
        status, evidence = _evaluate_one(m["name"], ev)
        score = 100.0 if (not is_due or status == "compliant") else _STATUS_SCORE[status]
        results.append(
            MilestoneResult(
                name=m["name"],
                deadline=deadline,
                is_due=is_due,
                status=status,
                weight=int(m["weight"]),
                score_contribution=score,
                evidence=evidence,
            )
        )

    total_weight = sum(m.weight for m in results) or 1
    overall = sum(m.score_contribution * m.weight for m in results) / total_weight

    upcoming = [m.deadline for m in results if not m.is_due]
    next_deadline = min(upcoming) if upcoming else None
    days = (next_deadline - as_of).days if next_deadline else None

    return CNSA2Report(
        as_of=as_of,
        milestones=results,
        overall_score=round(overall, 1),
        current_phase=_current_phase(results),
        next_deadline=next_deadline,
        days_to_next_deadline=days,
        next_action=_next_action(results),
    )


@dataclass(frozen=True)
class _Evidence:
    has_inventory: bool
    hybrid_kex_present: bool
    pure_pqc_kex_present: bool
    pqc_sig_present: bool
    aes256_present: bool
    strong_hash_present: bool
    any_shor_vulnerable: bool


def _evidence(assets: list[CryptoAsset], policy: dict[str, Any]) -> _Evidence:
    algos_present = {a.algorithm for a in assets}
    kex = policy["approved_key_exchange"]
    return _Evidence(
        has_inventory=len(assets) > 0,
        hybrid_kex_present=bool(algos_present & set(kex["hybrid"])),
        pure_pqc_kex_present=bool(algos_present & set(kex["pure"])),
        pqc_sig_present=bool(algos_present & set(policy["approved_signatures"])),
        aes256_present=bool(algos_present & set(policy["approved_symmetric"])),
        strong_hash_present=bool(algos_present & set(policy["approved_hash"])),
        any_shor_vulnerable=any(a.quantum_vulnerable.attack == QuantumAttack.shor for a in assets),
    )


def _evaluate_one(milestone_name: str, ev: _Evidence) -> tuple[str, str]:
    """Return (status, human-readable evidence) for one milestone by name."""
    if milestone_name == "Preparation Phase":
        if ev.has_inventory:
            return "compliant", "asset inventory exists"
        return "non-compliant", "no assets scanned yet"

    if milestone_name == "New NSS Systems":
        present = {
            "PQC KEM": ev.hybrid_kex_present or ev.pure_pqc_kex_present,
            "PQC signature": ev.pqc_sig_present,
            "AES-256": ev.aes256_present,
            "SHA-384/512": ev.strong_hash_present,
        }
        met = [k for k, v in present.items() if v]
        if len(met) == len(present):
            return "compliant", "ML-KEM/ML-DSA/AES-256/SHA-384+ all present"
        if met:
            return (
                "partial",
                f"present: {', '.join(met)}; missing: {', '.join(set(present) - set(met))}",
            )
        return "non-compliant", "no CNSA-2.0-approved algorithms detected"

    if milestone_name == "TLS 1.3 Required":
        if ev.hybrid_kex_present and not ev.any_shor_vulnerable:
            return "compliant", "hybrid PQC key exchange present, no Shor-vulnerable assets remain"
        if ev.hybrid_kex_present:
            return "partial", "hybrid PQC key exchange present, but Shor-vulnerable assets remain"
        return "non-compliant", "no hybrid PQC key exchange detected"

    if milestone_name == "Legacy System Update":
        if not ev.any_shor_vulnerable:
            return "compliant", "no Shor-vulnerable (classically-broken-by-quantum) assets remain"
        if ev.hybrid_kex_present or ev.pure_pqc_kex_present or ev.pqc_sig_present:
            return "in-progress", "PQC adoption underway, but Shor-vulnerable assets still present"
        return "non-compliant", "Shor-vulnerable assets present, no PQC migration evidence"

    if milestone_name == "Full PQC Transition":
        if ev.pure_pqc_kex_present and ev.pqc_sig_present and not ev.any_shor_vulnerable:
            return "compliant", "pure PQC key exchange + signatures, no classical crypto remains"
        if ev.hybrid_kex_present or ev.pqc_sig_present:
            return "partial", "PQC adoption present but still hybrid/incomplete"
        return "non-compliant", "no PQC adoption evidence"

    return "non-compliant", "unrecognized milestone"


def _current_phase(results: list[MilestoneResult]) -> str:
    for m in results:
        if not m.is_due:
            return m.name
    return results[-1].name if results else "unknown"


def _next_action(results: list[MilestoneResult]) -> str:
    for m in results:
        if m.is_due and m.status != "compliant":
            return f"{m.name} (due {m.deadline.isoformat()}): {m.evidence}"
    for m in results:
        if not m.is_due and m.status != "compliant":
            return f"{m.name} (due {m.deadline.isoformat()}, not yet due): {m.evidence}"
    return "all milestones compliant"


__all__ = ["CNSA2Report", "MilestoneResult", "evaluate_cnsa2"]
