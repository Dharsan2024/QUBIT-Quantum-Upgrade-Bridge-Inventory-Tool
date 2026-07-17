from __future__ import annotations

from fastapi import APIRouter
from qubit_core.algorithms import ALGORITHMS

router = APIRouter(prefix="/registry", tags=["registry"])


@router.get("/algorithms")
def list_algorithms() -> list[dict[str, object]]:
    return [
        {
            "canonical": algorithm.canonical,
            "family": algorithm.family,
            "kind": algorithm.kind,
            "attack": algorithm.attack.value,
            "vulnerable": algorithm.vulnerable,
            "key_size": algorithm.key_size,
            "oid": algorithm.oid,
            "aliases": list(algorithm.aliases),
            "classical_security_level": algorithm.classical_security_level,
            "nist_quantum_security_level": algorithm.nist_quantum_security_level,
        }
        for algorithm in ALGORITHMS
    ]
