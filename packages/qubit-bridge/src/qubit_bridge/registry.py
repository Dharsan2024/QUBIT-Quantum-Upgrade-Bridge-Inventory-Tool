"""Canonical TLS groups registry for qubit-bridge."""

# IANA TLS Supported Groups
HYBRID_GROUPS = {
    "X25519MLKEM768": 0x11EC,  # 4588
    "SecP256r1MLKEM768": 0x11EB,  # 4587
    "SecP384r1MLKEM1024": 0x11ED,  # 4589
}

PURE_PQC_GROUPS = {
    "MLKEM512": 0x0200,
    "MLKEM768": 0x0201,
    "MLKEM1024": 0x0202,
}

CLASSICAL_GROUPS = {
    "x25519": 0x001D,
    "secp256r1": 0x0017,
    "secp384r1": 0x0018,
    "x448": 0x001E,
}


def is_hybrid(group: str | None) -> bool:
    """Return True if the group is a PQC hybrid."""
    if not group:
        return False
    return group in HYBRID_GROUPS


def codepoint(group: str | None) -> int | None:
    """Return the IANA codepoint for the given group."""
    if not group:
        return None
    return {**HYBRID_GROUPS, **PURE_PQC_GROUPS, **CLASSICAL_GROUPS}.get(group)
