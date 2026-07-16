"""Evidence redaction — security-critical.

QUBIT's selling point is that it never exfiltrates code. Its own evidence store and CBOM export
must therefore never contain private-key bytes, passwords, or high-entropy secrets. This module
scrubs those from any evidence snippet before it is persisted. A CI test asserts no PEM private-key
block ever survives (doc 01 §6.5, failure-mode 15).
"""

from __future__ import annotations

import math
import re

# PEM private-key blocks (RSA/EC/OPENSSH/PKCS8) — the highest-severity leak.
_PEM_PRIVATE_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r".*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)

# Long base64/hex-looking string literals (probable keys/tokens).
_B64_LITERAL_RE = re.compile(r"""(['"])([A-Za-z0-9+/=_-]{40,})\1""")

# Assignments that name a secret (password/secret/api_key/token/private_key = "…").
_SECRET_ASSIGN_RE = re.compile(
    r"""(?ix)
    \b(pass(?:wd|word)?|secret(?:_?key)?|api_?key|access_?key|token|private_?key)\b
    \s*[:=]\s*
    (['"])(?P<val>[^'"]+)\2
    """
)

REDACTED = "«REDACTED»"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact_snippet(snippet: str) -> str:
    """Return ``snippet`` with private keys, secret assignments, and high-entropy literals removed.

    Deterministic and idempotent: ``redact_snippet(redact_snippet(x)) == redact_snippet(x)``.
    """
    if not snippet:
        return snippet

    out = _PEM_PRIVATE_RE.sub(f"{REDACTED}-PRIVATE-KEY", snippet)

    def _mask_assign(m: re.Match[str]) -> str:
        return m.group(0).replace(m.group("val"), REDACTED)

    out = _SECRET_ASSIGN_RE.sub(_mask_assign, out)

    def _mask_literal(m: re.Match[str]) -> str:
        quote, val = m.group(1), m.group(2)
        # Only redact genuinely high-entropy blobs, not ordinary long identifiers/URLs.
        if _shannon_entropy(val) >= 3.5:
            return f"{quote}{REDACTED}{quote}"
        return m.group(0)

    out = _B64_LITERAL_RE.sub(_mask_literal, out)
    return out


def contains_private_key(text: str) -> bool:
    """True if ``text`` still contains a PEM private-key block (used by the CI safety test)."""
    return _PEM_PRIVATE_RE.search(text) is not None


__all__ = ["REDACTED", "contains_private_key", "redact_snippet"]
