"""HNDL exposure-surface scanner: hardcoded secrets, keys, tokens, and PII in source/config.

QUBIT's thesis is Harvest-Now-Decrypt-Later: an adversary captures encrypted data today and
decrypts it once a quantum computer breaks the crypto. So the risk isn't only *weak algorithms* —
it's everything that weak/eventually-decryptable crypto is protecting. This pass finds the sensitive
material an attacker would harvest: API keys, tokens, private keys, passwords, and PII sitting in
code. Each finding gets an "exploit under HNDL" narrative (see ``hndl_narrative``).

Detection is regex-based over the raw file text (secrets/PII don't live in the AST the way crypto
calls do). Patterns are chosen for high precision — a noisy secret scanner is worse than none.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from qubit_core import Location

from ..models import Detection

# Only scan text-like files; skip binaries/lockfiles/minified assets.
_TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".properties",
    ".txt",
    ".md",
    ".sh",
    ".xml",
    ".gradle",
    ".tf",
}
_SKIP_NAMES = {"package-lock.json", "uv.lock", "yarn.lock", "poetry.lock", "Cargo.lock"}


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str  # human name, becomes the asset "algorithm" field
    regex: re.Pattern[str]
    asset_type: str  # "secret" | "sensitive-data"
    sensitivity: str  # maps to CryptoAsset usage/sensitivity narrative
    confidence: str = "high"


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# High-precision patterns. Ordered most-specific first; a line matched by a provider-specific rule
# is not re-reported by the generic ones.
_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "SECRET-AWS-AKID",
        "AWS Access Key ID",
        _p(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-GITHUB-PAT",
        "GitHub token",
        _p(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-SLACK",
        "Slack token",
        _p(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-GOOGLE-API",
        "Google API key",
        _p(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-STRIPE",
        "Stripe secret key",
        _p(r"\bsk_(live|test)_[0-9A-Za-z]{16,}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-JWT",
        "JSON Web Token",
        _p(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "secret",
        "token",
    ),
    SecretPattern(
        "SECRET-PRIVATE-KEY",
        "Private key material",
        _p(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-HARDCODED-PW",
        "Hardcoded password/secret",
        _p(
            r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"\s]{6,}['"]"""
        ),
        "secret",
        "credentials",
        "medium",
    ),
    # PII / sensitive data
    SecretPattern(
        "PII-EMAIL",
        "PII: email address",
        _p(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "sensitive-data",
        "pii",
        "medium",
    ),
    SecretPattern(
        "PII-CREDIT-CARD",
        "PII: credit-card number",
        _p(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        "sensitive-data",
        "financial",
    ),
    SecretPattern(
        "PII-SSN",
        "PII: US Social Security Number",
        _p(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
        "sensitive-data",
        "pii",
        "medium",
    ),
]

# Lines containing these are almost always examples/placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"(?i)(example|placeholder|dummy|your[_-]?key|xxxx|<[^>]+>|changeme|todo|sample|test@|foo@bar)"
)


def hndl_narrative(asset_type: str, label: str, sensitivity: str) -> str:
    """One-line 'harvest now, decrypt later' exploit explanation for a finding."""
    if asset_type == "secret":
        return (
            f"{label} exposed in source. Under HNDL, an adversary who has harvested traffic or "
            f"backups decrypts them once a CRQC arrives — and any long-lived secret like this "
            f"that is still valid then grants direct access (credential replay), no crypto-break "
            f"needed for the secret itself. Rotate + move to a vault; never commit secrets."
        )
    return (
        f"{label} handled in code. HNDL adversaries harvest this data in transit/at rest today and "
        f"decrypt it after quantum breaks the protecting crypto; {sensitivity} data has a long "
        f"secrecy shelf-life, so it is exactly what HNDL targets. Ensure it is encrypted with "
        f"PQC-ready algorithms and minimized."
    )


class SecretScanner:
    """Regex pass over a text file, emitting secret/PII Detections with HNDL narratives."""

    def scan_file(self, path: Path, *, repo: str | None = None) -> list[Detection]:
        if path.name in _SKIP_NAMES or path.suffix.lower() not in _TEXT_SUFFIXES:
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        out: list[Detection] = []
        claimed: set[tuple[int, int]] = set()  # (line, col) already reported — most-specific wins
        for pat in _PATTERNS:
            for m in pat.regex.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                line_start = text.rfind("\n", 0, m.start()) + 1
                col = m.start() - line_start
                if (line_no, col) in claimed:
                    continue
                eol = text.find("\n", m.start())
                line_text = text[line_start : eol if eol != -1 else len(text)]
                if _PLACEHOLDER.search(line_text):
                    continue
                claimed.add((line_no, col))
                usage = pat.sensitivity if pat.sensitivity in {"token", "password"} else "unknown"
                out.append(
                    Detection(
                        scanner="code",
                        rule_id=pat.id,
                        raw_algorithm=pat.label,
                        usage_context=usage,
                        asset_type=pat.asset_type,
                        location=Location(repo=repo, file_path=str(path), line=line_no),
                        evidence_snippet=line_text.strip()[:200],
                        evidence_context={
                            "extra": {
                                "hndl_narrative": hndl_narrative(
                                    pat.asset_type, pat.label, pat.sensitivity
                                ),
                                "sensitivity": pat.sensitivity,
                            }
                        },
                        confidence=pat.confidence,
                    )
                )
        return out


__all__ = ["SecretPattern", "SecretScanner", "hndl_narrative"]
