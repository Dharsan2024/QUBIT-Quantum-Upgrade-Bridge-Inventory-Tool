"""Password-context heuristic, kept free of libcst so it can be imported cheaply."""

from __future__ import annotations

import re

from qubit_core import CryptoAsset


def is_password_context(source: str, asset: CryptoAsset) -> bool:
    """Heuristic: is this a password-hashing context?"""
    password_indicators = re.compile(
        r"\b(password|passwd|pw\b|hash_?password|store_?pass|check_?pass"
        r"|verify_?pass|auth|credential|login)\b",
        re.IGNORECASE,
    )
    if password_indicators.search(source):
        return True
    return bool(asset.usage_context and "password" in asset.usage_context.value.lower())
