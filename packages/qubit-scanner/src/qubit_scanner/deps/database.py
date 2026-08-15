"""Load + query the curated dependency -> algorithm map (``crypto_library_map.yaml``).

Lookup is by (ecosystem, package name) only — version-agnostic, matching how most manifest
entries carry a range rather than a pinned version (mirrors cryptodeps' own version-fallback
lookup, per docs/design/07-ecosystem-factcheck.md §11).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_DB_PATH = Path(__file__).parent / "crypto_library_map.yaml"


@lru_cache(maxsize=1)
def _load(path: Path | None = None) -> dict[str, dict[str, Any]]:
    p = path or _DB_PATH
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    index: dict[str, dict[str, Any]] = {}
    for entry in raw["packages"]:
        key = f"{entry['ecosystem']}:{entry['package'].lower()}"
        index[key] = entry
    return index


def lookup(ecosystem: str, package_name: str) -> list[dict[str, str]] | None:
    """Return the ``algorithms`` list for a (ecosystem, package) pair, or None if not curated."""
    entry = _load().get(f"{ecosystem}:{package_name.lower()}")
    return entry["algorithms"] if entry else None


__all__ = ["lookup"]
