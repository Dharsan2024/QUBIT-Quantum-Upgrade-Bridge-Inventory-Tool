"""Migration Knowledge Base — load + query (E5, doc 08 §2).

Versioned params file: ``params/migration_kb.yaml``.
Hash recorded in migration engine-version records (reproducibility N8).
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_PARAMS_DIR = Path(__file__).parent / "params"
_KB_PATH = _PARAMS_DIR / "migration_kb.yaml"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class KBLibrary(BaseModel):
    """Library recommendation for one language."""

    name: str
    min_version: str


class KBLibraries(BaseModel):
    """Per-language library recommendations."""

    python: KBLibrary | None = None
    java: KBLibrary | None = None


class KBTarget(BaseModel):
    """PQC target specification."""

    algorithm: str
    mode: str  # "pure" | "hybrid"
    parameter_set: str | None = None
    hybrid_group: str | None = None
    category: int | None = None
    fips: str | None = None


class KBVuln(BaseModel):
    """Vulnerable algorithm identifier."""

    family: str
    usage_context: str


class KBEntry(BaseModel):
    """One KB entry: vuln → target mapping with library and guidance."""

    vuln: KBVuln
    target: KBTarget
    library: KBLibraries
    guidance: str = ""

    def matches(self, family: str, usage_context: str) -> bool:
        """Return True if this entry applies to the given family + usage context."""
        return (
            self.vuln.family.casefold() == family.casefold()
            and self.vuln.usage_context.casefold() == usage_context.casefold()
        )


class KBArtifactImpact(BaseModel):
    """What migrating TO one PQC algorithm does to sizes, storage and compatibility.

    The migration facts that are NOT visible from the flagged line. An ML-DSA-65 signature is 3309
    bytes where RSA-2048 gave 256, so the column holding it breaks even though the call site now
    looks correct. Rendered into the generator prompt so a patch addresses the whole change rather
    than the one line the scanner pointed at.
    """

    fips: str | None = None
    #: "kem" | "signature" — a KEM cannot be dropped in where a cipher was called.
    kind: str = ""
    #: Artifact name -> size in bytes, e.g. {"signature": 3309}.
    sizes: dict[str, int] = Field(default_factory=dict)
    #: Classical algorithm -> its corresponding sizes, for the before/after comparison.
    replaces: dict[str, str] = Field(default_factory=dict)
    #: Concrete consequences a correct patch has to handle.
    breaks: list[str] = Field(default_factory=list)


class MigrationKB(BaseModel):
    """Full knowledge base (versioned)."""

    version: str
    entries: list[KBEntry] = Field(default_factory=list)
    #: Target algorithm -> its wire/storage impact, keyed by the same names the entries'
    #: `target.algorithm` uses so a target resolves to its impact without a second mapping.
    artifact_impact: dict[str, KBArtifactImpact] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_migration_kb(path: Path | None = None) -> MigrationKB:
    """Load and validate the migration KB from YAML.

    Cached after first load — call ``load_migration_kb.cache_clear()`` in tests
    if you need to reload a patched file.
    """
    p = path or _KB_PATH
    raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8"))
    return MigrationKB.model_validate(raw)


def kb_file_hash(path: Path | None = None) -> str:
    """SHA-256 hex digest of the KB file — for engine-version records."""
    p = path or _KB_PATH
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


def lookup_kb(
    family: str,
    usage_context: str,
    path: Path | None = None,
) -> KBEntry | None:
    """Return the first KB entry that matches ``family`` + ``usage_context``, or None."""
    kb = load_migration_kb(path)
    for entry in kb.entries:
        if entry.matches(family, usage_context):
            return entry
    return None


def lookup_impact(algorithm: str, path: Path | None = None) -> KBArtifactImpact | None:
    """The wire/storage impact of migrating TO ``algorithm``, or None if none is recorded.

    Keyed on the TARGET algorithm, not the vulnerable one: the consequences belong to what the code
    is moving to, so every RSA-signature and every ECDSA-signature finding heading for ML-DSA-65
    inherits the same 3309-byte signature problem regardless of where it started.
    """
    if not algorithm:
        return None
    impact = load_migration_kb(path).artifact_impact
    direct = impact.get(algorithm)
    if direct is not None:
        return direct
    wanted = algorithm.casefold()
    return next((v for k, v in impact.items() if k.casefold() == wanted), None)


__all__ = [
    "KBArtifactImpact",
    "KBEntry",
    "KBLibraries",
    "KBLibrary",
    "KBTarget",
    "KBVuln",
    "MigrationKB",
    "kb_file_hash",
    "load_migration_kb",
    "lookup_impact",
    "lookup_kb",
]
