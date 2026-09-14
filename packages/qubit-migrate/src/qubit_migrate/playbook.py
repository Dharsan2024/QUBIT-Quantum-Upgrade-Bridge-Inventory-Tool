"""Loader for ``params/remediation_playbook.yaml`` - the verified provider and procedure facts.

Two consumers read this, and that is the point. ``transform/codemods.py`` needs the version floor
it writes into a manifest; ``transform/guidance.py`` needs the same floor to tell the user what to
install. Those were separate hand-maintained tables, which is the exact shape of the bug this
project keeps finding: a Maven artifact spelled one way in the rule and another in the floor table
made ``dep-pqc-01`` unreachable for every Maven project. One table, read twice.

Nothing here touches the network. The registry checks happened once, by hand, and the answers -
with the date and the API that produced them - are recorded in the YAML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PLAYBOOK_PATH = Path(__file__).parent / "params" / "remediation_playbook.yaml"


@dataclass(frozen=True)
class Provider:
    """A verified way to obtain post-quantum primitives in one ecosystem."""

    key: str
    package: str
    constraint: str
    provides: tuple[str, ...]
    verified_on: str
    source: str
    adoption: str
    manifests: tuple[str, ...] = ()
    latest_seen: str | None = None
    license: str | None = None
    install: str | None = None
    usage: str | None = None
    caveat: str | None = None
    note: str | None = None
    alternative: str | None = None
    standard: str | None = None

    def citation(self) -> str:
        """One line a reader can check the claim against."""
        return f"{self.adoption} (verified {self.verified_on} via {self.source})"


@dataclass(frozen=True)
class Unavailable:
    """An ecosystem with no provider QUBIT is willing to install automatically, and what to do."""

    key: str
    reason: str
    options: tuple[str, ...]
    sources: tuple[str, ...]
    verified_on: str
    manifests: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcedureStep:
    title: str
    detail: str = ""
    command: str = ""


@dataclass(frozen=True)
class Procedure:
    """A remediation that is a procedure rather than an edit - a certificate, a rotated secret."""

    key: str
    title: str
    applies_to: str
    honest_note: str
    steps: tuple[ProcedureStep, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Playbook:
    providers: dict[str, Provider]
    unavailable: dict[str, Unavailable]
    authorities: dict[str, str]
    procedures: dict[str, Procedure]

    def provider_for_manifest(self, filename: str) -> Provider | None:
        """The provider whose manifest list contains ``filename`` (basename, case-insensitive).

        Glob entries (`*.csproj`) are matched as suffixes so a real project file resolves.
        """
        from fnmatch import fnmatch

        name = Path(filename).name.lower()
        for provider in self.providers.values():
            for pattern in provider.manifests:
                if fnmatch(name, pattern.lower()):
                    return provider
        return None

    def unavailable_for_manifest(self, filename: str) -> Unavailable | None:
        from fnmatch import fnmatch

        name = Path(filename).name.lower()
        for entry in self.unavailable.values():
            for pattern in entry.manifests:
                if fnmatch(name, pattern.lower()):
                    return entry
        return None


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


@lru_cache(maxsize=4)
def _load(path: Path) -> Playbook:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    providers: dict[str, Provider] = {}
    for key, raw in (data.get("providers") or {}).items():
        providers[key] = Provider(
            key=key,
            package=str(raw["package"]),
            constraint=str(raw["constraint"]),
            provides=_as_tuple(raw.get("provides")),
            verified_on=str(raw.get("verified_on", "")),
            source=str(raw.get("source", "")),
            adoption=str(raw.get("adoption", "")),
            manifests=_as_tuple(raw.get("manifest")),
            latest_seen=raw.get("latest_seen"),
            license=raw.get("license"),
            install=raw.get("install"),
            usage=raw.get("usage"),
            caveat=raw.get("caveat"),
            note=raw.get("note"),
            alternative=raw.get("alternative"),
            standard=raw.get("standard"),
        )

    unavailable: dict[str, Unavailable] = {}
    for key, raw in (data.get("unavailable") or {}).items():
        unavailable[key] = Unavailable(
            key=key,
            reason=str(raw.get("reason", "")),
            options=_as_tuple(raw.get("options")),
            sources=_as_tuple(raw.get("sources")),
            verified_on=str(raw.get("verified_on", "")),
            manifests=_as_tuple(raw.get("manifest")),
        )

    procedures: dict[str, Procedure] = {}
    for key, raw in (data.get("procedures") or {}).items():
        procedures[key] = Procedure(
            key=key,
            title=str(raw.get("title", "")),
            applies_to=str(raw.get("applies_to", "")),
            honest_note=str(raw.get("honest_note", "")),
            steps=tuple(
                ProcedureStep(
                    title=str(s.get("title", "")),
                    detail=str(s.get("detail", "")),
                    command=str(s.get("command", "")),
                )
                for s in (raw.get("steps") or [])
            ),
        )

    return Playbook(
        providers=providers,
        unavailable=unavailable,
        authorities=dict(data.get("authorities") or {}),
        procedures=procedures,
    )


def load_playbook(path: Path | None = None) -> Playbook:
    """The parsed playbook (cached per path)."""
    return _load(path or PLAYBOOK_PATH)


load_playbook.cache_clear = _load.cache_clear  # type: ignore[attr-defined]

__all__ = [
    "PLAYBOOK_PATH",
    "Playbook",
    "Procedure",
    "ProcedureStep",
    "Provider",
    "Unavailable",
    "load_playbook",
]
