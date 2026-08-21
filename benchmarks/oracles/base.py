"""One shape for every detector, so QUBIT is measured as one opinion among several.

The first version of this benchmark had a privileged position built into its type system: an
`OracleFinding` and a `QubitFinding`, compared by a function that knew which was which. That is fine
for "how much of the oracle's output did QUBIT reproduce" and useless for the question this
evaluation actually needs to answer, which is:

    Given N independently written detectors, how much cryptography did ALL of them miss?

That question needs every detector to be the same kind of thing, including QUBIT. So there is one
`Finding`, one `Detector` protocol, and no privileged detector. `qubit.py` is an adapter like any
other, and the estimator in `population.py` cannot tell which of its inputs is the tool under test.

Detectors disagree about names as much as about lines. `family()` folds `RSA-2048` and `RSA`
together, `ECDSA`/`ECDH`/`Ed25519` down to `EC`, `Kyber` onto `ML-KEM`, because the question is
whether a detector saw the cryptography at all, not whether two tools agree on parameters. The
folding is deliberately coarse and deliberately visible: it is the single assumption most likely to
flatter the agreement numbers, so it lives in one table a reviewer can read.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

#: Names for the same primitive, across detectors that never agreed on a vocabulary. Folding to the
#: LEFT of each pair would be wrong -- `SHA-256` and `SHA-1` are not one family for our purposes,
#: because a detector that reports the wrong one has made a real error. Only synonyms fold.
_FAMILY_ALIASES: dict[str, str] = {
    "TRIPLEDES": "3DES",
    "DES3": "3DES",
    "DESEDE": "3DES",
    "ECDSA": "EC",
    "ECDH": "EC",
    "ECDHE": "EC",
    "ECC": "EC",
    "ED25519": "EC",
    "EDDSA": "EC",
    "X25519": "EC",
    "CURVE25519": "EC",
    "SECP256R1": "EC",
    "P256": "EC",
    "SHA1": "SHA-1",
    "SHA-1": "SHA-1",
    "MLKEM": "ML-KEM",
    "MLDSA": "ML-DSA",
    "SLHDSA": "SLH-DSA",
    "KYBER": "ML-KEM",
    "DILITHIUM": "ML-DSA",
    "SPHINCS": "SLH-DSA",
    "SPHINCS+": "SLH-DSA",
    "FALCON": "FN-DSA",
    "TRIPLE": "3DES",
}

#: Suffix -> language label. Only extensions QUBIT's scanner actually reads: comparing detectors on
#: files one of them never opens measures the file filter, not the detection.
SUFFIXES: dict[str, str] = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".swift": "swift",
    ".dart": "dart",
    ".sh": "bash",
    ".ps1": "powershell",
    ".sql": "sql",
}

#: Directories no detector should descend into. `vendor` and `node_modules` are the important two:
#: a repository that vendors a crypto library would otherwise be scored on its dependencies.
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "vendor", "dist", "build", "target"})


def family(algorithm: str) -> str:
    """Coarse family label, so `RSA-2048` and `RSA` compare equal."""
    token = (algorithm or "").upper().strip()
    if not token:
        return "?"
    token = token.replace("_", "-")
    if token in _FAMILY_ALIASES:
        return _FAMILY_ALIASES[token]
    head = token.split("-")[0]
    return _FAMILY_ALIASES.get(head, head)


@dataclass(frozen=True)
class Finding:
    """One detector's claim that a specific line uses a specific kind of cryptography.

    `path` is always repository-relative and posix-separated, because the same file reached through
    a Docker bind mount, a Windows path and a `git help/` clone must compare equal or every
    cross-detector comparison silently scores zero.
    """

    detector: str
    path: str
    line: int
    algorithm: str
    rule_id: str = ""
    text: str = ""

    @property
    def family(self) -> str:
        return family(self.algorithm)

    @property
    def site(self) -> tuple[str, str]:
        """The unit of comparison: this file uses this family of cryptography.

        Deliberately not the line. Twelve QUBIT rules carry `dedupe: per-file` by design, and the
        first run of this benchmark compared line-by-line against a regex that fires on every line,
        scored 9.5%, and measured nothing but that design decision.
        """
        return (self.path, self.family)


@runtime_checkable
class Detector(Protocol):
    """What every adapter provides. Deliberately tiny: a name, and findings for a tree."""

    #: Short stable identifier used in reports and as a capture-history column.
    name: str

    #: Human-readable provenance -- upstream project, licence, pinned version or image digest.
    #: Printed with every result, because "measured against an independent detector" is only a
    #: meaningful claim if a reader can see WHICH one and check it.
    provenance: str

    def available(self) -> tuple[bool, str]:
        """Whether this detector can run here, and why not if it cannot.

        Adapters that shell out to Docker are unavailable on a machine without it, and a benchmark
        that silently reports zero findings for an absent tool would look exactly like a detector
        that found nothing -- which is the difference between "no evidence" and "evidence of none".
        """
        ...

    def scan(self, root: Path) -> list[Finding]:
        """Findings for one repository tree."""
        ...


def iter_source_files(root: Path):
    """Every file any detector is expected to consider, in a stable order."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


__all__ = [
    "SKIP_DIRS",
    "SUFFIXES",
    "Detector",
    "Finding",
    "family",
    "iter_source_files",
]
