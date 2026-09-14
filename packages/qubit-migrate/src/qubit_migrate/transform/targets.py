"""Can the target actually be built here? Asked of the installed library, not of a version table.

A migration to a primitive the environment cannot provide is worse than no migration. The patch
applies, it parses, its names look right, and then it fails to import — and every downstream gate
blames the PATCH for what is an environment problem. Measured on this installation: four patches
named `pqcrypto`, a package that does not exist in this project at all, and the `symbols` stage
caught them one gate too late, after the model time had already been spent.

**Probed, not tabulated.** The obvious implementation is a table mapping each target to the library
version that introduced it. That table is a claim about software this machine may never have run,
it goes stale silently, and a wrong entry blocks a migration that would have worked. Asking the
installed library whether it has the symbol is cheaper, always current, and cannot be wrong about
the machine it is running on.

The version is still recorded — not to make the decision, but because "ML-DSA is unavailable" is
not actionable while "cryptography 45.0.1 does not provide `mldsa.MLDSA65PrivateKey`; it appears in
49.0.0" tells the operator exactly what to do.

Probed 2026-09-02 against `cryptography` 49.0.0:

* `mldsa.MLDSA65PrivateKey` — present
* `mlkem.MLKEM768PrivateKey` — present
* `slhdsa` — **ABSENT**. BSI TR-02102 approves SLH-DSA and a rule may legitimately target it, so
  this is a live gap rather than a hypothetical: a patch generated for that target today produces
  code this environment cannot run.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
from dataclasses import dataclass
from functools import lru_cache

__all__ = [
    "TargetAvailability",
    "clear_availability_cache",
    "installed_version",
    "library_exists",
    "target_availability",
]


@dataclass(frozen=True)
class Probe:
    """Where a target's implementation lives, so its presence can be asked rather than assumed."""

    #: Distribution name, for the version in the advisory.
    distribution: str
    #: Import path of the module that should hold the primitive.
    module: str
    #: An attribute that must exist on it. Checked as well as the module, because a package can
    #: import successfully while lacking the class — a namespace package, a partial vendoring, or a
    #: version that shipped the module before the primitive.
    symbol: str


#: Keyed by the target family, matched as a prefix of the rule's target algorithm.
#:
#: Longest match wins, so `ML-DSA-65+ECDSA-P256` resolves through its PQC half rather than falling
#: off the end of the table.
_PROBES: dict[str, Probe] = {
    "ML-DSA": Probe(
        "cryptography", "cryptography.hazmat.primitives.asymmetric.mldsa", "MLDSA65PrivateKey"
    ),
    "ML-KEM": Probe(
        "cryptography", "cryptography.hazmat.primitives.asymmetric.mlkem", "MLKEM768PrivateKey"
    ),
    "SLH-DSA": Probe(
        "cryptography", "cryptography.hazmat.primitives.asymmetric.slhdsa", "SLHDSAPrivateKey"
    ),
    "AES": Probe("cryptography", "cryptography.hazmat.primitives.ciphers.aead", "AESGCM"),
    "CHACHA20": Probe(
        "cryptography", "cryptography.hazmat.primitives.ciphers.aead", "ChaCha20Poly1305"
    ),
    # Hashes come from the standard library, so they are always available. Listed rather than
    # omitted: an absent entry means "unknown", and silently treating unknown as available is the
    # assumption this module exists to remove.
    "SHA": Probe("", "hashlib", "sha384"),
    "BLAKE2": Probe("", "hashlib", "blake2b"),
}


@dataclass(frozen=True)
class TargetAvailability:
    """Whether this environment can build the target, and what to say if it cannot."""

    target: str
    available: bool
    #: Empty when available. Otherwise a sentence naming the library, the version present, and the
    #: symbol that is missing — enough for the operator to act without reading the code.
    advisory: str = ""
    distribution: str = ""
    version: str = ""
    #: True when no probe covers this target. Distinct from `available=False`: nothing was
    #: established, and blocking on it would refuse every target the table has not caught up with.
    unknown: bool = False


def installed_version(distribution: str) -> str:
    """The installed version of `distribution`, or "" if it is not installed or unnamed."""
    if not distribution:
        return ""
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return ""


def library_exists(name: str) -> bool:
    """Is `name` a real, importable top-level package on this machine?

    The check the `pqcrypto` patches needed. A model asked for a post-quantum library will happily
    name one that does not exist — `pqcrypto` and `oqs` are both plausible, neither is installed
    here — and a generator with no way to ask produces code that cannot import.

    `find_spec` rather than `import`: it answers without executing module-level code, which for an
    arbitrary model-named package is not something to do inside the generator.
    """
    if not name or not name.replace("_", "").isalnum():
        return False
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        # `find_spec` raises for a name whose PARENT is missing, and ValueError for some malformed
        # names. Both mean the same thing here.
        return False


@lru_cache(maxsize=256)
def _probe_symbol(module: str, symbol: str) -> bool:
    """Does `module` import and carry `symbol`? Cached — it cannot change inside a run."""
    try:
        loaded = importlib.import_module(module)
    except Exception:
        return False
    return hasattr(loaded, symbol)


def _probe_for(target: str) -> tuple[str, Probe] | None:
    """Longest matching prefix, so a composite resolves through its PQC half."""
    upper = (target or "").strip().upper().replace("_", "-")
    best: tuple[str, Probe] | None = None
    for prefix, probe in _PROBES.items():
        if prefix in upper and (best is None or len(prefix) > len(best[0])):
            best = (prefix, probe)
    return best


def target_availability(target: str) -> TargetAvailability:
    """Can this environment build `target`?

    `unknown` is returned for a target no probe covers, and callers must NOT treat that as
    unavailable. Blocking on an unrecognised target would refuse every new algorithm the moment a
    rule named one before this table did — turning a coverage gap into a capability loss, which is
    the same mistake as treating a skipped gate as a passed one.
    """
    found = _probe_for(target)
    if found is None:
        return TargetAvailability(
            target=target,
            available=True,
            unknown=True,
            advisory=f"no availability probe covers {target!r}; generation is not blocked",
        )

    prefix, probe = found
    version = installed_version(probe.distribution)
    if _probe_symbol(probe.module, probe.symbol):
        return TargetAvailability(
            target=target, available=True, distribution=probe.distribution, version=version
        )

    where = f"{probe.distribution} {version}" if version else (probe.distribution or "the stdlib")
    return TargetAvailability(
        target=target,
        available=False,
        distribution=probe.distribution,
        version=version,
        advisory=(
            f"{target} cannot be built here: {where} does not provide "
            f"{probe.module}.{probe.symbol}. A patch naming it would apply and then fail to "
            f"import, and every later gate would blame the patch for an environment problem. "
            f"Install a release that ships {prefix}, or choose a target this environment supports."
        ),
    )


def clear_availability_cache() -> None:
    """Forget probed symbols. For tests that simulate a different environment."""
    _probe_symbol.cache_clear()
