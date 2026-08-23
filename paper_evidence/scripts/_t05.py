"""T05 helper: how a language can name a post-quantum algorithm, if it can at all.

Split out because the honest answer has three states rather than two. A pack like `kotlin/jca.yaml`
holds no literal `ML-DSA` string anywhere, yet `Signature.getInstance("ML-DSA-65")` resolves
correctly, because the rule reads the algorithm out of the call. Scoring that language "no PQC
rules" would be wrong in the direction that understates coverage; scoring it the same as a pack
with explicit ML-KEM rules would overstate it.
"""

from __future__ import annotations

import re

from qubit_core.algorithms import resolve

#: `kind` values in the canonical registry that mean post-quantum.
PQC_KINDS = ("pqc-kem", "pqc-signature", "pqc-hybrid")

#: Resolvers whose whole vocabulary is post-quantum: liboqs constants, noble-pqc names, the Go
#: `crypto/mlkem` helpers, pyca's PQC classes. A rule using one of these cannot report a classical
#: algorithm, so it is an explicit PQC rule even with no PQC string written anywhere in the file.
PQC_RESOLVERS = frozenset(
    {
        "liboqs-alg-const",
        "noble-pqc-name",
        "pqc-identifier",
        "go-mlkem-fn",
        "pyca-pqc-class",
    }
)


def is_pqc(name: str | None) -> bool:
    if not name:
        return False
    record = resolve(name)
    return bool(record and (record.kind in PQC_KINDS or "pqc" in record.kind))


def _regex_alternatives(pattern: str) -> list[str]:
    """The literal names a constraint regex admits, for the anchored-alternation shape the rule
    packs use: `^(MlKem512|MlKem768|Kyber768)$`. Anything more complex returns nothing rather than
    a guess."""
    match = re.fullmatch(r"\^\(([^()]+)\)\$", pattern.strip())
    if not match:
        return []
    return [part for part in match.group(1).split("|") if re.fullmatch(r"[\w-]+", part)]


def _constrained_to_pqc(rule) -> bool:
    """Does a `where` clause pin a capture to post-quantum names only?

    `SWIFT-CRYPTOKIT-MLKEM` carries no literal: it reads the algorithm from the captured class and
    restricts that capture to `[MLKEM768, MLKEM1024]`. Rust and C do the same thing with a regex
    (`^(MlKem768|Kyber768|...)$`). Both are every bit as explicit as a literal rule, and counting
    them merely `dynamic` understated PQC coverage for Swift, Rust, C and Go.
    """
    for clause in rule.match.where:
        values = list(getattr(clause, "in_", None) or [])
        if getattr(clause, "equals", None):
            values.append(clause.equals)
        if pattern := getattr(clause, "regex", None):
            values += _regex_alternatives(pattern)
        if values and all(is_pqc(v) for v in values):
            return True
    return False


def classify_rule(rule) -> str:
    """`literal`, `dynamic` or `classical-only`, for one rule."""
    extractor = rule.extract.get("algorithm")
    if extractor is None:
        return "classical-only"
    if (
        is_pqc(getattr(extractor, "literal", None))
        or getattr(extractor, "resolve", None) in PQC_RESOLVERS
        or _constrained_to_pqc(rule)
    ):
        return "literal"
    if getattr(extractor, "from_", None):
        # The algorithm is read out of the source, so whatever the code names is what is reported.
        return "dynamic"
    return "classical-only"
