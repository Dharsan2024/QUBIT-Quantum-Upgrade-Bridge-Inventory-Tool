from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter
from qubit_core.algorithms import ALGORITHMS
from qubit_scanner import RuleCatalog
from qubit_scanner.code.languages import EXT_TO_LANGUAGE, NAME_TO_LANGUAGE

router = APIRouter(prefix="/registry", tags=["registry"])


@router.get("/algorithms")
def list_algorithms() -> list[dict[str, object]]:
    return [
        {
            "canonical": algorithm.canonical,
            "family": algorithm.family,
            "kind": algorithm.kind,
            "attack": algorithm.attack.value,
            "vulnerable": algorithm.vulnerable,
            "key_size": algorithm.key_size,
            "oid": algorithm.oid,
            "aliases": list(algorithm.aliases),
            "classical_security_level": algorithm.classical_security_level,
            "nist_quantum_security_level": algorithm.nist_quantum_security_level,
        }
        for algorithm in ALGORITHMS
    ]


@router.get("/languages")
def list_languages() -> list[dict[str, object]]:
    """Which source languages the code scanner can actually read, and how many rules back each.

    Exposed because the alternative is that nobody can tell: a language with no rules parses
    cleanly, finds nothing, and reports as a scanned file — the same output as a file with no
    cryptography in it. Showing the rule count next to the language makes an empty pack visible
    instead of silent.

    `rules` counts DISTINCT rules. A pack that also compiles against a sibling grammar (the
    TypeScript pack covers TSX; the C pack covers C++) contributes one rule to each grammar it
    serves, which is the honest per-language number.
    """
    catalog = RuleCatalog.load()

    extensions: dict[str, list[str]] = defaultdict(list)
    for extension, language in EXT_TO_LANGUAGE.items():
        extensions[language].append(extension)
    for name, language in NAME_TO_LANGUAGE.items():
        extensions[language].append(name)

    out: list[dict[str, object]] = []
    for language in sorted(catalog.languages()):
        compiled = catalog.for_language(language)
        out.append(
            {
                "language": language,
                "rules": len({c.rule.id for c in compiled}),
                "libraries": sorted({c.library_name for c in compiled}),
                "extensions": sorted(extensions.get(language, [])),
            }
        )
    return out
