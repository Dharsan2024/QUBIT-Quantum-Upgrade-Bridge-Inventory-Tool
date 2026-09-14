"""Every language the migrator can rewrite must ship an example of what the rewrite looks like.

`qubit_migrate.transform.target_shapes` asks the scanner "what ML-KEM code do you recognise in this
language?" and answers from each rule's **example** block, not from its query. The generator is then
told to write that shape, and the rescan checks for it — so the generator and the checker are given
their instructions by the same authority and cannot drift apart.

The failure mode this pins is quiet and one-directional. Kotlin's and Scala's JCA queries already
matched `KeyPairGenerator.getInstance("ML-KEM-768")` — a probe confirmed the scanner resolved it
correctly in both languages — but no rule carried it as an example. So `verified_target_shapes`
returned an empty tuple, which means *"no rewrite in this language can be confirmed"*, and the
migrator gave up on migrations that would in fact have passed. Detection was fine; the advice was
missing, and nothing in the suite could tell the difference.

These tests are about the *examples*, deliberately. `test_rule_examples.py` already proves every
example is detected, so an example asserted here is an example the migrator can safely quote.
"""

from __future__ import annotations

import pytest
from qubit_scanner import CodeScanner, RuleCatalog
from qubit_scanner.normalize import normalize

_CATALOG = RuleCatalog.load()
_SCANNER = CodeScanner(_CATALOG)

#: Languages a PQC rewrite is claimed for and whose target API is settled enough to show. The JVM
#: three reach ML-KEM/ML-DSA through one provider interface, so their shapes are the same call.
#: Swift joined them once `SWIFT-CRYPTOKIT-MLKEM`/`-MLDSA` existed: before that it had rules for
#: MD5, SHA-1, RC4 and TLS versions and none for the replacement, so a migrated Swift file
#: inventoried as containing no post-quantum cryptography at all.
_JVM = ["java", "kotlin", "scala"]

#: Every language a PQC rewrite is claimed for. Swift reaches ML-KEM/ML-DSA through CryptoKit's own
#: types rather than a provider lookup, so it belongs in the coverage guarantee but not in the
#: JVM-shaped assertion below.
#:
#: Go was missing from this list, which is the only reason the gap it guards against survived: the
#: scanner detected `crypto/mlkem` but nothing at all for ML-DSA, because ML-DSA is not in the Go
#: standard library and the CIRCL package `code-signature-01` tells the model to use had no rule.
#: The cost was not under-counting — stage-5 asserts `present: ML-DSA`, so EVERY Go signature
#: migration was unwinnable by construction: a correct CIRCL rewrite inventoried as containing no
#: post-quantum cryptography and the gate rejected it after three attempts. Measured on
#: go-ethereum: 0 of 107 findings could pass, with 4 recorded failures naming this exact cause.
_PQC_LANGUAGES = [*_JVM, "swift", "go"]


def _examples_yielding(language: str, prefix: str) -> list[str]:
    """Every positive example in `language` that the scanner reads as `prefix`-something.

    Matched on the **canonical** algorithm, and scanned with `collapse=False`, because those are
    what `qubit rules examples --algorithm-prefix` does and this test is only worth anything if it
    asks the same question the migrator asks. On the raw string it would have been wrong in both
    directions: Swift's rules yield `MLKEM768`, which does not start with `ML-KEM`, while Java's
    yield `ML-DSA-65`, which does -- so Swift would have looked uncovered after it was covered.
    """
    found = []
    for compiled in _CATALOG.all_rules():
        if compiled.language != language:
            continue
        for example in compiled.rule.examples.positive:
            dets = _SCANNER.scan_source(example.encode(), language, file_path="ex", collapse=False)
            if any(normalize(d).algorithm.upper().startswith(prefix) for d in dets):
                found.append(example)
    return found


class TestEveryClaimedLanguageCanShowItsTarget:
    @pytest.mark.parametrize("language", _PQC_LANGUAGES)
    @pytest.mark.parametrize("prefix", ["ML-KEM", "ML-DSA"])
    def test_a_post_quantum_example_exists(self, language: str, prefix: str) -> None:
        examples = _examples_yielding(language, prefix)
        assert examples, (
            f"no {language} rule ships an example the scanner reads as {prefix}. "
            f"target_shapes will report 'no confirmable rewrite' and the migrator will skip "
            f"every {prefix} task in {language}, even though its queries match the call."
        )

    @pytest.mark.parametrize("language", _JVM)
    def test_the_example_is_the_provider_call_and_not_a_library_of_its_own(
        self, language: str
    ) -> None:
        """Kotlin and Scala have no PQC API of their own; showing one would be an invention."""
        joined = "\n".join(_examples_yielding(language, "ML-KEM"))
        assert "KeyPairGenerator.getInstance" in joined, joined[:200]


class TestTheClassicalExamplesStillStand:
    """The PQC examples were added beside the classical ones, not in place of them.

    A rule whose only example is its post-quantum target has quietly stopped documenting what it
    detects, which is the legacy algorithm.
    """

    @pytest.mark.parametrize("language", _PQC_LANGUAGES)
    def test_a_classical_key_exchange_example_survives(self, language: str) -> None:
        assert _examples_yielding(language, "RSA"), f"{language} lost its RSA example"
