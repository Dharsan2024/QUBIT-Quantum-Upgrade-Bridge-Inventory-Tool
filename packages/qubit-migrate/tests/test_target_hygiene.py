"""Target hygiene: never write a migration this environment cannot build.

A patch naming a primitive the machine does not have is worse than no patch. It applies, it
parses, its names read correctly, and then it fails to import — at which point every later gate
blames the PATCH for what is an environment problem, and the model time is already spent.

Both halves are measured rather than hypothetical:

* `cryptography` 49.0.0 ships **no `slhdsa` module**, while BSI TR-02102 approves SLH-DSA and a
  rule may legitimately target it.
* Four patches on this installation named `pqcrypto`, which is not a dependency of this project.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform.targets import (
    clear_availability_cache,
    installed_version,
    library_exists,
    target_availability,
)


class TestProbedNotTabulated:
    """The check asks the installed library, so it cannot be wrong about this machine."""

    def test_an_available_target_is_allowed(self) -> None:
        result = target_availability("ML-DSA-65")
        assert result.available
        assert not result.unknown
        assert result.advisory == ""

    def test_a_target_with_no_implementation_here_is_blocked(self) -> None:
        """SLH-DSA. Approved by BSI, standardised as FIPS 205, and absent from `cryptography`
        49.0.0 — so a patch naming it today produces code this environment cannot run."""
        result = target_availability("SLH-DSA-SHA2-128s")
        assert not result.available
        assert not result.unknown

    def test_the_advisory_names_the_library_version_and_symbol(self) -> None:
        """ "ML-DSA is unavailable" is not actionable. The operator needs to know which package,
        at which version, is missing which name."""
        advisory = target_availability("SLH-DSA-SHA2-128s").advisory
        assert "cryptography" in advisory
        assert installed_version("cryptography") in advisory
        assert "slhdsa" in advisory

    def test_an_uncovered_target_is_unknown_and_is_not_blocked(self) -> None:
        """A coverage gap must not become a capability loss.

        Blocking on an unrecognised target would refuse every new algorithm the moment a rule
        named one before the probe table did — the same mistake as counting a skipped gate as a
        passed one, in the opposite direction.
        """
        result = target_availability("FALCON-512")
        assert result.unknown
        assert result.available, "an unknown target must not be blocked"

    def test_a_composite_resolves_through_its_pqc_half(self) -> None:
        """`ML-DSA-65+ECDSA-P256` must be judged on the lattice component, not fall off the end
        of the table into `unknown`."""
        result = target_availability("ML-DSA-65+ECDSA-P256")
        assert result.available
        assert not result.unknown

    def test_the_longest_prefix_wins_regardless_of_table_order(self) -> None:
        """`SLH-DSA-SHA2-128s` contains BOTH `SLH-DSA` and `SHA` — because `SHA2` contains `SHA`.

        The SHA probe points at `hashlib`, which is always available, so matching the shorter
        prefix would report an SLH-DSA target as buildable when this environment has no `slhdsa`
        module at all. Today's dict happens to list SLH-DSA first, which is why a
        "first match wins" implementation passes by luck; reversing the table exposes it.
        """
        import qubit_migrate.transform.targets as module

        original = dict(module._PROBES)
        try:
            module._PROBES.clear()
            module._PROBES.update(reversed(list(original.items())))
            result = target_availability("SLH-DSA-SHA2-128s")
            assert not result.available, "matched the SHA probe instead of SLH-DSA"
        finally:
            module._PROBES.clear()
            module._PROBES.update(original)

    def test_the_probe_checks_the_symbol_not_just_the_module(self) -> None:
        """A package can import while lacking the class — a partial vendoring, or a version that
        shipped the module before the primitive. Only the symbol settles it."""
        import qubit_migrate.transform.targets as module

        clear_availability_cache()
        probe = module._PROBES["ML-DSA"]
        original = probe.symbol
        module._PROBES["ML-DSA"] = type(probe)(
            probe.distribution, probe.module, "NoSuchClassInThisRelease"
        )
        try:
            assert not target_availability("ML-DSA-65").available
        finally:
            module._PROBES["ML-DSA"] = type(probe)(probe.distribution, probe.module, original)
            clear_availability_cache()


class TestLibraryNamesAreVerified:
    """The `pqcrypto` case: a model told to import a package that does not exist will do it."""

    @pytest.mark.parametrize("name", ["cryptography", "hashlib", "json"])
    def test_a_real_package_is_recognised(self, name: str) -> None:
        assert library_exists(name)

    @pytest.mark.parametrize("name", ["pqcrypto", "oqs", "liboqs_python", "definitely_not_here"])
    def test_an_invented_package_is_rejected(self, name: str) -> None:
        assert not library_exists(name)

    @pytest.mark.parametrize("name", ["", "not a name", "os.path", "../etc"])
    def test_a_malformed_name_is_rejected_by_the_guard(self, name: str) -> None:
        """Rejected before `find_spec` is reached. A dotted or spaced name is not a top-level
        package, and asking the import system about it is both pointless and, for a dotted name
        whose parent is missing, an exception."""
        assert not library_exists(name)

    def test_a_finder_that_raises_does_not_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The guard above means well-formed names never reach a raising `find_spec` in THIS
        environment — but a broken meta-path finder in someone else's would, and the generator
        must get an answer rather than an exception.

        Tested by making it raise, because no input that survives the guard raises here: asserting
        on the guard's inputs leaves the handler unexercised.
        """
        import qubit_migrate.transform.targets as module

        def boom(_name: str) -> None:
            raise ImportError("a meta-path finder blew up")

        monkeypatch.setattr(module.importlib.util, "find_spec", boom)
        assert library_exists("cryptography") is False

    def test_it_does_not_execute_the_package_it_is_asked_about(self) -> None:
        """`find_spec`, not `import`. Running module-level code from an arbitrary model-named
        package is not something to do inside the generator."""
        import sys

        before = set(sys.modules)
        library_exists("email")  # stdlib, present, and not already imported in most runs
        assert "email.mime" not in set(sys.modules) - before


class TestSynthesisDropsAnAbsentLibrary:
    """The rule must not instruct the model to import something that is not there."""

    @staticmethod
    def _asset(algorithm: str = "RSA-2048"):
        from qubit_core import (
            AssetType,
            CryptoAsset,
            Evidence,
            Location,
            QuantumAttack,
            QuantumVulnerability,
            Sensitivity,
            SourceScanner,
            UsageContext,
            utcnow,
        )

        return CryptoAsset(
            algorithm=algorithm,
            usage_context=UsageContext.kex,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="pkg/net.py", line=3),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
            sensitivity=Sensitivity.credentials,
            evidence=Evidence(),
            discovered_at=utcnow(),
        )

    def test_an_uninstallable_library_is_omitted_from_the_rule(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dropped, not substituted. Inventing a replacement is the same failure with a different
        author — the model would then write against whatever QUBIT guessed."""
        import qubit_migrate.transform.synthesized as module

        monkeypatch.setattr(module, "library_exists", lambda _name: False)
        rule = module.synthesize_rule(self._asset(), "python")
        assert rule is not None
        assert "library" not in rule.target, rule.target
        # The TARGET survives, because the rescan and the metamorphic oracle verify it
        # independently of any library recommendation.
        assert rule.target.get("algorithm")

    def test_an_installed_library_is_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The control. Without it the test above would pass if the library were never set."""
        import qubit_migrate.transform.synthesized as module

        monkeypatch.setattr(module, "library_exists", lambda _name: True)
        rule = module.synthesize_rule(self._asset(), "python")
        assert rule is not None
        assert rule.target.get("library", {}).get("name"), rule.target
