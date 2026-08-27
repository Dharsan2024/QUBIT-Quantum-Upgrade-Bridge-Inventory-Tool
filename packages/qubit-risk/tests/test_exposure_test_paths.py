"""Test/fixture code must not be scored as production exposure.

QUBIT's own held-out measurement put this pass's precision at 47.1%, and named the single largest
remaining false-positive source precisely: the pass did not distinguish a test fixture from
production code. A throwaway RSA key in ``tests/fixtures/`` was scored exactly like one terminating
production TLS, so half of what an operator saw as "urgent" was code no adversary can reach.

The dangerous direction here is the opposite error — silently discounting a REAL production finding
because its path merely contains the letters "test" (``contest/``, ``latest/``, ``protests/``).
Those cases are pinned below and matter more than the ones this fix is for: a missed real finding
in a security tool is worse than a surfaced fixture.
"""

from __future__ import annotations

import pytest
from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_risk.score import exposure_of, looks_like_test_path


def _asset(file_path: str | None, usage: UsageContext = UsageContext.kex) -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(file_path=file_path, line=1),
        evidence=Evidence(snippet="rsa.generate_private_key(...)"),
    )


class TestPathsThatAreTestCode:
    @pytest.mark.parametrize(
        "path",
        [
            "tests/test_crypto.py",
            "test/helpers.go",
            "src/spec/crypto_spec.rb",
            "app/__tests__/keys.ts",
            "tests/fixtures/server.key",
            "internal/testdata/cert.pem",
            "pkg/mocks/signer.go",
            "examples/quickstart.py",
            "demo/app.js",
            "samples/tls_client.java",
            "benchmarks/hash_bench.rs",
        ],
    )
    def test_a_directory_segment_marks_the_file_as_test_code(self, path: str) -> None:
        assert looks_like_test_path(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "pkg/crypto/signer_test.go",  # Go keeps tests beside the code
            "src/auth/session.test.ts",
            "src/auth/session.spec.js",
            "app/test_login.py",
            "app/conftest.py",
        ],
    )
    def test_a_filename_shape_marks_the_file_as_test_code(self, path: str) -> None:
        assert looks_like_test_path(path) is True

    def test_windows_separators_are_handled(self) -> None:
        # Scans on Windows record backslash paths; the same file must classify identically.
        assert looks_like_test_path(r"pkg\tests\fixtures\server.key") is True


class TestPathsThatAreProductionCode:
    @pytest.mark.parametrize(
        "path",
        [
            "contest/scoring.py",  # contains "test", is not a test directory
            "src/latest/handler.go",
            "protests/api.rb",
            "src/attestation/verify.go",
            "lib/testify.py",  # "testify" is not "test"
            "src/crypto/tls.go",
            "server.key",
            "internal/specification/parser.py",  # "specification" is not "spec"
        ],
    )
    def test_a_lookalike_directory_is_not_treated_as_test_code(self, path: str) -> None:
        assert looks_like_test_path(path) is False

    @pytest.mark.parametrize("path", ["", None])
    def test_a_missing_path_is_not_test_code(self, path: str | None) -> None:
        # Network/Vault findings carry no file path at all; they must keep their real exposure.
        assert looks_like_test_path(path) is False


class TestExposureTier:
    def test_a_fixture_key_drops_to_the_lowest_exposure_tier(self) -> None:
        assert exposure_of(_asset("tests/fixtures/server.key")) == "offline"

    def test_the_same_finding_in_production_keeps_network_exposure(self) -> None:
        # The regression that matters: the discount must not leak onto real code.
        assert exposure_of(_asset("src/crypto/tls.go")) == "network"

    def test_a_lookalike_directory_keeps_network_exposure(self) -> None:
        assert exposure_of(_asset("contest/scoring.py")) == "network"

    def test_an_asset_with_no_file_path_is_unaffected(self) -> None:
        # A live TLS probe records a host, not a file - it must still read as network exposure.
        assert exposure_of(_asset(None)) == "network"

    def test_a_test_path_outranks_usage_context(self) -> None:
        # `kex` usage would normally force "network"; being a fixture overrides that, which is
        # the whole point - the algorithm is irrelevant if the code never runs.
        assert exposure_of(_asset("tests/tls_fixture.py", UsageContext.kex)) == "offline"
