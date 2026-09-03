"""The vacuous flag, through the real rescan stage rather than a constructed StageResult.

The fallback at the heart of this lives in `_stage_rescan`, not in the ladder, and a unit test
against a hand-built `StageResult` would pass whether or not the stage ever sets the flag.
"""

from __future__ import annotations

from qubit_migrate.transform.rules import MigrationRule
from qubit_migrate.transform.validate import _stage_rescan

_AES_GCM = (
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    "\n"
    "def seal(key, nonce, data):\n"
    "    return AESGCM(key).encrypt(nonce, data, None)\n"
)


def _rule(gone: list[str]) -> MigrationRule:
    return MigrationRule(
        id="probe",
        language="python",
        title="weak cipher",
        matches={"algorithm": gone},
        target={"algorithm": "AES-256-GCM"},
        codemod=None,
        prompt_constraints=[],
        remediation="auto",
        rescan_expect={"gone": {"algorithm_prefix": gone}},
    )


def test_an_unfailable_gone_criterion_is_flagged_vacuous() -> None:
    """An AES finding routed to a rule that lists DES/3DES/RC4/Blowfish.

    The patch is checked for the absence of four algorithms the file never contained. It passes,
    and the pass says nothing. This is the shape the plan predicted; the flag makes it countable.
    """
    result = _stage_rescan(
        _AES_GCM,
        _rule(["DES", "3DES", "RC4", "Blowfish"]),
        language="python",
        asset_algorithm="AES-128-ECB",
    )
    assert result.status == "pass"
    assert result.vacuous is True
    assert "could not have failed" in result.detail


def test_a_criterion_that_names_the_asset_is_not_vacuous() -> None:
    """The control. Same code path, same shape of rule — only the prefix list differs."""
    result = _stage_rescan(
        _AES_GCM,
        _rule(["DES", "AES-128-ECB", "RC4"]),
        language="python",
        asset_algorithm="AES-128-ECB",
    )
    assert result.status == "pass"
    assert result.vacuous is False


def test_a_present_only_rule_is_not_called_vacuous() -> None:
    """A rule with no `gone` clause is a different bucket (present-gated), not this one."""
    rule = MigrationRule(
        id="probe",
        language="python",
        title="present only",
        matches={"algorithm": ["RSA"]},
        target={"algorithm": "AES-256-GCM"},
        codemod=None,
        prompt_constraints=[],
        remediation="auto",
        rescan_expect={"present": {"algorithm_prefix": ["AES-256-GCM"]}},
    )
    result = _stage_rescan(_AES_GCM, rule, language="python", asset_algorithm="RSA-2048")
    assert result.vacuous is False


class TestConfigFilesCanRescan:
    """`parses` and `compiles` cannot judge a config file. `rescan` can, and was skipping anyway.

    Measured on the live database before this fix: 11 nginx/apache TLS-config patches were APPLIED
    with an evidence level of "nothing established", because the rescan stage looked the language
    up in a SOURCE-FILE extension map. The scanner had found the weak TLS asset in those same files
    moments earlier.
    """

    _NGINX_WEAK = "server {\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n}\n"
    _NGINX_HARDENED = (
        "server {\n"
        "    ssl_protocols TLSv1.3;\n"
        "    ssl_conf_command Groups X25519MLKEM768:X25519;\n"
        "}\n"
    )

    @staticmethod
    def _tls_rule() -> MigrationRule:
        return MigrationRule(
            id="nginx-tls-01",
            language="nginx",
            title="harden TLS",
            matches={"algorithm": ["TLS"]},
            target={"algorithm": "X25519MLKEM768"},
            codemod=None,
            prompt_constraints=[],
            remediation="auto",
            rescan_expect={"gone": {"algorithm_prefix": ["TLSv1.0", "TLSv1.1"]}},
        )

    def test_an_nginx_patch_is_rescanned_rather_than_skipped(self) -> None:
        result = _stage_rescan(
            self._NGINX_HARDENED,
            self._tls_rule(),
            language="nginx",
            target_rel_path="conf/nginx.conf",
        )
        assert result.status != "skipped", result.detail

    @staticmethod
    def _names_written(*args: object, **kwargs: object) -> list[str]:
        """The filenames `_stage_rescan` actually handed the scanner.

        The stage's own verdict is too coarse to pin this: several different wrong filenames
        produce the same status by different routes, so asserting on the status passes with the
        guard reverted. The name is the thing under test.
        """
        import tempfile
        from pathlib import Path as _Path

        import qubit_migrate.transform.validate as validate_module

        seen: list[str] = []
        real = tempfile.TemporaryDirectory

        class _Spy:
            def __init__(self) -> None:
                self._d = real()

            def __enter__(self) -> str:
                return self._d.__enter__()

            def __exit__(self, *exc: object) -> None:
                seen.extend(p.name for p in _Path(self._d.name).iterdir())
                self._d.__exit__(None, None, None)

        validate_module.tempfile.TemporaryDirectory = _Spy  # type: ignore[assignment,misc]
        try:
            _stage_rescan(*args, **kwargs)  # type: ignore[arg-type]
        finally:
            validate_module.tempfile.TemporaryDirectory = real  # type: ignore[misc]
        return seen

    def test_the_original_basename_reaches_the_scanner(self) -> None:
        """The config dispatch is name-sensitive: `options-ssl-apache.conf` routes to the Apache
        parser because "apache" is in its NAME. Writing everything to `patched.conf` sent an
        Apache file to nginx's stricter grammar instead."""
        seen = self._names_written(
            self._NGINX_HARDENED,
            self._tls_rule(),
            language="apache",
            target_rel_path="tls_configs/options-ssl-apache.conf",
        )
        assert seen == ["options-ssl-apache.conf"], seen

    def test_a_path_whose_suffix_disagrees_with_the_language_is_not_trusted(self) -> None:
        """A Python patch whose recorded path ends `.txt` must still be written as `.py`.

        Writing it as `crypto.txt` is not merely a skip — it is worse. The scanner does not read
        `.txt`, so it returns no detections at all: a `gone` check is then satisfied by a file that
        was never examined, and a `present` check fails a perfectly correct rewrite.
        """
        seen = self._names_written(
            _AES_GCM,
            _rule(["DES"]),
            language="python",
            target_rel_path="pkg/crypto.txt",
        )
        assert seen == ["patched.py"], seen


class TestHybridInvertsTheExpectation:
    """For a composite target the classical half must SURVIVE, not vanish.

    Left unhandled, the gate rewarded exactly the wrong patch: a rewrite that dropped the classical
    signature satisfied `gone: ECDSA` and was ACCEPTED, while the correct composite — which
    necessarily still contains ECDSA — was REJECTED. The tool would have driven every hybrid
    migration toward the non-compliant outcome and reported success for it.
    """

    _COMPOSITE = (
        "from cryptography.hazmat.primitives.asymmetric import ec, mldsa\n"
        "\n"
        "def sign(data):\n"
        "    classical = ec.generate_private_key(ec.SECP256R1())\n"
        "    pqc = mldsa.MLDSA65PrivateKey.generate()\n"
        "    return classical.sign(data, ec.ECDSA(None)) + pqc.sign(data)\n"
    )
    #: The dangerous one. Only the lattice half survives — and the old `gone: ECDSA` criterion
    #: reads that as a clean migration.
    _PQC_ONLY = (
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "\n"
        "def sign(data):\n"
        "    return mldsa.MLDSA65PrivateKey.generate().sign(data)\n"
    )

    @staticmethod
    def _rule(target: str) -> MigrationRule:
        return MigrationRule(
            id="py-signature-01",
            language="python",
            title="ECDSA -> composite",
            matches={"algorithm": ["ECDSA"]},
            target={"algorithm": target},
            codemod=None,
            prompt_constraints=[],
            remediation="auto",
            rescan_expect={
                "gone": {"algorithm_prefix": ["ECDSA"]},
                "present": {"algorithm_prefix": ["ML-DSA"]},
            },
        )

    def test_dropping_the_classical_half_is_rejected(self) -> None:
        result = _stage_rescan(
            self._PQC_ONLY,
            self._rule("ML-DSA-65+ECDSA-P256"),
            language="python",
            asset_algorithm="ECDSA-P256",
        )
        assert result.status == "fail", result.detail
        assert "defence in depth" in result.detail

    def test_the_correct_composite_is_accepted(self) -> None:
        """It still contains ECDSA. Under the pure expectation that alone would fail it."""
        result = _stage_rescan(
            self._COMPOSITE,
            self._rule("ML-DSA-65+ECDSA-P256"),
            language="python",
            asset_algorithm="ECDSA-P256",
        )
        assert result.status == "pass", result.detail

    def test_a_pure_target_still_requires_the_old_algorithm_gone(self) -> None:
        """The control. Same rule shape, same sources — only the target differs."""
        kept = _stage_rescan(
            self._COMPOSITE,
            self._rule("ML-DSA-65"),
            language="python",
            asset_algorithm="ECDSA-P256",
        )
        assert kept.status == "fail", kept.detail
        removed = _stage_rescan(
            self._PQC_ONLY,
            self._rule("ML-DSA-65"),
            language="python",
            asset_algorithm="ECDSA-P256",
        )
        assert removed.status == "pass", removed.detail

    def test_both_halves_are_required_not_either(self) -> None:
        """A composite's halves are not alternatives. The `present` list normally means "any one
        of these is acceptable", which for a composite accepts a patch that shipped one half."""
        pqc_missing = (
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "\n"
            "def sign(data):\n"
            "    return ec.generate_private_key(ec.SECP256R1()).sign(data, ec.ECDSA(None))\n"
        )
        result = _stage_rescan(
            pqc_missing,
            self._rule("ML-DSA-65+ECDSA-P256"),
            language="python",
            asset_algorithm="ECDSA-P256",
        )
        assert result.status == "fail", result.detail
        assert "ML-DSA-65" in result.detail
