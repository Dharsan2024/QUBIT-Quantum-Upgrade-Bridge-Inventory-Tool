"""Transform-rule coverage, routing and codemod correctness.

Detection outgrew migration badly (145 detection rules against 2 transform rules), so these tests
pin down the three things that had to be true once the rule pack expanded:

1. Every rule declares a codemod that actually exists, or is explicitly an LLM rule.
2. Assets route to the RIGHT rule. Config-hardening rules legitimately list common algorithm names
   (a weak TLS suite contains RSA / AES-128 / 3DES), so without provenance and file-type matching
   they would claim source-code assets and point a config codemod at a .py file.
3. The deterministic codemods produce the intended output, including the post-quantum bits.
"""

from __future__ import annotations

from pathlib import Path

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
from qubit_migrate.transform.codemods import _CODEMOD_REGISTRY, run_codemod
from qubit_migrate.transform.config_codemods import harden_apache, harden_nginx, harden_ssh
from qubit_migrate.transform.rules import load_rules, match_rule


def _asset(
    algorithm: str,
    *,
    source: SourceScanner = SourceScanner.code,
    usage: UsageContext = UsageContext.hash,
    path: str = "a.py",
) -> CryptoAsset:
    return CryptoAsset(
        source_scanner=source,
        asset_type=AssetType.algorithm_use,
        algorithm=algorithm,
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(file_path=path, line=1),
        evidence=Evidence(),
    )


# ---------------------------------------------------------------------------
# Rule-pack integrity
# ---------------------------------------------------------------------------


def test_every_declared_codemod_is_registered() -> None:
    """A rule naming a codemod that does not exist fails only at apply time, on a real repo."""
    load_rules.cache_clear()
    missing = [
        f"{r.id} -> {r.codemod}"
        for r in load_rules()
        if r.codemod and r.codemod not in _CODEMOD_REGISTRY
    ]
    assert not missing, f"rules reference unregistered codemods: {missing}"


def test_every_rule_has_a_worked_example_for_the_llm() -> None:
    """The examples are few-shot prompt content now, not documentation, so a rule without one gives
    the local model materially less to work from."""
    load_rules.cache_clear()
    without = [r.id for r in load_rules() if not r.example]
    assert not without, f"rules with no worked example: {without}"


def test_data_compat_reflects_real_migration_hazard() -> None:
    """`in_place` is a promise that nothing stored has to change. Config rules can honestly make it
    (a TLS directive only affects the next handshake); a cipher swap cannot, because existing
    ciphertext is unreadable by the new code."""
    load_rules.cache_clear()
    by_id = {r.id: r for r in load_rules()}
    assert by_id["cfg-tls-01"].data_compat == "in_place"
    assert by_id["cfg-ssh-01"].data_compat == "in_place"
    assert by_id["py-weakcipher-01"].data_compat == "reencrypt_required"
    assert by_id["py-ecdh-kex-01"].data_compat == "reencrypt_required"


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm,source,usage,path,expected",
    [
        ("MD5", SourceScanner.code, UsageContext.hash, "a.py", "py-weakhash-01"),
        ("MD5", SourceScanner.code, UsageContext.hash, "a.go", "code-weakhash-02"),
        ("SHA-1", SourceScanner.code, UsageContext.hash, "a.c", "code-weakhash-02"),
        ("MD5", SourceScanner.code, UsageContext.hash, "a.ts", "code-weakhash-02"),
        ("RSA-2048", SourceScanner.code, UsageContext.kex, "a.py", "py-rsa-kex-01"),
        ("ECDH-P256", SourceScanner.code, UsageContext.kex, "a.py", "py-ecdh-kex-01"),
        ("X25519", SourceScanner.code, UsageContext.kex, "a.py", "py-ecdh-kex-01"),
        ("ECDSA-P256", SourceScanner.code, UsageContext.signature, "a.py", "py-signature-01"),
        ("RS256", SourceScanner.code, UsageContext.token, "a.py", "py-signature-01"),
        ("3DES", SourceScanner.code, UsageContext.encryption_at_rest, "a.py", "py-weakcipher-01"),
        ("TLSv1.0", SourceScanner.config, UsageContext.tls, "nginx.conf", "cfg-tls-01"),
        ("ssh-rsa", SourceScanner.config, UsageContext.signature, "sshd_config", "cfg-ssh-01"),
        ("RSA", SourceScanner.config, UsageContext.kex, "requirements.txt", "dep-pqc-01"),
    ],
)
def test_asset_routes_to_expected_rule(
    algorithm: str, source: SourceScanner, usage: UsageContext, path: str, expected: str
) -> None:
    load_rules.cache_clear()
    rule = match_rule(_asset(algorithm, source=source, usage=usage, path=path))
    assert rule is not None, f"{algorithm} ({path}) matched no rule"
    assert rule.id == expected


def test_config_rules_do_not_claim_source_code_assets() -> None:
    """The regression this guards: cfg-tls-01 lists RSA/AES-128/3DES because a weak TLS suite
    really does contain them. Without source_scanner matching it would also match a Python
    AES-128 asset and hand a .py file to the config codemod."""
    load_rules.cache_clear()
    for algorithm in ("AES-128", "3DES", "RSA"):
        rule = match_rule(
            _asset(
                algorithm,
                source=SourceScanner.code,
                usage=UsageContext.encryption_at_rest,
                path="app.py",
            )
        )
        assert rule is None or rule.id.startswith("py-"), (
            f"{algorithm} in code routed to {rule.id if rule else None}, expected a py-* rule"
        )


# ---------------------------------------------------------------------------
# Deterministic codemods
# ---------------------------------------------------------------------------


def test_nginx_hardening_adds_the_hybrid_pqc_group() -> None:
    """This single directive is the reason config hardening is the highest-value transform: it makes
    every TLS session the service negotiates hybrid post-quantum, immediately."""
    source = "server {\n    ssl_protocols TLSv1 TLSv1.1;\n    ssl_ciphers HIGH:!aNULL;\n}\n"
    new_source, changed = harden_nginx(source)
    assert changed
    assert "X25519MLKEM768" in new_source
    assert "TLSv1.2 TLSv1.3" in new_source
    assert "TLSv1.1" not in new_source
    # TLS 1.2 is deliberately retained; dropping it would break clients and make the patch unusable.
    assert "TLSv1.2" in new_source


def test_ssh_hardening_uses_the_pqc_hybrid_kex() -> None:
    source = (
        "Ciphers aes128-cbc,3des-cbc\nMACs hmac-sha1\nKexAlgorithms diffie-hellman-group1-sha1\n"
    )
    new_source, changed = harden_ssh(source)
    assert changed
    assert "sntrup761x25519-sha512@openssh.com" in new_source
    assert "3des-cbc" not in new_source
    assert "hmac-sha1\n" not in new_source


def test_apache_hardening_disables_legacy_and_sets_curves() -> None:
    source = "SSLProtocol all -SSLv2\nSSLCipherSuite HIGH:!aNULL\n"
    new_source, changed = harden_apache(source)
    assert changed
    assert "+TLSv1.2 +TLSv1.3" in new_source
    assert "X25519MLKEM768" in new_source


def test_already_hardened_config_is_left_alone() -> None:
    """Idempotence matters: re-running must not produce an empty-but-dirty patch, which would fail
    the validation pipeline's `applies` stage as a no-op diff."""
    hardened, _ = harden_ssh(
        "Ciphers aes128-cbc\nMACs hmac-sha1\nKexAlgorithms diffie-hellman-group1-sha1\n"
    )
    _, changed_again = harden_ssh(hardened)
    assert changed_again is False


def test_dependency_bump_raises_floor_only(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("Flask==3.0.3\ncryptography==42.0.8\n", encoding="utf-8")
    result = run_codemod("bump_crypto_dependency", _asset("RSA", source=SourceScanner.config), reqs)
    assert result is not None
    _, new_source = result
    assert "cryptography>=48.0.0" in new_source
    assert "Flask==3.0.3" in new_source  # unrelated pins untouched

    ahead = tmp_path / "requirements.txt"
    ahead.write_text("cryptography==49.0.0\n", encoding="utf-8")
    assert run_codemod("bump_crypto_dependency", _asset("RSA"), ahead) is None


def test_cross_language_hash_swap_updates_the_import(tmp_path: Path) -> None:
    """A swapped constructor without a swapped import does not compile, so the import has to move
    with it."""
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "crypto/md5"\n\nfunc f(b []byte) { md5.New() }\n', encoding="utf-8"
    )
    result = run_codemod("weakhash_to_sha256", _asset("MD5", path="main.go"), go_file)
    assert result is not None
    _, new_source = result
    assert '"crypto/sha256"' in new_source
    assert "sha256.New()" in new_source
    assert "md5" not in new_source


def test_unknown_codemod_raises() -> None:
    with pytest.raises(KeyError):
        run_codemod("does_not_exist", _asset("MD5"), Path("a.py"))


# ---------------------------------------------------------------------------
# Codemod authority and filename routing
# ---------------------------------------------------------------------------


def test_config_and_manifest_rules_keep_their_codemod_authority() -> None:
    """These transforms have a single correct output — the hybrid group, the version floor — so the
    codemod outranks an explicit `--generator llm`.

    The regression: forcing the LLM produced an nginx.conf that LOOKED modern (TLS 1.2+1.3, AEAD
    suites) but omitted `ssl_ecdh_curve X25519MLKEM768`, the one line that makes the deployment
    quantum-safe. It then blocked every sibling asset in that file, because the model saw an
    already-modern config and returned it unchanged — three wasted attempts each."""
    load_rules.cache_clear()
    by_id = {r.id: r for r in load_rules()}
    for rule_id in ("cfg-tls-01", "cfg-ssh-01", "dep-pqc-01"):
        assert by_id[rule_id].codemod_authoritative, (
            f"{rule_id} must not be delegated to the LLM: its correct output is a constant"
        )


def test_authoritative_rules_actually_have_a_codemod_to_be_authoritative_with() -> None:
    """`codemod_authoritative` without a codemod would silently do nothing."""
    load_rules.cache_clear()
    broken = [r.id for r in load_rules() if r.codemod_authoritative and not r.codemod]
    assert not broken, f"rules claiming codemod authority but declaring no codemod: {broken}"


@pytest.mark.parametrize("filename", ["requirements.txt", "pyproject.toml", "pom.xml"])
def test_dependency_manifests_do_not_route_to_config_hardening(filename: str) -> None:
    """The dependency scanner reports manifests with `source_scanner=config` too, so provenance
    alone cannot separate them from an sshd_config. Without filename matching, an ECDSA-P256 pin in
    requirements.txt was claimed by cfg-ssh-01 and the sshd hardening codemod was pointed at a
    pip manifest."""
    load_rules.cache_clear()
    rule = match_rule(
        _asset(
            "ECDSA-P256",
            source=SourceScanner.config,
            usage=UsageContext.signature,
            path=filename,
        )
    )
    assert rule is not None, f"{filename} matched no rule at all"
    assert rule.id == "dep-pqc-01"


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("nginx.conf", "cfg-tls-01"),
        ("httpd.conf", "cfg-tls-01"),
        ("sshd_config", "cfg-ssh-01"),
    ],
)
def test_config_files_still_route_to_their_own_hardening_rule(filename: str, expected: str) -> None:
    """The filename constraint must not be so tight that real config files stop matching."""
    load_rules.cache_clear()
    usage = UsageContext.tls if expected == "cfg-tls-01" else UsageContext.kex
    rule = match_rule(
        _asset("AES-128", source=SourceScanner.config, usage=usage, path=f"/etc/{filename}")
    )
    assert rule is not None and rule.id == expected


def test_nginx_hardening_is_idempotent() -> None:
    """Sibling assets in one file re-run the codemod. A second pass that reports a change would
    produce an empty-but-dirty patch and fail validation as a no-op diff."""
    hardened, changed = harden_nginx(
        "server {\n    ssl_protocols TLSv1 TLSv1.1;\n    ssl_ciphers HIGH:!aNULL;\n}\n"
    )
    assert changed
    _, changed_again = harden_nginx(hardened)
    assert changed_again is False


def test_apache_hardening_is_idempotent() -> None:
    hardened, changed = harden_apache("SSLProtocol all -SSLv2\nSSLCipherSuite HIGH:!aNULL\n")
    assert changed
    _, changed_again = harden_apache(hardened)
    assert changed_again is False
