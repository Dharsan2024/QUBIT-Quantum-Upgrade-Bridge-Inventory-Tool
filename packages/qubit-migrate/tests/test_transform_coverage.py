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
    LibraryRef,
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
    library: str | None = None,
) -> CryptoAsset:
    """A synthetic asset.

    `library` matters for manifest findings: every asset the dependency scanner emits carries a
    package name (verified — 31 of 31 library assets in the polyglot corpus have one), and
    `dep-pqc-01` matches on it so it only claims packages with a verified PQC-capable floor. An
    SCA fixture without a library name is therefore not a realistic one.
    """
    return CryptoAsset(
        source_scanner=source,
        asset_type=AssetType.library if library else AssetType.algorithm_use,
        algorithm=algorithm,
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(file_path=path, line=1),
        library=LibraryRef(name=library) if library else None,
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
    ],
)
def test_asset_routes_to_expected_rule(
    algorithm: str, source: SourceScanner, usage: UsageContext, path: str, expected: str
) -> None:
    load_rules.cache_clear()
    rule = match_rule(_asset(algorithm, source=source, usage=usage, path=path))
    assert rule is not None, f"{algorithm} ({path}) matched no rule"
    assert rule.id == expected


@pytest.mark.parametrize(
    ("library", "path", "expected"),
    [
        # Packages with a verified PQC-capable floor in codemods._MIN_PQC_VERSIONS.
        ("cryptography", "requirements.txt", "dep-pqc-01"),
        ("cryptography", "pyproject.toml", "dep-pqc-01"),
        ("bcprov-jdk18on", "pom.xml", "dep-pqc-01"),
        # A package with no established floor must NOT be claimed: the rule would match, the
        # codemod would find nothing to bump, and the app's Generate button would answer 422.
        ("pyjwt", "requirements.txt", None),
        # A manifest format the codemod cannot parse at all. Matching `.toml` by suffix claimed
        # Cargo.toml and produced exactly that 422.
        ("md-5", "Cargo.toml", None),
        ("jsonwebtoken", "package.json", None),
    ],
)
def test_dependency_rule_only_claims_packages_it_can_actually_bump(
    library: str, path: str, expected: str | None
) -> None:
    """A rule that matches but produces no patch is worse than one that does not match.

    `dep-pqc-01` matched on `file_suffix: [".txt", ".toml", ".xml"]` and any of six algorithm names,
    so it claimed every SCA finding in any of those files — Cargo.toml, package.json, an arbitrary
    XML — while `bump_crypto_dependency` knows three manifest formats and two packages. The
    Migration Hub offered Generate on all of them and answered `422 Codemod produced no change`
    after the click.
    """
    load_rules.cache_clear()
    rule = match_rule(
        _asset(
            "RSA",
            source=SourceScanner.config,
            usage=UsageContext.kex,
            path=path,
            library=library,
        )
    )
    assert (rule.id if rule else None) == expected


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


@pytest.mark.parametrize(
    ("filename", "library"),
    [
        ("requirements.txt", "cryptography"),
        ("pyproject.toml", "cryptography"),
        ("pom.xml", "bcprov-jdk18on"),
    ],
)
def test_dependency_manifests_do_not_route_to_config_hardening(filename: str, library: str) -> None:
    """The dependency scanner reports manifests with `source_scanner=config` too, so provenance
    alone cannot separate them from an sshd_config. Without filename matching, an ECDSA-P256 pin in
    requirements.txt was claimed by cfg-ssh-01 and the sshd hardening codemod was pointed at a
    pip manifest.

    The fixtures carry a package name because every asset the dependency scanner emits does (31 of
    31 in the polyglot corpus), and `dep-pqc-01` now matches on it — a nameless SCA asset is not a
    shape this scanner can produce.
    """
    load_rules.cache_clear()
    rule = match_rule(
        _asset(
            "ECDSA-P256",
            source=SourceScanner.config,
            usage=UsageContext.signature,
            path=filename,
            library=library,
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


# ── Weak-hash swaps, one language at a time ──────────────────────────────────
#
# `code-weakhash-02` covers every language the scanner reads except Python (which has its own
# libcst rule). Each fixture below is real code in that ecosystem's idiom, and each case is checked
# three ways rather than by reading the diff:
#
#   1. the swap changed something at all;
#   2. QUBIT's own scanner, rescanning the OUTPUT, no longer reports a weak algorithm and now
#      reports SHA-256 — this is what catches a swap that produces plausible but wrong code;
#   3. the output parses with zero tree-sitter ERROR nodes, because a file can still yield findings
#      while being syntactically broken.
#
# Without (2) a "passing" test only proves that text was replaced with other text.

_WEAK_HASHES = frozenset({"MD5", "SHA-1", "MD4", "RIPEMD-160"})

_HASH_FIXTURES: dict[str, tuple[str, str]] = {
    "ruby": (
        "billing.rb",
        """require 'digest'
require 'openssl'

def fingerprint(payload)
  Digest::MD5.hexdigest(payload)
end

def marker(payload)
  Digest::SHA1.hexdigest(payload)
end

def legacy(payload)
  OpenSSL::Digest::MD5.new.digest(payload)
end
""",
    ),
    "php": (
        "legacy.php",
        """<?php
function fingerprint(string $payload): string {
    return md5($payload);
}
function marker(string $payload): string {
    return sha1($payload);
}
function named(string $payload): string {
    return hash('md5', $payload);
}
""",
    ),
    # The declared type has to move with the factory call or this does not compile:
    # `using (MD5 hasher = SHA256.Create())` is a type error, not a working patch.
    "csharp": (
        "Vault.cs",
        """using System.Security.Cryptography;

public static class Vault
{
    public static byte[] Fingerprint(byte[] payload)
    {
        using (MD5 hasher = MD5.Create())
        {
            return hasher.ComputeHash(payload);
        }
    }

    public static byte[] Marker(byte[] payload)
    {
        using var sha = SHA1.Create();
        return sha.ComputeHash(payload);
    }

    public static byte[] OneShot(byte[] payload) => MD5.HashData(payload);
}
""",
    ),
    "rust": (
        "seal.rs",
        """use md5::{Md5, Digest};

pub fn fingerprint(payload: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
}

pub fn one_shot(payload: &[u8]) -> Vec<u8> {
    Md5::digest(payload).to_vec()
}
""",
    ),
    "kotlin": (
        "Crypto.kt",
        """import java.security.MessageDigest

fun fingerprint(payload: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(payload)
}

fun marker(payload: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-1").digest(payload)
""",
    ),
    "scala": (
        "Ledger.scala",
        """import java.security.MessageDigest

object Ledger {
  def fingerprint(payload: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("MD5").digest(payload)

  def marker(payload: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-1").digest(payload)
}
""",
    ),
    # CommonCrypto's DIGEST_LENGTH constant must move with the function, or a 32-byte digest is
    # written into a 20-byte buffer — a stack overwrite rather than a wrong answer.
    "swift": (
        "Wallet.swift",
        """import CryptoKit
import CommonCrypto
import Foundation

func fingerprint(_ payload: Data) -> String {
    let digest = Insecure.MD5.hash(data: payload)
    return digest.map { String(format: "%02x", $0) }.joined()
}

func marker(_ payload: Data) -> String {
    let digest = Insecure.SHA1.hash(data: payload)
    return digest.map { String(format: "%02x", $0) }.joined()
}

func legacy(_ payload: Data) -> Data {
    var out = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    _ = payload.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(payload.count), &out) }
    return Data(out)
}
""",
    ),
    "dart": (
        "fleet.dart",
        """import 'package:crypto/crypto.dart';
import 'dart:convert';

String fingerprint(String payload) {
  return md5.convert(utf8.encode(payload)).toString();
}

String marker(String payload) {
  return sha1.convert(utf8.encode(payload)).toString();
}
""",
    ),
    "bash": (
        "provision.sh",
        """#!/usr/bin/env bash
set -euo pipefail

fingerprint() {
  md5sum "$1" | cut -d' ' -f1
}

marker() {
  sha1sum "$1" | cut -d' ' -f1
}

legacy() {
  openssl dgst -md5 "$1"
}
""",
    ),
    "powershell": (
        "Provision.ps1",
        """param([string]$Path)

function Get-Fingerprint {
    Get-FileHash -Algorithm MD5 -Path $Path
}

function Get-Marker {
    Get-FileHash -Algorithm SHA1 -Path $Path
}
""",
    ),
    # Only the dialect-unambiguous forms are swapped. MySQL's `MD5(x)` is deliberately excluded —
    # its replacement `SHA2(x, 256)` changes the call's arity.
    "sql": (
        "V3__hash.sql",
        """CREATE TABLE estate_credentials (
    id SERIAL PRIMARY KEY,
    secret TEXT NOT NULL,
    fingerprint BYTEA NOT NULL DEFAULT digest('', 'md5'),
    marker BYTEA NOT NULL DEFAULT digest('', 'sha1')
);
""",
    ),
    "cpp": (
        "gateway.cpp",
        """#include <QCryptographicHash>
#include <openssl/evp.h>

QByteArray fingerprint(const QByteArray &payload) {
    return QCryptographicHash::hash(payload, QCryptographicHash::Md5);
}

const EVP_MD *legacy() { return EVP_sha1(); }
""",
    ),
    "tsx": (
        "Component.tsx",
        """import crypto from 'node:crypto';

export function Fingerprint({ payload }: { payload: string }) {
  const digest = crypto.createHash('md5').update(payload).digest('hex');
  return <span>{digest}</span>;
}
""",
    ),
}


@pytest.mark.parametrize("language", sorted(_HASH_FIXTURES))
def test_weak_hash_swap_clears_the_finding(language: str, tmp_path: Path) -> None:
    """Swapping a weak hash must actually remove it, in every language the scanner reads.

    This is the test that makes the swap tables trustworthy. `_apply_hash_swap` returning
    `changed=True` only proves text was replaced; rescanning the output with QUBIT's own scanner
    proves the replacement means what it is supposed to mean.
    """
    from qubit_migrate.transform.codemods import _apply_hash_swap
    from qubit_migrate.transform.validate import _stage_parses
    from qubit_scanner import scan_paths

    filename, source = _HASH_FIXTURES[language]

    before_path = tmp_path / f"before_{filename}"
    before_path.write_text(source, encoding="utf-8")
    before = {a.algorithm for a in scan_paths([before_path]).assets}
    assert before & _WEAK_HASHES, (
        f"the {language} fixture does not contain a weak hash the scanner can see "
        f"({sorted(before)}), so this test would pass without testing anything"
    )

    patched, changed = _apply_hash_swap(source, language)
    assert changed, f"no swap fired for {language}"

    after_path = tmp_path / f"after_{filename}"
    after_path.write_text(patched, encoding="utf-8")
    after = {a.algorithm for a in scan_paths([after_path]).assets}

    assert not (after & _WEAK_HASHES), (
        f"{language}: still weak after the swap — {sorted(after & _WEAK_HASHES)}"
    )
    assert "SHA-256" in after, (
        f"{language}: the weak hash is gone but SHA-256 is not there — the swap produced code the "
        f"scanner cannot read as a digest at all. Got {sorted(after)}"
    )

    parsed = _stage_parses(patched, language)
    assert parsed.status == "pass", f"{language}: patched output does not parse — {parsed.detail}"


def test_every_language_with_a_swap_table_is_reachable_from_a_rule() -> None:
    """A swap table nothing routes to is dead code, and a suffix that routes nowhere is worse.

    The second half is the one that bit: `.tsx` and `.cjs` appeared in some rules' `file_suffix`
    lists but in neither the codemod's suffix map nor the validator's, so a React component matched
    the rule, produced no edit, skipped the parse stage, and reported success.
    """
    from qubit_migrate.transform.codemods import _HASH_SWAPS
    from qubit_migrate.transform.languages import SUFFIX_TO_LANGUAGE

    weakhash = next(r for r in load_rules() if r.id == "code-weakhash-02")
    suffixes = weakhash.matches["file_suffix"]

    unmapped = [s for s in suffixes if s not in SUFFIX_TO_LANGUAGE]
    assert not unmapped, (
        f"code-weakhash-02 lists suffixes with no language mapping: {unmapped}. The rule would "
        "match those files and then produce no edit."
    )

    languages = {SUFFIX_TO_LANGUAGE[s] for s in suffixes}
    without_table = sorted(lang for lang in languages if lang not in _HASH_SWAPS)
    assert not without_table, (
        f"code-weakhash-02 claims these languages but has no swap table for them: {without_table}"
    )


def test_every_rule_suffix_has_a_language_and_a_grammar() -> None:
    """Across every rule pack, not just the weak-hash one.

    A source-code rule listing a suffix with no language mapping makes the validator fall back to
    the rule's own `language`, and for a `multi` rule that means the parse stage is skipped — so a
    patch that changed nothing, or broke the file, passes validation.

    Manifest and config rules are exempt by design, not by omission: `requirements.txt`,
    `pyproject.toml` and `pom.xml` are not source code and have no grammar to check against. The
    test asserts they resolve to a language `_stage_parses` deliberately skips, rather than just
    letting any unmapped suffix through.
    """
    from qubit_migrate.transform.languages import SUFFIX_TO_LANGUAGE, TS_GRAMMAR
    from qubit_migrate.transform.validate import _NON_CODE_LANGUAGES

    problems: list[str] = []
    for rule in load_rules():
        rule_is_code = rule.language not in _NON_CODE_LANGUAGES
        for suffix in rule.matches.get("file_suffix") or []:
            language = SUFFIX_TO_LANGUAGE.get(suffix)
            if language is None:
                if rule_is_code:
                    problems.append(
                        f"{rule.id} (language={rule.language}) lists {suffix}, which maps to no "
                        "language — the validator cannot parse-check its patches"
                    )
                elif rule.language not in _NON_CODE_LANGUAGES:
                    problems.append(
                        f"{rule.id}: {suffix} is unmapped and {rule.language!r} is not a "
                        "recognised non-code language, so the parse stage neither runs nor skips "
                        "deliberately"
                    )
            elif language not in TS_GRAMMAR:
                problems.append(f"{rule.id}: {suffix} -> {language} has no tree-sitter grammar")
    assert not problems, "\n".join(problems)


# ── Parity between what the scanner reads and what migration can act on ──────
#
# The recurring failure in this repo is not a wrong transform, it is a subsystem growing while a
# neighbouring one does not follow. Code scanning went from 6 grammars to 19; the codemod tables,
# the validator's grammar map, the validator's rescan-extension map and the rule packs' suffix lists
# each stayed at 6-7 and each failed *silently* — a rule matched, nothing was edited, validation
# skipped, and the patch reported success.
#
# These assert the joins rather than the pieces.


def test_every_scanner_language_is_known_to_migrate() -> None:
    """A language the scanner reads but migration does not know produces findings nothing can act
    on, and — worse — a patch the validator cannot parse-check."""
    from qubit_migrate.transform.languages import SUFFIX_TO_LANGUAGE
    from qubit_scanner.code.languages import EXT_TO_LANGUAGE

    scanner = set(EXT_TO_LANGUAGE.values())
    migrate = set(SUFFIX_TO_LANGUAGE.values())
    missing = sorted(scanner - migrate)
    assert not missing, (
        f"the scanner reads {sorted(scanner)} but qubit-migrate has no mapping for {missing}"
    )


def test_every_migrate_language_has_a_grammar_and_a_rescan_extension() -> None:
    """Both maps gate a validation stage, and a missing entry *skips* that stage rather than
    failing it — so the gap is invisible in a passing report."""
    from qubit_migrate.transform.languages import (
        LANGUAGE_TO_EXT,
        SUFFIX_TO_LANGUAGE,
        TS_GRAMMAR,
    )

    languages = set(SUFFIX_TO_LANGUAGE.values())
    assert not sorted(languages - set(TS_GRAMMAR)), "languages with no tree-sitter grammar"
    assert not sorted(languages - set(LANGUAGE_TO_EXT)), "languages with no rescan extension"


def test_rescan_extension_round_trips_through_the_scanner() -> None:
    """The rescan stage writes the patched source to `patched<ext>` and scans it. If that extension
    dispatches to a different language, the file is parsed by the wrong grammar — which is exactly
    how a correct Go rewrite was once rejected with "Algorithms: set()"."""
    from qubit_migrate.transform.languages import LANGUAGE_TO_EXT
    from qubit_scanner.code.languages import EXT_TO_LANGUAGE

    mismatched = {
        language: (ext, EXT_TO_LANGUAGE.get(ext))
        for language, ext in LANGUAGE_TO_EXT.items()
        if EXT_TO_LANGUAGE.get(ext) != language
    }
    assert not mismatched, f"rescan extension does not round-trip: {mismatched}"


def test_every_rule_algorithm_and_target_is_in_the_canonical_registry() -> None:
    """A rule matching on an algorithm name the registry does not know can never fire; a rule whose
    TARGET is unknown aims at something the inventory cannot represent, so no rescan can ever
    confirm the migration worked."""
    from qubit_core.algorithms import resolve

    load_rules.cache_clear()
    unknown_matches = sorted(
        {
            f"{r.id}:{a}"
            for r in load_rules()
            for a in (r.matches.get("algorithm") or [])
            if resolve(a) is None
        }
    )
    assert not unknown_matches, f"rules match on unresolvable algorithms: {unknown_matches}"

    unknown_targets = sorted(
        {
            f"{r.id}:{r.target.get('algorithm')}"
            for r in load_rules()
            if r.target.get("algorithm") and resolve(str(r.target["algorithm"])) is None
        }
    )
    assert not unknown_targets, f"rules target unresolvable algorithms: {unknown_targets}"


def test_every_language_specific_rule_constrains_the_file_suffix() -> None:
    """The exact shape of the `py-rsa-kex-01` / `py-weakhash-01` bug, generalised.

    A rule that names a language without constraining the suffix claims `source_scanner=code`
    assets in EVERY language, and the app then offers that language's codemod for a file it cannot
    transform.
    """
    from qubit_migrate.transform.validate import _NON_CODE_LANGUAGES

    load_rules.cache_clear()
    unguarded = [
        r.id
        for r in load_rules()
        if r.language not in _NON_CODE_LANGUAGES
        and r.language != "multi"
        and not r.matches.get("file_suffix")
    ]
    assert not unguarded, (
        f"these rules name a language but match any file type: {unguarded}. They will claim assets "
        "in other languages and offer a transform that cannot work on them."
    )


# ── Dependency version bumps, per manifest format ────────────────────────────
#
# `_apply_dependency_bump` gated on the filename for three formats and then applied ONE regex —
# pip's `name==version`. Measured: requirements.txt bumped, pom.xml and pyproject.toml never
# changed at all, because a Maven version is its own XML element and a PEP 621 pin lives inside a
# quoted string in an array. The rule claimed three formats and delivered on one; the other two
# answered `422 Codemod produced no change` after the click.
#
# Version floors are verified, not assumed:
#   pyca/cryptography 48      — native ML-KEM + ML-DSA
#   BouncyCastle Java 1.79    — bouncycastle.org release notes
#   BouncyCastle .NET 2.5.0   — bouncycastle.org release notes

_BUMP_CASES = [
    (
        "requirements.txt",
        "cryptography==42.0.8\nPyJWT==2.8.0\n",
        "cryptography>=48.0.0",
    ),
    (
        "pyproject.toml",
        '[project]\ndependencies = ["cryptography==42.0.8", "pyjwt>=2.8"]\n',
        '"cryptography>=48.0.0"',
    ),
    (
        "pom.xml",
        "<project><dependencies><dependency>\n"
        "<groupId>org.bouncycastle</groupId>\n"
        "<artifactId>bcprov-jdk18on</artifactId>\n"
        "<version>1.78</version>\n"
        "</dependency></dependencies></project>\n",
        "<version>1.79</version>",
    ),
    (
        "Billing.csproj",
        "<Project><ItemGroup>\n"
        '  <PackageReference Include="BouncyCastle.Cryptography" Version="2.3.0" />\n'
        '  <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "</ItemGroup></Project>\n",
        'Version="2.5.0"',
    ),
]


@pytest.mark.parametrize(
    ("filename", "source", "expected"), _BUMP_CASES, ids=[c[0] for c in _BUMP_CASES]
)
def test_dependency_bump_understands_each_manifest_format(
    filename: str, source: str, expected: str
) -> None:
    from qubit_migrate.transform.codemods import _apply_dependency_bump

    patched, changed = _apply_dependency_bump(source, filename)
    assert changed, f"{filename} was accepted but produced no change"
    assert expected in patched, f"{filename}: expected {expected!r} in\n{patched}"


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        # Already at or above the floor — the rule only ever raises one.
        ("requirements.txt", "cryptography==49.0.0\n"),
        ("pom.xml", "<artifactId>bcprov-jdk18on</artifactId><version>1.80</version>\n"),
        (
            "Billing.csproj",
            '<PackageReference Include="BouncyCastle.Cryptography" Version="2.6.1" />\n',
        ),
        # A package with no verified floor must never be touched.
        ("requirements.txt", "PyJWT==2.8.0\n"),
        # A version held in a property or MSBuild variable: the real pin is elsewhere in the file,
        # and rewriting the reference would break the build rather than raise the floor.
        ("pom.xml", "<artifactId>bcprov-jdk18on</artifactId><version>${bc.version}</version>\n"),
        (
            "Billing.csproj",
            '<PackageReference Include="BouncyCastle.Cryptography" Version="$(BcVer)" />\n',
        ),
        # A manifest format the codemod does not understand must decline, not guess.
        ("Cargo.toml", 'md-5 = "0.10"\n'),
        ("package.json", '{"dependencies": {"jsonwebtoken": "9.0.0"}}\n'),
    ],
)
def test_dependency_bump_leaves_everything_else_alone(filename: str, source: str) -> None:
    from qubit_migrate.transform.codemods import _apply_dependency_bump

    patched, changed = _apply_dependency_bump(source, filename)
    assert not changed, f"{filename} was modified when it should not have been:\n{patched}"
    assert patched == source
