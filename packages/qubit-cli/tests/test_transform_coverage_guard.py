"""Systemic guard: every vulnerable asset detection can produce must have a migration path.

Detection and migration are separate rule packs that grew at very different rates — 145 detection
rules against 2 transform rules at one point — and nothing connected them. The result was measurable
and bad: a sweep over every detection rule's own positive examples found that only **31%** of the
vulnerable assets QUBIT could FIND had any transform rule that matched. A scanner that reports
a risk it can never remediate is a worse product than one that reports less.

The gaps were systematic rather than random, which is why counting rules never revealed them:

* The LLM rules for key exchange, signatures and ciphers were Python-only, so Go, Java, JS, TS and C
  had no migration for their highest-risk findings at all — only a weak-hash swap.
* Rules listed only SIZED algorithm names (`RSA-2048`), but a keygen call whose size comes from a
  variable normalizes to the bare family (`RSA`), and those assets matched nothing.
* Every HMAC variant was rated quantum-vulnerable, including HS512, so MAC findings had no safe
  target to migrate TO — permanently un-remediable by construction.
* `ssl_ecdh_curve` findings were reported with `usage_context: kex`, but the config rule that
  rewrites that exact directive only matched `tls`.

This test pins the invariant so it cannot silently rot as either pack grows. The corpus is every
detection rule's own positive example, which means it automatically covers any rule added later:
add a detection rule with no migration path and this fails.
"""

from __future__ import annotations

import tempfile
from collections import defaultdict
from pathlib import Path

import pytest
from qubit_migrate.transform.rules import load_rules, match_rule
from qubit_scanner import scan_paths
from qubit_scanner.catalog import RuleCatalog
from qubit_scanner.code import CodeScanner
from qubit_scanner.normalize import normalize

# Detection rule languages -> the file extension the code scanner dispatches on.
_EXT = {
    "python": ".py",
    "go": ".go",
    "java": ".java",
    "javascript": ".js",
    "typescript": ".ts",
    "c": ".c",
    "cpp": ".cpp",
}

# Asset classes no code patch can remediate, with the real-world action each needs instead. They are
# excluded from the coverage requirement deliberately and explicitly, rather than by being quietly
# absent — a certificate is fixed by reissuing it, not by editing a file.
_NOT_CODE_PATCHABLE = {
    "cert": "certificate reissue with a PQC-capable CA",
    "key": "key rotation in the HSM / Vault that holds it",
    "network": "hardening the live server's own config, which the config rules cover",
}


def _code_assets() -> list:
    """Every vulnerable asset the detection catalog's own positive examples produce."""
    catalog = RuleCatalog.load()
    scanner = CodeScanner(catalog)
    tmp = Path(tempfile.mkdtemp(prefix="qubit-cov-"))
    assets = []
    for compiled in catalog.all_rules():
        ext = _EXT.get(compiled.language)
        if ext is None:
            continue
        for i, src in enumerate(compiled.rule.examples.positive):
            path = tmp / f"{compiled.rule.id.replace('/', '_')}_{i}{ext}"
            path.write_text(src, encoding="utf-8")
            try:
                detections = scanner.scan_file(path)
            except Exception:  # a scanner failure is test_rule_examples.py's business, not ours
                continue
            for det in detections:
                asset = normalize(det, occurrence=1)
                if asset.quantum_vulnerable.vulnerable:
                    assets.append((compiled.rule.id, asset))
    return assets


def test_every_vulnerable_code_asset_has_a_migration_path() -> None:
    """The headline invariant: 100% of what detection finds in code must be migratable."""
    load_rules.cache_clear()
    assets = _code_assets()
    assert len(assets) > 100, f"corpus collapsed to {len(assets)} assets — the sweep is not running"

    gaps: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for rule_id, asset in assets:
        if match_rule(asset) is None:
            suffix = Path(asset.location.file_path).suffix
            gaps[(suffix, asset.algorithm, asset.usage_context.value)].add(rule_id)

    assert not gaps, (
        "vulnerable assets with NO transform rule (detection can find them, migration cannot fix "
        f"them): {ldict(gaps)}"
    )


def ldict(gaps: dict) -> str:
    return "; ".join(
        f"{suffix} {alg}/{usage} (from {sorted(rids)[0]})"
        for (suffix, alg, usage), rids in sorted(gaps.items())
    )


def test_every_vulnerable_config_and_manifest_asset_has_a_migration_path(tmp_path: Path) -> None:
    """The same invariant for the non-code scanners. This is where the `ssl_ecdh_curve` gap lived:
    the directive was detected with `usage_context: kex` while the rule that rewrites it matched
    only
    `tls`, so the single most valuable config finding had no migration path."""
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "    ssl_protocols TLSv1 TLSv1.1;\n"
        "    ssl_ciphers ECDHE-RSA-AES128-SHA:DES-CBC3-SHA;\n"
        "    ssl_ecdh_curve prime256v1;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "sshd_config").write_text(
        "Ciphers aes128-cbc,3des-cbc\n"
        "MACs hmac-sha1\n"
        "KexAlgorithms diffie-hellman-group1-sha1\n"
        "HostKeyAlgorithms ssh-rsa\n",
        encoding="utf-8",
    )
    (tmp_path / "httpd.conf").write_text(
        "SSLProtocol all -SSLv2\nSSLCipherSuite HIGH:MEDIUM:RC4\nSSLECDHCurve prime256v1\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.8\n", encoding="utf-8")

    load_rules.cache_clear()
    gaps = [
        (asset.source_scanner.value, asset.algorithm, asset.usage_context.value)
        for asset in scan_paths([tmp_path]).assets
        if asset.quantum_vulnerable.vulnerable
        and asset.source_scanner.value not in _NOT_CODE_PATCHABLE
        and match_rule(asset) is None
    ]
    assert not gaps, f"config/manifest assets with no transform rule: {sorted(set(gaps))}"


@pytest.mark.parametrize("scanner_name,remedy", sorted(_NOT_CODE_PATCHABLE.items()))
def test_non_patchable_classes_are_excluded_on_purpose(scanner_name: str, remedy: str) -> None:
    """Documents WHY the coverage requirement above excludes these, so the exclusion is a stated
    engineering position rather than an unnoticed hole. Each needs an operational action, not a
    patch, and pretending otherwise would mean emitting a diff that cannot fix the finding."""
    assert remedy, scanner_name


def test_hmac_sha2_is_not_reported_as_something_needing_migration() -> None:
    """HMAC-SHA-256/384/512 are quantum-safe: Grover halves symmetric strength and 128 bits survive,
    which is the same reasoning that makes AES-256 and SHA-256 safe in this registry. They were
    rated
    vulnerable, which meant HMAC findings had no safe target to migrate to — the finding could never
    be cleared no matter what the code was changed to."""
    from qubit_core import algorithms

    for name in ("HS256", "HS384", "HS512", "hmac-sha256", "hmac-sha2-512"):
        resolved = algorithms.resolve(name)
        assert resolved is not None, f"{name} does not resolve"
        assert not resolved.vulnerable, f"{name} is rated quantum-vulnerable but is quantum-safe"

    # The genuinely broken ones stay flagged — on the hash, not on Grover.
    for name in ("hmac-sha1", "hmac-md5"):
        resolved = algorithms.resolve(name)
        assert resolved is not None and resolved.vulnerable, f"{name} must stay flagged"
