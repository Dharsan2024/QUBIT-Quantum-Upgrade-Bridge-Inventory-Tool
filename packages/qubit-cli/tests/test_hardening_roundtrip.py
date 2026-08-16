"""Round-trip guard: what the hardening codemods WRITE must be what the scanner UNDERSTANDS.

`test_no_silent_unknowns.py` asserts that every algorithm a detection rule can emit as a literal
resolves in the canonical registry. That closed one half of the loop and left the other half open,
and a real bug lived in the gap: the SSH codemod writes `sntrup761x25519-sha512@openssh.com` — the
post-quantum hybrid key exchange that is the entire point of the transform — and the registry did
not know that name. So a freshly hardened `sshd_config` rescanned with its strongest algorithm
reported as `UNKNOWN(...)`, which `normalize()` marks `vulnerable=False`: the migration looked like
it had succeeded while producing an inventory that could not show it had landed on anything PQC.

The generalisable point is that remediation output is scanner INPUT. These tests therefore run the
real pipeline both ways — harden a weak config, scan the result, and assert on the verdicts — rather
than checking codemod output as text. Only this direction can catch a name the writer and the reader
disagree about.

The two properties asserted are the two claims QUBIT makes to a user who runs a migration:
1. Nothing in a hardened config is unrecognised (no silent `UNKNOWN(...)`-and-not-vulnerable).
2. The hardened config actually contains a post-quantum algorithm the risk engine can see as safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_core import algorithms
from qubit_migrate.transform.config_codemods import harden_apache, harden_nginx, harden_ssh
from qubit_scanner import scan_paths

# Deliberately awful starting points, in the spellings really found in the wild.
_WEAK_NGINX = """server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-MD5;
    ssl_certificate /etc/nginx/certs/server.crt;
}
"""

_WEAK_SSHD = """Ciphers aes128-cbc,3des-cbc
MACs hmac-sha1,hmac-md5
KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
HostKeyAlgorithms ssh-rsa,ssh-dss
"""

_WEAK_APACHE = """SSLProtocol all -SSLv2
SSLCipherSuite HIGH:MEDIUM:!aNULL:RC4
"""


def _harden(source: str, filename: str) -> str:
    """Route to the right codemod the way the transform layer does, by config flavour."""
    if filename == "nginx.conf":
        hardened, changed = harden_nginx(source)
    elif filename == "sshd_config":
        hardened, changed = harden_ssh(source)
    else:
        hardened, changed = harden_apache(source)
    assert changed, f"{filename} was already considered hardened — fixture is not weak enough"
    return hardened


@pytest.mark.parametrize(
    "filename,source",
    [
        ("nginx.conf", _WEAK_NGINX),
        ("sshd_config", _WEAK_SSHD),
        ("httpd.conf", _WEAK_APACHE),
    ],
)
def test_hardened_config_contains_no_unrecognised_algorithm(
    filename: str, source: str, tmp_path: Path
) -> None:
    """The failure this exists for: hardening writes a modern algorithm name, the registry has never
    heard of it, and the rescan silently calls it not-vulnerable."""
    (tmp_path / filename).write_text(_harden(source, filename), encoding="utf-8")

    assets = scan_paths([tmp_path]).assets
    assert assets, f"scanner found nothing at all in a hardened {filename}"

    unknown = sorted({a.algorithm for a in assets if a.algorithm.startswith("UNKNOWN(")})
    assert not unknown, (
        f"hardened {filename} contains algorithms the registry does not recognise: {unknown}. "
        "These are reported as NOT vulnerable, so the remediated config would silently look clean."
    )


@pytest.mark.parametrize(
    "filename,source,expected_pqc",
    [
        ("nginx.conf", _WEAK_NGINX, "X25519MLKEM768"),
        ("sshd_config", _WEAK_SSHD, "sntrup761x25519-sha512"),
        ("httpd.conf", _WEAK_APACHE, "X25519MLKEM768"),
    ],
)
def test_hardening_lands_on_a_post_quantum_algorithm_the_engine_can_see(
    filename: str, source: str, expected_pqc: str, tmp_path: Path
) -> None:
    """Writing the directive is not the deliverable — the deliverable is an inventory that shows the
    deployment is now quantum-safe. That requires the canonical registry to resolve the new name AND
    to class it as not Shor/Grover-breakable."""
    resolved = algorithms.resolve(expected_pqc)
    assert resolved is not None, f"{expected_pqc} does not resolve in the canonical registry"
    assert not resolved.vulnerable, (
        f"{expected_pqc} is the post-quantum target of a transform but the registry rates it "
        "quantum-vulnerable"
    )

    (tmp_path / filename).write_text(_harden(source, filename), encoding="utf-8")
    assets = scan_paths([tmp_path]).assets

    safe = {a.algorithm for a in assets if not a.quantum_vulnerable.vulnerable}
    assert resolved.canonical in safe, (
        f"hardened {filename} does not yield a quantum-safe {resolved.canonical} asset on rescan; "
        f"safe algorithms found were {sorted(safe)}"
    )


def test_deprecated_ssh_rsa_is_not_conflated_with_the_sha2_variants() -> None:
    """`ssh-rsa` means RSA-with-SHA-1, deprecated by OpenSSH 8.8+. `rsa-sha2-256/512` are the
    recommended replacements. They were aliased onto one canonical entry, so hardening a config —
    which swaps exactly one for the other — left `ssh-rsa` still apparently present and made the
    remediation look like it had achieved nothing. Both are still RSA and so still Shor-breakable;
    that shared verdict is correct and is not what this asserts."""
    deprecated = algorithms.resolve("ssh-rsa")
    modern = algorithms.resolve("rsa-sha2-512")
    assert deprecated is not None and modern is not None
    assert deprecated.canonical != modern.canonical, (
        "ssh-rsa and rsa-sha2-512 share a canonical name, so a rescan cannot tell a hardened "
        "sshd_config from a vulnerable one"
    )
    # Honest verdict: swapping the signature hash does not escape Shor. Only the key type does.
    assert modern.vulnerable


def test_hardened_ssh_no_longer_reports_the_deprecated_host_key(tmp_path: Path) -> None:
    """End-to-end form of the above, through the real scanner."""
    (tmp_path / "sshd_config").write_text(_harden(_WEAK_SSHD, "sshd_config"), encoding="utf-8")
    found = {a.algorithm for a in scan_paths([tmp_path]).assets}
    assert "ssh-rsa" not in found, f"deprecated ssh-rsa survived hardening; found {sorted(found)}"
