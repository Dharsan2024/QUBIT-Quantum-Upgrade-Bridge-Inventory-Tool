"""Systemic guard against the single most dangerous failure mode in this scanner.

When a rule emits an algorithm name the canonical registry does not recognise, `normalize()` turns
it into ``UNKNOWN(<name>)`` **with `vulnerable=False`**. That means a detection can fire correctly
and still report genuinely broken cryptography as safe — the finding is present, the verdict is
wrong, and nothing fails. Every instance of this found so far was silent: bare `AES`,
`aes-128-cbc`, `3DES-EDE-CBC`, `hmac-sha1`, `ssh-rsa`, `diffie-hellman-group1-sha1`,
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, and a certificate file PATH used as an algorithm name.

So this asserts the invariant directly: every algorithm any rule can emit as a LITERAL must resolve,
and a realistic mixed corpus must produce no UNKNOWN findings at all.
"""

from __future__ import annotations

from pathlib import Path

from qubit_core import algorithms
from qubit_scanner import RuleCatalog, scan_paths

_UNRESOLVED_ON_PURPOSE = {
    # Rules that legitimately cannot name the algorithm at the call site emit this sentinel: the
    # concrete algorithm lives in a key object or a serialized blob the AST cannot see. Confidence
    # is set to "low" for these and `normalize()` maps the sentinel deliberately.
    "UNRESOLVED",
}


def test_every_literal_algorithm_in_the_catalog_resolves() -> None:
    """A rule with `algorithm: {literal: X}` hard-codes X, so X must be a name the registry knows.
    This is the cheapest possible check and it catches a typo or a new library spelling before it
    can reach an inventory as UNKNOWN(...)-and-not-vulnerable."""
    unresolved: list[str] = []
    for compiled in RuleCatalog.load().all_rules():
        extractor = compiled.rule.extract.get("algorithm")
        if extractor is None or extractor.literal is None:
            continue
        literal = extractor.literal
        if literal in _UNRESOLVED_ON_PURPOSE:
            continue
        if algorithms.resolve(literal) is None:
            unresolved.append(f"{compiled.rule.id} -> {literal!r}")

    assert not unresolved, (
        "These rules emit algorithm names the canonical registry cannot resolve, so their findings "
        "would be reported as UNKNOWN(...) with a NOT-VULNERABLE verdict:\n  "
        + "\n  ".join(sorted(unresolved))
        + "\nAdd the name (or an alias) to qubit_core.algorithms."
    )


def _mixed_corpus(root: Path) -> None:
    """A deliberately broad sample: several languages, a weak TLS config, an SSH config and a
    dependency manifest, so the assertion covers the normalize() path for every scanner source."""
    (root / "app.py").write_text(
        "import hashlib, hmac\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "dsa.generate_private_key(key_size=1024)\n"
        "Cipher(algorithms.AES(k), modes.GCM(i))\n"
        "Cipher(algorithms.TripleDES(k), modes.CBC(i))\n"
        "AESGCM(k)\nChaCha20Poly1305(k)\n"
        "hmac.new(k, m, 'sha256')\n"
        "hashlib.md5(b'')\nhashlib.sha384(b'')\nhashlib.pbkdf2_hmac('sha256', p, s, 1)\n"
        "public_key.encrypt(m, padding.PKCS1v15())\n",
        encoding="utf-8",
    )
    (root / "main.go").write_text(
        'package main\nimport ("crypto/tls";"crypto/rsa";"crypto/aes")\n'
        "var c = &tls.Config{MinVersion: tls.VersionTLS10}\n"
        "func f(k *rsa.PrivateKey) {\n"
        "  aes.NewCipher(key)\n"
        "  rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d)\n"
        "  hmac.New(sha256.New, key)\n"
        "  bcrypt.GenerateFromPassword(pw, 12)\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "svc.c").write_text(
        "#include <openssl/evp.h>\n"
        "void f(void){\n"
        "  EVP_DigestInit_ex(c, EVP_sha1(), NULL);\n"
        "  EVP_EncryptInit_ex(x, EVP_aes_128_cbc(), NULL, k, iv);\n"
        "  EVP_EncryptInit_ex(x, EVP_des_ede3_cbc(), NULL, k, iv);\n"
        "  RSA_generate_key_ex(r, 1024, e, NULL);\n"
        "  SSL_CTX_new(TLSv1_method());\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "sign.ts").write_text(
        "import * as crypto from 'crypto';\n"
        "crypto.createHash('md5');\n"
        "crypto.createCipheriv('aes-128-cbc', k, iv);\n"
        "crypto.createECDH('secp256k1');\n"
        "crypto.createDiffieHellman(1024);\n",
        encoding="utf-8",
    )
    (root / "sshd_config").write_text(
        "Ciphers aes128-cbc,3des-cbc,aes256-gcm@openssh.com\n"
        "MACs hmac-sha1,hmac-sha2-512-etm@openssh.com\n"
        "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256\n"
        "HostKeyAlgorithms ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256\n",
        encoding="utf-8",
    )
    (root / "httpd.conf").write_text(
        "SSLProtocol -all +TLSv1 +TLSv1.2\n"
        "SSLCipherSuite HIGH:!aNULL:!MD5\n"
        "SSLCertificateFile /etc/ssl/certs/server.crt\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("cryptography==49.0.0\nPyJWT==2.8.0\n", encoding="utf-8")


def test_realistic_mixed_corpus_produces_no_unknown_assets(tmp_path: Path) -> None:
    _mixed_corpus(tmp_path)
    result = scan_paths([tmp_path])

    assert result.assets, "corpus produced no findings at all — the guard would be vacuous"
    unknown = sorted(
        {
            f"{a.rule_id}: {a.algorithm}"
            for a in result.assets
            if a.algorithm.startswith("UNKNOWN(")
            and a.algorithm
            != "UNKNOWN(UNRESOLVED)"  # the deliberate sentinel, see module docstring
        }
    )
    assert not unknown, (
        "Findings resolved to UNKNOWN(...), which carries a NOT-VULNERABLE verdict and so hides "
        "real risk:\n  " + "\n  ".join(unknown)
    )
    assert not result.errors, f"scan errors: {result.errors}"


def test_known_weak_algorithms_are_actually_flagged(tmp_path: Path) -> None:
    """The mirror of the UNKNOWN check: resolving is not enough, the VERDICT has to be right. Each
    of these was at some point reported as safe because of a resolution gap."""
    _mixed_corpus(tmp_path)
    result = scan_paths([tmp_path])
    vulnerable = {a.algorithm for a in result.assets if a.quantum_vulnerable.vulnerable}

    for expected in ("MD5", "SHA-1", "3DES", "AES-128", "RSA-1024", "TLSv1.0", "DH-1024-group1"):
        assert expected in vulnerable, (
            f"{expected} was found but NOT marked quantum-vulnerable — "
            f"vulnerable set was {sorted(vulnerable)}"
        )
