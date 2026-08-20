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
    _mixed_corpus_extra_languages(root)


def _mixed_corpus_extra_languages(root: Path) -> None:
    """The twelve languages added after the original six.

    Each file is written the way the language's real code is written, not the way its rule
    examples are — the examples are minimal by design, while this corpus is meant to look like
    something a scan would actually meet.
    """
    (root / "Vault.cs").write_text(
        "using System.Security.Cryptography;\n"
        "using System.Net;\n"
        "class Vault {\n"
        "  void Seal(byte[] data, byte[] key) {\n"
        "    var h = MD5.Create();\n"
        "    var c = new TripleDESCryptoServiceProvider();\n"
        "    var r = new RSACryptoServiceProvider(1024);\n"
        "    var m = new HMACMD5(key);\n"
        "    var k = new Rfc2898DeriveBytes(pw, salt, 1000);\n"
        "    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;\n"
        "    var e = ECDsa.Create();\n"
        '    var algo = "MD5";\n'
        "    var byName = HashAlgorithm.Create(algo);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "legacy.php").write_text(
        "<?php\n"
        "function store_password($pw) { return md5($pw); }\n"
        'function seal($d, $k) { return openssl_encrypt($d, "des-ede3-cbc", $k); }\n'
        'function mac($d, $k) { return hash_hmac("sha1", $d, $k); }\n'
        'function token($p, $k) { return JWT::encode($p, $k, "HS256"); }\n'
        'function newkey() { return openssl_pkey_new(array("private_key_bits" => 1024)); }\n'
        "function modern($m, $n, $k) { return sodium_crypto_secretbox($m, $n, $k); }\n"
        "function stored($pw) { return password_hash($pw, PASSWORD_BCRYPT); }\n"
        "function sign($d, &$s, $key) { openssl_sign($d, $s, $key, OPENSSL_ALGO_SHA1); }\n",
        encoding="utf-8",
    )
    (root / "seal.rs").write_text(
        "use md5::Md5;\nuse des::TdesEde3;\nuse openssl::rsa::Rsa;\n"
        "fn seal(key: &[u8]) {\n"
        "  let mut h = Md5::new();\n"
        '  let d = Sha1::digest(b"payload");\n'
        "  let c = TdesEde3::new(&key.into());\n"
        "  let r = Rsa::generate(1024).unwrap();\n"
        "  let m = MessageDigest::md5();\n"
        "  let k = RsaPrivateKey::new(&mut rng, 1024).unwrap();\n"
        "  let dg = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);\n"
        "  let (dk, ek) = MlKem768::generate_keypair(&mut rng);\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "Crypto.kt").write_text(
        "import java.security.MessageDigest\nimport javax.crypto.Cipher\n"
        "fun seal() {\n"
        '  val d = MessageDigest.getInstance("MD5")\n'
        '  val c = Cipher.getInstance("DES/ECB/PKCS5Padding")\n'
        '  val kg = KeyPairGenerator.getInstance("RSA")\n'
        '  val s = Signature.getInstance("SHA1withRSA")\n'
        '  val m = Mac.getInstance("HmacMD5")\n'
        '  val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")\n'
        '  val ctx = SSLContext.getInstance("TLSv1")\n'
        "}\n",
        encoding="utf-8",
    )
    (root / "Ledger.scala").write_text(
        "import java.security.MessageDigest\nimport javax.crypto.Cipher\n"
        "object Ledger {\n"
        "  def seal(): Unit = {\n"
        '    val d = MessageDigest.getInstance("MD5")\n'
        '    val c = Cipher.getInstance("AES/ECB/NoPadding")\n'
        '    val s = Signature.getInstance("SHA1withRSA")\n'
        '    val ctx = SSLContext.getInstance("TLSv1")\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "billing.rb").write_text(
        "require 'openssl'\nrequire 'digest'\nrequire 'jwt'\n"
        "def digest_pw(x) = Digest::MD5.hexdigest(x)\n"
        "def cipher = OpenSSL::Cipher.new('des-ede3-cbc')\n"
        "def key = OpenSSL::PKey::RSA.new(1024)\n"
        "def mac(k, d) = OpenSSL::HMAC.hexdigest('SHA1', k, d)\n"
        "def token(p, k) = JWT.encode(p, k, 'HS256')\n",
        encoding="utf-8",
    )
    (root / "Wallet.swift").write_text(
        "import CryptoKit\nimport CommonCrypto\nimport Security\n"
        "func seal(x: Data) {\n"
        "  let d = Insecure.MD5.hash(data: x)\n"
        "  let s = Insecure.SHA1.hash(data: x)\n"
        "  let g = SHA256.hash(data: x)\n"
        "  CC_MD5(p, l, o)\n"
        "  CCCrypt(op, kCCAlgorithm3DES, opts, kk, kl, iv, i, il, o, ol, m)\n"
        "  let attrs: [String: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA]\n"
        "  c.tlsMinimumSupportedProtocolVersion = .TLSv10\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "fleet.dart").write_text(
        "import 'package:crypto/crypto.dart';\n"
        "import 'package:encrypt/encrypt.dart';\n"
        "void seal(List<int> bytes, Key key) {\n"
        "  var d = md5.convert(bytes);\n"
        "  var s = sha1.convert(bytes);\n"
        "  var h = Hmac(md5, bytes);\n"
        "  var e = Encrypter(AES(key, mode: AESMode.ecb));\n"
        "  var p = RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 64);\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "gateway.cpp").write_text(
        "#include <cryptopp/md5.h>\n#include <botan/hash.h>\n#include <openssl/evp.h>\n"
        "void seal() {\n"
        "  CryptoPP::Weak::MD5 hash;\n"
        "  CryptoPP::DES_EDE3::Encryption enc(key, 24);\n"
        '  auto h = Botan::HashFunction::create("MD5");\n'
        "  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);\n"
        "  cfg.setProtocol(QSsl::TlsV1_0);\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "provision.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        "openssl dgst -md5 release.tar.gz\n"
        "openssl enc -des3 -in backup.sql -out backup.enc\n"
        "openssl genrsa -out server.key 1024\n"
        "openssl req -new -newkey rsa:2048 -nodes -keyout k.pem -out r.csr\n"
        "openssl s_client -connect legacy.internal:443 -tls1\n"
        "ssh-keygen -t rsa -b 1024 -f deploy_key -N ''\n"
        "gpg --cipher-algo 3DES --symmetric archive.tar\n"
        "md5sum artifact.bin\n"
        "curl --tlsv1.0 https://partner.example.com/api\n",
        encoding="utf-8",
    )
    (root / "Provision.ps1").write_text(
        "$md5 = [System.Security.Cryptography.MD5]::Create()\n"
        "Get-FileHash -Algorithm MD5 -Path .\\release.zip\n"
        "$c = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider\n"
        "New-SelfSignedCertificate -DnsName app.local -KeyAlgorithm RSA -KeyLength 1024\n"
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n",
        encoding="utf-8",
    )
    (root / "V3__hash_passwords.sql").write_text(
        "SELECT MD5(password) FROM users;\n"
        "SELECT SHA2(password, 256) FROM users;\n"
        "SELECT PASSWORD('secret');\n"
        "SELECT DES_ENCRYPT(card_number, @key) FROM cards;\n"
        "SELECT AES_ENCRYPT(ssn, @key) FROM staff;\n"
        "SELECT digest(payload, 'md5') FROM events;\n"
        "SELECT hmac(payload, secret, 'sha1') FROM events;\n"
        "SELECT encrypt(ssn, :key, 'des') FROM staff;\n"
        "INSERT INTO u(pw) VALUES (crypt(:pw, gen_salt('md5')));\n"
        "SELECT HASHBYTES('SHA2_256', pw) FROM dbo.Users;\n",
        encoding="utf-8",
    )
    (root / "Component.tsx").write_text(
        "import * as crypto from 'crypto';\n"
        "export const Panel = () => {\n"
        "  crypto.createHash('md5');\n"
        "  crypto.createCipheriv('aes-128-cbc', k, iv);\n"
        "  return <div />;\n"
        "};\n",
        encoding="utf-8",
    )
    # Dependency manifests for the ecosystems the new packs opened up.
    (root / "Cargo.toml").write_text(
        '[package]\nname = "svc"\n[dependencies]\nmd-5 = "0.10"\nrsa = "0.9"\nserde = "1.0"\n',
        encoding="utf-8",
    )
    (root / "composer.json").write_text(
        '{"require": {"firebase/php-jwt": "^6.10", "phpseclib/phpseclib": "^3.0"}}\n',
        encoding="utf-8",
    )
    (root / "Gemfile").write_text(
        "source 'https://rubygems.org'\ngem 'jwt', '~> 2.8'\ngem 'bcrypt', '3.1.20'\n",
        encoding="utf-8",
    )
    (root / "Billing.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />'
        "</ItemGroup></Project>\n",
        encoding="utf-8",
    )


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

    for expected in (
        "MD5",
        "SHA-1",
        "3DES",
        "AES-128",
        "RSA-1024",
        "TLSv1.0",
        "DH-1024-group1",
        # Reachable only through the languages added later — each one is a verdict that was
        # unreachable before because the language itself could not be scanned.
        "DES",  # SQL DES_ENCRYPT, PHP openssl_encrypt, Rust TdesEde3
        "HMAC-MD5",  # .NET HMACMD5, PHP hash_hmac, Kotlin Mac.getInstance
        "RSA",  # shell `ssh-keygen -t rsa`, PowerShell New-SelfSignedCertificate
    ):
        assert expected in vulnerable, (
            f"{expected} was found but NOT marked quantum-vulnerable — "
            f"vulnerable set was {sorted(vulnerable)}"
        )
