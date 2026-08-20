"""Deterministic codemods — template transforms, no LLM (doc 03 §6.3).

These handle every transform that can be made SAFELY without a model:

* Python weak-hash swaps via libcst (`weakhash_to_argon2_or_sha256`).
* Non-Python weak-hash swaps via line-scoped token replacement (`weakhash_to_sha256`).
* nginx / Apache / OpenSSH hardening, including the hybrid post-quantum key exchange
  (`harden_tls_config` — see config_codemods.py for why this is the highest-value transform).
* Crypto dependency version bumps that make PQC primitives available (`bump_crypto_dependency`).

Cipher swaps and key-exchange/signature rewrites are deliberately NOT here: changing DES to AES
alters key and IV lengths, and moving RSA key transport to a KEM changes the shape of the protocol,
so both need the LLM path with explicit constraints plus sandbox validation.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from qubit_core import CryptoAsset

from .config_codemods import harden_config_file
from .languages import SUFFIX_TO_LANGUAGE as _SUFFIX_TO_LANGUAGE

# ---------------------------------------------------------------------------
# py-weakhash-01 codemod
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Dependency version bumps (manifest patches)
# ---------------------------------------------------------------------------
# A code patch to ML-KEM is un-appliable if the pinned library predates PQC support, so this runs
# ahead of the structural rewrites: it is the change that makes the PQC primitives available at all.
# Minimum versions come from the same facts recorded in docs/design/07-ecosystem-factcheck.md §10.
_MIN_PQC_VERSIONS: dict[str, str] = {
    "cryptography": "48.0.0",  # pyca/cryptography ships native ML-KEM + ML-DSA from 48
    "bcprov-jdk18on": "1.79",  # BouncyCastle ships ML-KEM/ML-DSA/SLH-DSA from 1.79
}

_PY_PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*(?P<op>==|>=|~=)\s*(?P<ver>[0-9][^\s;#]*)")


def _version_tuple(text: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[._-]", text):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts) or (0,)


def _apply_dependency_bump(source: str, filename: str) -> tuple[str, bool]:
    """Raise a crypto library's pinned version to one that provides PQC primitives.

    Only ever raises a floor, never lowers one — a project already ahead of the minimum is left
    exactly as it is.
    """
    if filename not in ("requirements.txt", "pyproject.toml", "pom.xml"):
        return source, False

    changed = False
    out: list[str] = []
    for line in source.splitlines(keepends=False):
        pin = _PY_PIN_RE.match(line.strip())
        if pin is None:
            out.append(line)
            continue
        name = pin.group("name").lower().replace("_", "-")
        minimum = _MIN_PQC_VERSIONS.get(name)
        if minimum is None or _version_tuple(pin.group("ver")) >= _version_tuple(minimum):
            out.append(line)
            continue
        # `==` is deliberately relaxed to `>=`: pinning exactly would re-freeze the
        # dependency at the very moment the point is to allow the PQC-capable line.
        indent = line[: len(line) - len(line.lstrip())]
        out.append(
            f"{indent}{pin.group('name')}>={minimum}  # QUBIT: version providing PQC primitives"
        )
        changed = True
    return ("\n".join(out) + ("\n" if source.endswith("\n") else ""), changed)


# ---------------------------------------------------------------------------
# Cross-language weak-hash swaps (deterministic token replacement)
# ---------------------------------------------------------------------------
# libcst only understands Python, and importing qubit-scanner's tree-sitter would violate the
# frame's no-cross-package-imports rule. For these languages the edit is a small set of well-known
# tokens, so a textual replacement is both sufficient and safer than a whole-file LLM rewrite: the
# diff is minimal and cannot silently drop code.
#
# Every table was checked against that ecosystem's own reference documentation rather than written
# from memory; the sources are cited per language. The result is also proved mechanically rather
# than by inspection: `test_transform_coverage.py::test_weak_hash_swap_clears_the_finding` runs each
# swap over a real fixture and then rescans the OUTPUT with QUBIT's own scanner, asserting the weak
# algorithm is gone and SHA-256 is present. A swap that produced plausible-but-wrong code is caught
# there, because the scanner reads all 19 of these languages.
#
# Deliberately hash-only. Cipher swaps are NOT safe as token replacements — DES->AES changes key
# length from 8 to 32 bytes and the block size with it, so a naive swap compiles and then throws at
# runtime. Those go to the LLM with explicit key/IV guidance instead.
#
# Entries are (pattern, replacement). A `str` pattern is a literal replacement; a compiled regex is
# used where the edit depends on surrounding tokens — C# needs it because the *declared type* has to
# change with the factory call, or `MD5 h = MD5.Create()` becomes `MD5 h = SHA256.Create()`, which
# does not compile.
#
# Order matters within a table: longer, more specific patterns first, so a short one cannot corrupt
# a longer token that contains it.
_Swap = tuple[str | re.Pattern[str], str]

_HASH_SWAPS: dict[str, tuple[_Swap, ...]] = {
    # https://pkg.go.dev/crypto/sha256
    "go": (
        # crypto.Hash selector, used by rsa.SignPKCS1v15 / ecdsa.SignASN1.
        ("crypto.SHA1", "crypto.SHA256"),
        ("crypto.MD5", "crypto.SHA256"),
        ("md5.New(", "sha256.New("),
        ("md5.Sum(", "sha256.Sum256("),
        ("sha1.New(", "sha256.New("),
        ("sha1.Sum(", "sha256.Sum256("),
        ('"crypto/md5"', '"crypto/sha256"'),
        ('"crypto/sha1"', '"crypto/sha256"'),
    ),
    # https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/MessageDigest.html
    # The standard algorithm name is "SHA-256"; "SHA256" unhyphenated is not a guaranteed alias.
    "java": (
        # JCA standard signature names. "ECDSA" on its own is documented as an ambiguous alias
        # for SHA1withECDSA, so it is spelled out rather than left to the provider.
        ('"SHA1withRSA"', '"SHA256withRSA"'),
        ('"MD5withRSA"', '"SHA256withRSA"'),
        ('"SHA1withECDSA"', '"SHA256withECDSA"'),
        ('"SHA1withDSA"', '"SHA256withDSA"'),
        ('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA-1")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA1")', 'MessageDigest.getInstance("SHA-256")'),
        # Apache Commons Codec — the most common third-party spelling.
        ("DigestUtils.md5Hex(", "DigestUtils.sha256Hex("),
        ("DigestUtils.sha1Hex(", "DigestUtils.sha256Hex("),
        ("DigestUtils.md5(", "DigestUtils.sha256("),
        ("DigestUtils.sha1(", "DigestUtils.sha256("),
    ),
    # https://nodejs.org/api/crypto.html#cryptocreatehashalgorithm-options
    "javascript": (
        ("createHash('md5')", "createHash('sha256')"),
        ('createHash("md5")', 'createHash("sha256")'),
        ("createHash('sha1')", "createHash('sha256')"),
        ('createHash("sha1")', 'createHash("sha256")'),
        # WebCrypto: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
        ("digest('SHA-1'", "digest('SHA-256'"),
        ('digest("SHA-1"', 'digest("SHA-256"'),
    ),
    # https://www.openssl.org/docs/man3.0/man3/EVP_sha256.html
    "c": (
        ("EVP_md5()", "EVP_sha256()"),
        ("EVP_sha1()", "EVP_sha256()"),
    ),
    # C++ adds the Qt, Crypto++ and Botan spellings on top of the OpenSSL ones.
    # https://doc.qt.io/qt-6/qcryptographichash.html  -> QCryptographicHash::Sha256
    # https://cryptopp.com/wiki/SHA2                  -> CryptoPP::SHA256 (MD5 lives in ::Weak)
    # https://botan.randombit.net/handbook/api_ref/hash.html
    "cpp": (
        ("EVP_md5()", "EVP_sha256()"),
        ("EVP_sha1()", "EVP_sha256()"),
        ("QCryptographicHash::Md5", "QCryptographicHash::Sha256"),
        ("QCryptographicHash::Sha1", "QCryptographicHash::Sha256"),
        ("CryptoPP::Weak1::MD5", "CryptoPP::SHA256"),
        ("CryptoPP::Weak::MD5", "CryptoPP::SHA256"),
        ("CryptoPP::SHA1", "CryptoPP::SHA256"),
        ("Weak1::MD5", "SHA256"),
        ("Weak::MD5", "SHA256"),
        ('HashFunction::create_or_throw("MD5")', 'HashFunction::create_or_throw("SHA-256")'),
        ('HashFunction::create_or_throw("SHA-1")', 'HashFunction::create_or_throw("SHA-256")'),
        ('HashFunction::create("MD5")', 'HashFunction::create("SHA-256")'),
        ('HashFunction::create("SHA-1")', 'HashFunction::create("SHA-256")'),
    ),
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256
    # `SHA256.Create()` is the factory, `SHA256.HashData(...)` the one-shot. The declared type has
    # to move with the factory call: `using (MD5 h = MD5.Create())` must become
    # `using (SHA256 h = SHA256.Create())`, so the type position needs a regex.
    "csharp": (
        # Signature digest selector.
        ("HashAlgorithmName.SHA1", "HashAlgorithmName.SHA256"),
        ("HashAlgorithmName.MD5", "HashAlgorithmName.SHA256"),
        (
            re.compile(r"\bnew\s+(?:MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)\s*\(\s*\)"),
            "SHA256.Create()",
        ),
        (re.compile(r"\b(?:MD5|SHA1)\.Create\s*\(\s*\)"), "SHA256.Create()"),
        (re.compile(r"\b(?:MD5|SHA1)\.HashData\s*\("), "SHA256.HashData("),
        # Name-based construction. Only the LITERAL form is swapped:
        # `HashAlgorithm.Create(algo)` where `algo` is a variable holding "MD5" is left alone,
        # because rewriting that variable's initialiser is not safe from one call site — the
        # variable may be read elsewhere. Those findings survive the patch, and the rescan stage
        # then correctly reports it as incomplete rather than claiming the file is clean.
        (re.compile(r'HashAlgorithm\.Create\s*\(\s*"(?:MD5|SHA1)"\s*\)'), "SHA256.Create()"),
        (re.compile(r'CryptoConfig\.CreateFromName\s*\(\s*"(?:MD5|SHA1)"\s*\)'), "SHA256.Create()"),
        (re.compile(r"\b(?:MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)\b"), "SHA256"),
        # Declared-type position: `MD5 hasher`, `SHA1 h`.
        (re.compile(r"\b(?:MD5|SHA1)\b(?=\s+[A-Za-z_])"), "SHA256"),
    ),
    # https://www.php.net/manual/en/function.hash.php
    # `hash(string $algo, string $data, bool $binary = false)`; `md5(string $string,
    # bool $binary = false)`. Rewriting the call head to `hash('sha256', ` therefore preserves an
    # optional second argument exactly: md5($x, true) -> hash('sha256', $x, true).
    "php": (
        # Signature digests. `openssl_sign($d, $s, $k, OPENSSL_ALGO_SHA1)` is a SHA-1 finding
        # with usage_context=signature; the fix is to sign with SHA-256.
        ("OPENSSL_ALGO_SHA1", "OPENSSL_ALGO_SHA256"),
        ("OPENSSL_ALGO_MD5", "OPENSSL_ALGO_SHA256"),
        ("OPENSSL_ALGO_MD4", "OPENSSL_ALGO_SHA256"),
        ("OPENSSL_ALGO_RMD160", "OPENSSL_ALGO_SHA256"),
        ("hash('md5'", "hash('sha256'"),
        ('hash("md5"', 'hash("sha256"'),
        ("hash('sha1'", "hash('sha256'"),
        ('hash("sha1"', 'hash("sha256"'),
        (re.compile(r"\bmd5_file\s*\("), "hash_file('sha256', "),
        (re.compile(r"\bsha1_file\s*\("), "hash_file('sha256', "),
        # Not preceded by -> or :: or $, so a method or property named md5() is left alone.
        (re.compile(r"(?<![>:$\w])md5\s*\("), "hash('sha256', "),
        (re.compile(r"(?<![>:$\w])sha1\s*\("), "hash('sha256', "),
    ),
    # https://docs.ruby-lang.org/en/3.3/Digest.html -> Digest::SHA256
    # `Digest::MD5` is also the tail of `OpenSSL::Digest::MD5`, so one pattern covers both.
    "ruby": (
        ("Digest::MD5", "Digest::SHA256"),
        ("Digest::SHA1", "Digest::SHA256"),
        ("Digest.new('MD5')", "Digest.new('SHA256')"),
        ('Digest.new("MD5")', 'Digest.new("SHA256")'),
        ("Digest.new('SHA1')", "Digest.new('SHA256')"),
        ('Digest.new("SHA1")', 'Digest.new("SHA256")'),
    ),
    # https://docs.rs/sha2  -> use sha2::{Sha256, Digest}; Sha256::new() / Sha256::digest(..)
    # https://docs.rs/md-5  -> crate `md-5`, module `md5`, struct `Md5`
    # This swaps one third-party crate for another, so `sha2` has to be a dependency. Cargo.toml is
    # a different file than the one being patched — see HASH_SWAP_DEPENDENCY_NOTES, which the
    # generated patch carries so the requirement is stated rather than discovered at build time.
    "rust": (
        ("use md5::{Md5, Digest}", "use sha2::{Sha256, Digest}"),
        ("use md5::{Digest, Md5}", "use sha2::{Digest, Sha256}"),
        ("use sha1::{Sha1, Digest}", "use sha2::{Sha256, Digest}"),
        ("use sha1::{Digest, Sha1}", "use sha2::{Digest, Sha256}"),
        ("use md5::Md5", "use sha2::Sha256"),
        ("use sha1::Sha1", "use sha2::Sha256"),
        ("md5::Md5", "sha2::Sha256"),
        ("sha1::Sha1", "sha2::Sha256"),
        # The `openssl` crate names digests through a factory, and `ring` spells SHA-1 with the
        # warning baked into the constant. Both appear in real Rust services; neither was covered
        # until the validator's rescan stage failed on `seal.rs` in the polyglot corpus.
        ("MessageDigest::md5()", "MessageDigest::sha256()"),
        ("MessageDigest::sha1()", "MessageDigest::sha256()"),
        ("digest::SHA1_FOR_LEGACY_USE_ONLY", "digest::SHA256"),
        ("SHA1_FOR_LEGACY_USE_ONLY", "SHA256"),
        ("Md5::new(", "Sha256::new("),
        ("Md5::digest(", "Sha256::digest("),
        ("Sha1::new(", "Sha256::new("),
        ("Sha1::digest(", "Sha256::digest("),
    ),
    # Kotlin and Scala both reach the JCA, so they use Java's standard algorithm names.
    "kotlin": (
        ('"SHA1withRSA"', '"SHA256withRSA"'),
        ('"MD5withRSA"', '"SHA256withRSA"'),
        ('"SHA1withECDSA"', '"SHA256withECDSA"'),
        ('"SHA1withDSA"', '"SHA256withDSA"'),
        ('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA-1")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA1")', 'MessageDigest.getInstance("SHA-256")'),
    ),
    "scala": (
        ('"SHA1withRSA"', '"SHA256withRSA"'),
        ('"MD5withRSA"', '"SHA256withRSA"'),
        ('"SHA1withECDSA"', '"SHA256withECDSA"'),
        ('"SHA1withDSA"', '"SHA256withDSA"'),
        ('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA-1")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA1")', 'MessageDigest.getInstance("SHA-256")'),
    ),
    # https://developer.apple.com/documentation/cryptokit/insecure
    # CryptoKit files MD5/SHA1 under `Insecure`; the secure form drops the prefix entirely.
    # CommonCrypto's digest LENGTH constant must move with the function, or a 32-byte digest is
    # written into a 16/20-byte buffer — a stack overwrite, not a wrong answer. The constants are
    # listed first so the shorter function-name swap cannot corrupt them.
    "swift": (
        # SecKeyAlgorithm signature selectors.
        (".rsaSignatureMessagePKCS1v15SHA1", ".rsaSignatureMessagePKCS1v15SHA256"),
        (".ecdsaSignatureMessageX962SHA1", ".ecdsaSignatureMessageX962SHA256"),
        ("CC_MD5_DIGEST_LENGTH", "CC_SHA256_DIGEST_LENGTH"),
        ("CC_SHA1_DIGEST_LENGTH", "CC_SHA256_DIGEST_LENGTH"),
        ("Insecure.MD5", "SHA256"),
        ("Insecure.SHA1", "SHA256"),
        ("CC_MD5(", "CC_SHA256("),
        ("CC_SHA1(", "CC_SHA256("),
    ),
    # https://pub.dev/packages/crypto -> top-level `sha256` constant, `.convert(bytes)`
    # https://pub.dev/documentation/pointycastle/latest/ -> digests named by string
    "dart": (
        # PointyCastle signers name the digest and the scheme together.
        ("Signer('SHA-1/RSA')", "Signer('SHA-256/RSA')"),
        ('Signer("SHA-1/RSA")', 'Signer("SHA-256/RSA")'),
        ("Signer('MD5/RSA')", "Signer('SHA-256/RSA')"),
        ("md5.convert(", "sha256.convert("),
        ("sha1.convert(", "sha256.convert("),
        ("Digest('MD5')", "Digest('SHA-256')"),
        ('Digest("MD5")', 'Digest("SHA-256")'),
        ("Digest('SHA-1')", "Digest('SHA-256')"),
        ('Digest("SHA-1")', 'Digest("SHA-256")'),
    ),
    # Coreutils / OpenSSL command names. `shasum -a 1` is the macOS spelling.
    "bash": (
        ("openssl dgst -md5", "openssl dgst -sha256"),
        ("openssl dgst -sha1", "openssl dgst -sha256"),
        (re.compile(r"\bopenssl\s+md5\b"), "openssl sha256"),
        (re.compile(r"\bopenssl\s+sha1\b"), "openssl sha256"),
        (re.compile(r"\bmd5sum\b"), "sha256sum"),
        (re.compile(r"\bsha1sum\b"), "sha256sum"),
        (re.compile(r"\bshasum\s+-a\s+1\b"), "shasum -a 256"),
    ),
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
    # PowerShell is case-insensitive, so the parameter match has to be too.
    "powershell": (
        (re.compile(r"-Algorithm\s+(?:MD5|SHA1)\b", re.IGNORECASE), "-Algorithm SHA256"),
        ("[System.Security.Cryptography.MD5]", "[System.Security.Cryptography.SHA256]"),
        ("[System.Security.Cryptography.SHA1]", "[System.Security.Cryptography.SHA256]"),
        ("[Security.Cryptography.MD5]", "[Security.Cryptography.SHA256]"),
        ("[Security.Cryptography.SHA1]", "[Security.Cryptography.SHA256]"),
    ),
    # SQL is dialect-specific, so only forms whose replacement is unambiguous are swapped:
    #   PostgreSQL pgcrypto  digest(data, 'md5')    -> digest(data, 'sha256')
    #   T-SQL                HASHBYTES('MD5', data) -> HASHBYTES('SHA2_256', data)
    # MySQL's `MD5(x)` is deliberately NOT swapped: its replacement `SHA2(x, 256)` changes the
    # call's arity, which a token swap cannot do correctly. Those findings keep no codemod and stay
    # manual, which is the honest outcome — the rule's semantic_note says so.
    "sql": (
        (re.compile(r"(digest\s*\([^,()]*,\s*)'md5'", re.IGNORECASE), r"\1'sha256'"),
        (re.compile(r'(digest\s*\([^,()]*,\s*)"md5"', re.IGNORECASE), r'\1"sha256"'),
        (re.compile(r"(digest\s*\([^,()]*,\s*)'sha1'", re.IGNORECASE), r"\1'sha256'"),
        (re.compile(r"(HASHBYTES\s*\(\s*)'MD5'", re.IGNORECASE), r"\1'SHA2_256'"),
        (re.compile(r'(HASHBYTES\s*\(\s*)"MD5"', re.IGNORECASE), r'\1"SHA2_256"'),
        (re.compile(r"(HASHBYTES\s*\(\s*)'SHA1'", re.IGNORECASE), r"\1'SHA2_256'"),
    ),
}
_HASH_SWAPS["typescript"] = _HASH_SWAPS["javascript"]
_HASH_SWAPS["tsx"] = _HASH_SWAPS["javascript"]

#: Languages whose swap trades one third-party package for a different one, so the source edit is
#: incomplete until the manifest is updated too. Carried on the generated patch rather than left for
#: the build to discover.
HASH_SWAP_DEPENDENCY_NOTES: dict[str, str] = {
    "rust": (
        "Add `sha2` to [dependencies] in Cargo.toml. This swap replaces the `md-5` / `sha1` crates "
        "with `sha2`, which is a different dependency — the edited file will not build until it is "
        "declared."
    ),
}


def _apply_hash_swap(source: str, language: str) -> tuple[str, bool]:
    """Replace weak-hash constructors with SHA-256 for a non-Python language.

    Returns ``(new_source, changed)``. ``changed`` is False when the language has no table *or* when
    nothing matched — the caller turns that into "no patch" rather than an empty diff, which is what
    stops a rule from reporting success on a file it never touched.
    """
    swaps = _HASH_SWAPS.get(language, ())
    if not swaps:
        return source, False
    new_source = source
    for pattern, replacement in swaps:
        if isinstance(pattern, str):
            new_source = new_source.replace(pattern, replacement)
        else:
            new_source = pattern.sub(replacement, new_source)
    return new_source, new_source != source


# ---------------------------------------------------------------------------
# Registry + public API
# ---------------------------------------------------------------------------

# Name -> callable(source, asset, file_path) -> (new_source, changed). Keeping this a real dispatch
# table (rather than the if-chain this used to be) is what lets a new rule ship as YAML + one
# function instead of editing run_codemod every time.
_CODEMOD_REGISTRY: dict[str, str] = {
    "weakhash_to_argon2_or_sha256": "python weak hash -> argon2id (passwords) or SHA-256",
    "weakhash_to_sha256": "non-Python weak hash -> SHA-256 (line-scoped token swap)",
    "harden_tls_config": "nginx/Apache/OpenSSH -> hybrid-PQC, AEAD-only posture",
    "bump_crypto_dependency": "manifest pin -> a version that provides PQC primitives",
}


def run_codemod(
    codemod_name: str,
    asset: CryptoAsset,
    file_path: Path,
    *,
    language: str | None = None,
) -> tuple[str, str] | None:
    """Run a deterministic codemod on ``file_path``.

    Returns (original_source, new_source) or None if codemod not applicable.
    Raises KeyError if codemod name is not registered.
    """
    if codemod_name not in _CODEMOD_REGISTRY:
        raise KeyError(f"Unknown codemod: {codemod_name!r}")

    if codemod_name == "harden_tls_config":
        # Config hardening reads the file itself (format is chosen by name/content).
        return harden_config_file(file_path)

    source = file_path.read_text(encoding="utf-8", errors="replace")

    if codemod_name == "weakhash_to_argon2_or_sha256":
        # Deferred: this is the only codemod needing libcst (~0.25s to import), and importing
        # this module is unavoidable for every `qubit` invocation because the migrate CLI sub-app
        # pulls it in at registration. See transform/libcst_codemods.py.
        from .libcst_codemods import apply_weakhash_codemod

        new_source, changed = apply_weakhash_codemod(source, asset)
    elif codemod_name == "weakhash_to_sha256":
        # Derived from the file extension when not supplied, so callers (the orchestrator) do not
        # need to know the language to run a codemod.
        lang = (language or _SUFFIX_TO_LANGUAGE.get(file_path.suffix.lower(), "")).lower()
        new_source, changed = _apply_hash_swap(source, lang)
    elif codemod_name == "bump_crypto_dependency":
        new_source, changed = _apply_dependency_bump(source, file_path.name.lower())
    else:  # pragma: no cover - registry and dispatch are kept in sync by test_codemod_registry
        return None

    return (source, new_source) if changed else None


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = ["_CODEMOD_REGISTRY", "file_sha256", "run_codemod"]
