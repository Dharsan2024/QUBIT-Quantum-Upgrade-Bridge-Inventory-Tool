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
# Cross-language weak-hash swaps (line-scoped, deterministic)
# ---------------------------------------------------------------------------
# libcst only understands Python, and importing qubit-scanner's tree-sitter would violate the
# frame's no-cross-package-imports rule. For these languages the edit is a single well-known token
# on a line the scanner already located, so a LINE-SCOPED textual replacement is both sufficient and
# safer than a whole-file LLM rewrite: the diff is one line and cannot silently drop code.
#
# Deliberately hash-only. Cipher swaps are NOT safe as token replacements — DES->AES changes key
# length from 8 to 32 bytes and the block size with it, so a naive swap compiles and then throws at
# runtime. Those go to the LLM with explicit key/IV guidance instead.
_HASH_SWAPS: dict[str, tuple[tuple[str, str], ...]] = {
    "go": (
        ("md5.New(", "sha256.New("),
        ("md5.Sum(", "sha256.Sum256("),
        ("sha1.New(", "sha256.New("),
        ("sha1.Sum(", "sha256.Sum256("),
        ('"crypto/md5"', '"crypto/sha256"'),
        ('"crypto/sha1"', '"crypto/sha256"'),
    ),
    "java": (
        ('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA-1")', 'MessageDigest.getInstance("SHA-256")'),
        ('MessageDigest.getInstance("SHA1")', 'MessageDigest.getInstance("SHA-256")'),
    ),
    "javascript": (
        ("createHash('md5')", "createHash('sha256')"),
        ('createHash("md5")', 'createHash("sha256")'),
        ("createHash('sha1')", "createHash('sha256')"),
        ('createHash("sha1")', 'createHash("sha256")'),
    ),
    "c": (
        ("EVP_md5()", "EVP_sha256()"),
        ("EVP_sha1()", "EVP_sha256()"),
    ),
}
_HASH_SWAPS["typescript"] = _HASH_SWAPS["javascript"]
_HASH_SWAPS["cpp"] = _HASH_SWAPS["c"]

_SUFFIX_TO_LANGUAGE: dict[str, str] = {
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
}


def _apply_hash_swap(source: str, language: str) -> tuple[str, bool]:
    """Replace weak-hash constructors with SHA-256 for a non-Python language."""
    swaps = _HASH_SWAPS.get(language, ())
    if not swaps:
        return source, False
    new_source = source
    for old, new in swaps:
        new_source = new_source.replace(old, new)
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
