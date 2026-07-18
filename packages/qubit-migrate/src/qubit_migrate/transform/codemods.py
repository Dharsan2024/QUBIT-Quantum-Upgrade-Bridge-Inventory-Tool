"""Deterministic libcst codemods — template transforms (no LLM) (doc 03 §6.3).

M1 implements: weakhash_to_argon2_or_sha256 (py-weakhash-01).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import libcst as cst
import libcst.matchers as m
from qubit_core import CryptoAsset

# ---------------------------------------------------------------------------
# py-weakhash-01 codemod
# ---------------------------------------------------------------------------


class _WeakHashTransformer(cst.CSTTransformer):
    """Replace hashlib.md5 / hashlib.sha1 password usage with argon2id.

    Heuristic: if the surrounding code context contains password-like
    identifiers, replace with argon2. Otherwise replace with hashlib.sha256.
    """

    def __init__(self, is_password_context: bool = False) -> None:
        super().__init__()
        self.is_password_context = is_password_context
        self.changed = False
        self._needs_argon2_import = False
        self._needs_sha256_comment = False

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.BaseExpression:
        # Match: hashlib.md5(...) or hashlib.sha1(...)
        if m.matches(
            updated_node,
            m.Call(
                func=m.Attribute(
                    value=m.Name("hashlib"),
                    attr=m.OneOf(m.Name("md5"), m.Name("sha1")),
                )
            ),
        ):
            self.changed = True
            if self.is_password_context:
                self._needs_argon2_import = True
                # Replace with _ph.hash(arg)
                args = updated_node.args
                if args:
                    # Extract the first argument
                    inner = args[0].value
                    # If .encode() call present, strip it
                    if m.matches(inner, m.Call(func=m.Attribute(attr=m.Name("encode")))):
                        # matcher guarantees inner is a Call whose func is an Attribute
                        inner = inner.func.value  # type: ignore[attr-defined]
                    return cst.parse_expression(
                        f"_ph.hash({cst.parse_module('').code_for_node(inner)})"
                    )  # type: ignore[arg-type]
            else:
                self._needs_sha256_comment = True
                # Replace hashlib.md5/sha1 with hashlib.sha256
                return updated_node.with_changes(
                    func=cst.Attribute(
                        value=cst.Name("hashlib"),
                        attr=cst.Name("sha256"),
                    )
                )
        return updated_node

    def leave_Module(self, original_node: cst.Module, updated_node: cst.Module) -> cst.Module:
        if not self._needs_argon2_import:
            return updated_node
        # Prepend argon2 import + _ph = PasswordHasher()
        argon2_import = cst.parse_statement("from argon2 import PasswordHasher\n")
        ph_assign = cst.parse_statement("_ph = PasswordHasher()\n")
        return updated_node.with_changes(body=[argon2_import, ph_assign, *updated_node.body])


def _is_password_context(source: str, asset: CryptoAsset) -> bool:
    """Heuristic: is this a password-hashing context?"""
    password_indicators = re.compile(
        r"\b(password|passwd|pw\b|hash_?password|store_?pass|check_?pass"
        r"|verify_?pass|auth|credential|login)\b",
        re.IGNORECASE,
    )
    if password_indicators.search(source):
        return True
    return bool(asset.usage_context and "password" in asset.usage_context.value.lower())


def _apply_weakhash_codemod(source: str, asset: CryptoAsset) -> tuple[str, bool]:
    """Apply weakhash codemod. Returns (new_source, changed)."""
    is_pw = _is_password_context(source, asset)
    try:
        tree = cst.parse_module(source)
        transformer = _WeakHashTransformer(is_password_context=is_pw)
        new_tree = tree.visit(transformer)
        return new_tree.code, transformer.changed
    except cst.ParserSyntaxError:
        return source, False


# ---------------------------------------------------------------------------
# Registry + public API
# ---------------------------------------------------------------------------

_CODEMOD_REGISTRY: dict[str, type] = {
    "weakhash_to_argon2_or_sha256": _WeakHashTransformer,
}


def run_codemod(
    codemod_name: str,
    asset: CryptoAsset,
    file_path: Path,
) -> tuple[str, str] | None:
    """Run a deterministic codemod on ``file_path``.

    Returns (original_source, new_source) or None if codemod not applicable.
    Raises KeyError if codemod name is not registered.
    """
    if codemod_name not in _CODEMOD_REGISTRY:
        raise KeyError(f"Unknown codemod: {codemod_name!r}")

    source = file_path.read_text(encoding="utf-8", errors="replace")

    if codemod_name == "weakhash_to_argon2_or_sha256":
        new_source, changed = _apply_weakhash_codemod(source, asset)
        if not changed:
            return None
        return source, new_source

    return None


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = ["_CODEMOD_REGISTRY", "file_sha256", "run_codemod"]
