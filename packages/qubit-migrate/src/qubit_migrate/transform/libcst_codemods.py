"""libcst-based Python codemods, isolated so libcst is imported only when one actually runs.

`libcst` costs ~0.25s to import, and `_WeakHashTransformer` subclasses `cst.CSTTransformer` at
class scope — so merely importing `transform.codemods` (which the orchestrator, the migrate CLI
sub-app and therefore EVERY `qubit` invocation does) paid for libcst whether a Python codemod ran
or not. That included each rescan subprocess the validator spawns per patch. Splitting the
libcst-dependent code into its own module lets `codemods.py` import it lazily, inside the one
function that needs it, while keeping the transformer at normal module scope here rather than
nested in a function body.
"""

from __future__ import annotations

import libcst as cst
import libcst.matchers as m
from qubit_core import CryptoAsset

from .password_context import is_password_context


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


def apply_weakhash_codemod(source: str, asset: CryptoAsset) -> tuple[str, bool]:
    """Apply weakhash codemod. Returns (new_source, changed)."""
    is_pw = is_password_context(source, asset)
    try:
        tree = cst.parse_module(source)
        transformer = _WeakHashTransformer(is_password_context=is_pw)
        new_tree = tree.visit(transformer)
        return new_tree.code, transformer.changed
    except cst.ParserSyntaxError:
        return source, False
