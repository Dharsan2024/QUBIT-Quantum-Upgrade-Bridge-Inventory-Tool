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

from collections.abc import Sequence

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
        # `hashlib.md5(x).hexdigest()` -> `_ph.hash(x)`, in one step.
        #
        # The inner call is rewritten first (children are visited before parents), so by the time
        # this sees the outer node it reads `_ph.hash(x).hexdigest()` — and argon2's `hash()`
        # returns a `str`, which has no `.hexdigest()`. Left alone the codemod emitted code that
        # parses, compiles, and raises AttributeError the moment it runs. Caught on the real
        # `requests` tree, where every rewritten call site was `hashlib.md5(x).hexdigest()`.
        if m.matches(
            updated_node,
            m.Call(
                func=m.Attribute(
                    value=m.Call(func=m.Attribute(value=m.Name("_ph"), attr=m.Name("hash"))),
                    attr=m.Name("hexdigest"),
                ),
                args=[],
            ),
        ):
            # matcher guarantees func is an Attribute whose value is the `_ph.hash(...)` call
            return updated_node.func.value  # type: ignore[attr-defined,no-any-return]

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
        argon2_import = cst.parse_statement("from argon2 import PasswordHasher\n")
        ph_assign = cst.parse_statement("_ph = PasswordHasher()\n")
        # NOT position 0. Python requires `from __future__` imports to be the first statement after
        # the docstring, so prepending ahead of them produced a file that does not compile --
        # "from __future__ imports must occur at the beginning of the file". Found on the real
        # `requests` tree, where `auth.py` opens with a docstring and `from __future__ import
        # annotations`: the validation gate caught it (compiles: fail) and the finding could not be
        # migrated at all. Insert after the prologue instead.
        at = _prologue_end(updated_node.body)
        body = list(updated_node.body)
        return updated_node.with_changes(body=[*body[:at], argon2_import, ph_assign, *body[at:]])


def _prologue_end(body: Sequence[cst.BaseStatement]) -> int:
    """Index of the first statement a new import may legally precede.

    That is: past a module docstring, and past every `from __future__ import ...`, both of which
    the language pins to the top of the file.
    """
    index = 0
    if body and m.matches(
        body[0],
        m.SimpleStatementLine(body=[m.Expr(value=m.SimpleString())]),
    ):
        index = 1
    while index < len(body) and m.matches(
        body[index],
        m.SimpleStatementLine(body=[m.ImportFrom(module=m.Name("__future__"))]),
    ):
        index += 1
    return index


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
