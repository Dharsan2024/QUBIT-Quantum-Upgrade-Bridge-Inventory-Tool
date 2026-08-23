"""The Python weak-hash codemod must emit a file that still compiles.

The password branch inserts `from argon2 import PasswordHasher` and a module-level hasher. It used
to put both at index 0 — ahead of the module docstring and, fatally, ahead of any
`from __future__ import ...`, which Python requires to be the first statement after the docstring.

Found on the real `requests` checkout: `requests/auth.py` opens with a docstring and
`from __future__ import annotations`, so every generated patch for it failed the compile stage with
"from __future__ imports must occur at the beginning of the file" and the finding could not be
migrated at all. The validation gate caught it, which is the gate working — these tests are so the
codemod stops producing it.
"""

from __future__ import annotations

import ast

import pytest
from qubit_core import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.transform.libcst_codemods import apply_weakhash_codemod


def _password_asset(line: int) -> CryptoAsset:
    """An asset whose surrounding code reads as a password context, which is the branch that
    inserts an import (the SHA-256 branch rewrites in place and needs none)."""
    return CryptoAsset(
        algorithm="MD5",
        usage_context=UsageContext.password,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="auth.py", line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        sensitivity=Sensitivity.credentials,
        evidence=Evidence(snippet="hashlib.md5(password.encode())"),
        discovered_at=utcnow(),
    )


def _migrated(source: str, line: int) -> str:
    new_source, changed = apply_weakhash_codemod(source, _password_asset(line))
    assert changed, "the codemod made no change, so this test would prove nothing"
    return new_source


class TestTheOutputAlwaysParses:
    def test_a_future_import_still_comes_first(self) -> None:
        source = (
            '"""Module docstring."""\n'
            "\n"
            "from __future__ import annotations\n"
            "\n"
            "import hashlib\n"
            "\n"
            "def check(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        )
        migrated = _migrated(source, 8)
        ast.parse(migrated)  # the actual regression: this used to raise SyntaxError

        body = ast.parse(migrated).body
        assert isinstance(body[0], ast.Expr), "the docstring must stay first"
        future = next(
            i
            for i, node in enumerate(body)
            if isinstance(node, ast.ImportFrom) and node.module == "__future__"
        )
        argon2 = next(
            i
            for i, node in enumerate(body)
            if isinstance(node, ast.ImportFrom) and node.module == "argon2"
        )
        assert future < argon2, "the argon2 import was inserted ahead of __future__"

    def test_several_future_imports_are_all_cleared(self) -> None:
        source = (
            "from __future__ import annotations\n"
            "from __future__ import division\n"
            "import hashlib\n"
            "\n"
            "def check(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        )
        ast.parse(_migrated(source, 6))

    def test_a_docstring_with_no_future_import_still_stays_first(self) -> None:
        source = (
            '"""Docs."""\n'
            "import hashlib\n"
            "\n"
            "def check(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        )
        migrated = _migrated(source, 5)
        ast.parse(migrated)
        assert isinstance(ast.parse(migrated).body[0], ast.Expr)

    @pytest.mark.parametrize(
        "prologue",
        ["", '"""Docs."""\n', "from __future__ import annotations\n"],
        ids=["bare", "docstring", "future-only"],
    )
    def test_every_prologue_shape_produces_valid_python(self, prologue: str) -> None:
        source = (
            f"{prologue}import hashlib\n\n"
            "def check(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        )
        ast.parse(_migrated(source, source.count("\n")))


class TestTheArgon2RewriteIsCallable:
    """`PasswordHasher.hash()` returns a `str`. Leaving a `.hexdigest()` on the end produced code
    that parsed, compiled, and raised AttributeError on first use — every rewritten call site on
    the real `requests` tree looked like `hashlib.md5(x).hexdigest()`."""

    def test_hexdigest_is_dropped_not_left_dangling(self) -> None:
        source = (
            "import hashlib\n"
            "\n"
            "def check(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        )
        migrated = _migrated(source, 4)
        ast.parse(migrated)
        assert ".hexdigest()" not in migrated, migrated
        assert "_ph.hash(password)" in migrated, migrated

    def test_a_bare_call_with_no_hexdigest_still_rewrites(self) -> None:
        source = (
            "import hashlib\n"
            "\n"
            "def check(password):\n"
            "    digest = hashlib.md5(password.encode())\n"
            "    return digest\n"
        )
        migrated = _migrated(source, 4)
        ast.parse(migrated)
        assert "_ph.hash(password)" in migrated, migrated
