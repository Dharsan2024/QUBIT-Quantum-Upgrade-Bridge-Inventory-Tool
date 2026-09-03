"""A migration task owns one finding, and its patch must touch one finding.

`_WeakHashTransformer` rewrote every `hashlib.md5`/`hashlib.sha1` in the module. That is the root
cause of the defect `orchestrator._contract_collateral` was written to contain: a patch generated
for finding A carried finding B along with it, including a B the protocol-contract guard had already
refused (`qubit-v2/11-implementation-findings.md` §23).

Containing it was never the fix. Two findings in one file are two tasks with two verdicts, and
bundling them means the only safe outcome is whatever is correct for *both*. On the MediVault twin
that cost a correct migration outright: `cache_key` is an in-process cache key and genuinely
migratable, `note_checksum` three lines above it is a persisted digest that must not change, and one
patch could not be right about both — so `tests` rejected the bundle and the cache key stayed on
MD5.
"""

from __future__ import annotations

import pytest
from qubit_core.schemas import CryptoAsset, Location, QuantumAttack, QuantumVulnerability
from qubit_migrate.transform.libcst_codemods import apply_weakhash_codemod

#: Two MD5 findings in one module with opposite correct dispositions — the twin's own shape.
TWO_FINDINGS = '''import hashlib


def note_checksum(note):
    """Persisted in a column and re-verified on read. MUST NOT change."""
    return hashlib.md5(note.encode()).hexdigest()


def cache_key(a, b):
    """In-process cache key. Free to change."""
    return hashlib.md5(f"{a}:{b}".encode()).hexdigest()
'''

CHECKSUM_LINE = 6
CACHE_KEY_LINE = 11


def _asset(line: int | None, algorithm: str = "MD5") -> CryptoAsset:
    return CryptoAsset(
        source_scanner="code",
        algorithm=algorithm,
        asset_type="algorithm-use",
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        location=Location(file_path="app/services/encounters.py", line=line),
    )


def _changed_lines(original: str, new: str) -> list[int]:
    before, after = original.splitlines(), new.splitlines()
    if len(before) != len(after):
        pytest.fail(f"line count changed {len(before)} -> {len(after)}; positions no longer align")
    return [i for i, (a, b) in enumerate(zip(before, after, strict=True), 1) if a != b]


class TestOnlyTheFindingsOwnLineIsRewritten:
    def test_a_patch_for_the_cache_key_leaves_the_checksum_alone(self) -> None:
        new, changed = apply_weakhash_codemod(TWO_FINDINGS, _asset(CACHE_KEY_LINE))
        assert changed
        assert _changed_lines(TWO_FINDINGS, new) == [CACHE_KEY_LINE]
        assert "hashlib.md5(note.encode())" in new, "the persisted checksum must be untouched"
        assert "hashlib.sha256(f" in new

    def test_a_patch_for_the_checksum_leaves_the_cache_key_alone(self) -> None:
        """The mirror image, so the test cannot pass by rewriting a fixed line."""
        new, changed = apply_weakhash_codemod(TWO_FINDINGS, _asset(CHECKSUM_LINE))
        assert changed
        assert _changed_lines(TWO_FINDINGS, new) == [CHECKSUM_LINE]
        assert "hashlib.sha256(note.encode())" in new
        assert 'hashlib.md5(f"{a}:{b}"' in new, "the cache key belongs to another task"

    def test_a_line_with_no_finding_changes_nothing(self) -> None:
        new, changed = apply_weakhash_codemod(TWO_FINDINGS, _asset(1))
        assert changed is False
        assert new == TWO_FINDINGS


class TestTheFallbackWhenNoLineIsRecorded:
    """Not every scanner records a line, and a codemod that silently becomes a no-op is worse than
    one that is too broad: the task reports `AlreadySatisfied` and parks itself as done, so the
    finding is neither migrated nor reported as unmigrated.

    So `location.line is None` keeps the old whole-file behaviour, deliberately.
    """

    def test_no_line_rewrites_every_occurrence(self) -> None:
        new, changed = apply_weakhash_codemod(TWO_FINDINGS, _asset(None))
        assert changed
        assert _changed_lines(TWO_FINDINGS, new) == [CHECKSUM_LINE, CACHE_KEY_LINE]

    def test_an_asset_with_no_location_at_all_also_falls_back(self) -> None:
        asset = CryptoAsset(
            source_scanner="code",
            algorithm="MD5",
            asset_type="algorithm-use",
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        )
        new, changed = apply_weakhash_codemod(TWO_FINDINGS, asset)
        assert changed
        assert _changed_lines(TWO_FINDINGS, new) == [CHECKSUM_LINE, CACHE_KEY_LINE]


class TestThePasswordPathIsScopedToo:
    """The argon2 branch rewrites more aggressively — it replaces the call AND inserts two
    statements — so it gets its own coverage rather than being assumed to share the guard.
    """

    SOURCE = """import hashlib


def check(username, password):
    return hashlib.sha1(password.encode()).hexdigest()


def etag(body):
    return hashlib.sha1(body).hexdigest()
"""

    def test_only_the_password_line_becomes_argon2(self) -> None:
        new, changed = apply_weakhash_codemod(self.SOURCE, _asset(5, "SHA-1"))
        assert changed
        assert "_ph.hash(password)" in new
        assert "from argon2 import PasswordHasher" in new
        # The ETag two functions down is a different finding and stays as it was.
        assert "hashlib.sha1(body)" in new

    def test_a_syntax_error_is_returned_unchanged(self) -> None:
        broken = "def f(:\n    pass\n"
        new, changed = apply_weakhash_codemod(broken, _asset(1))
        assert changed is False
        assert new == broken
