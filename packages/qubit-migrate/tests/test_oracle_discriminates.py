"""The metamorphic oracle must be able to FAIL, and on the right things.

`behaves` skipped on 39 of 39 patches before the oracle image and PYTHONPATH became configurable.
It now runs — and a gate that runs and says yes to everything is worth less than one that honestly
skips, because it looks like evidence. These pin what it catches and, just as importantly, what it
does not.

Marked `integration`: they need Docker and a built oracle image.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

REAL = "import hashlib\ndef k(u):\n    return hashlib.sha256(u.encode()).hexdigest()\n"
STUB = (
    "class sha256:\n"
    "    def __init__(self, d=b''): pass\n"
    "    def update(self, d): pass\n"
    "    def hexdigest(self): return 'x' * 64\n"
    "def k(u): return sha256(u.encode()).hexdigest()\n"
)
ALIASED = (
    "import hashlib\nsha256 = hashlib.md5\ndef k(u):\n    return sha256(u.encode()).hexdigest()\n"
)


def _oracle(source: str):
    from qubit_migrate.transform.validate import _image_present, _oracle_image, _run_oracle

    if not _image_present(_oracle_image()):
        pytest.skip(f"oracle image {_oracle_image()} is not built")
    return _run_oracle(source, "SHA-256", "hash", "pure")


class TestItCatchesWhatItClaimsTo:
    def test_a_correct_migration_passes(self) -> None:
        assert _oracle(REAL)["status"] == "pass"

    def test_a_stub_primitive_fails(self) -> None:
        """A class named `sha256` that returns a constant of the right length. It satisfies every
        syntactic gate — the name resolves, the file compiles, the scanner sees SHA-256."""
        assert _oracle(STUB)["status"] == "fail"

    def test_the_strong_name_bound_to_the_weak_algorithm_fails(self) -> None:
        """`sha256 = hashlib.md5`. The patch says SHA-256, `rescan` agrees, and the digest is 32 hex
        characters. This is the case no syntactic gate can distinguish, and the reason the digest-
        length relation exists."""
        verdict = _oracle(ALIASED)
        assert verdict["status"] == "fail"
        assert "digest-length" in str(verdict.get("reason", ""))


class TestTheLimitIsWhereItIsClaimedToBe:
    """The oracle exercises the PRIMITIVE the patch names, not the patched function.

    Asserted rather than left implicit, because the difference is the difference between "the
    migration preserves behaviour" and "the thing the patch installed is a real SHA-256" — and only
    the second is supportable. If a future change makes these fail, the claim in
    `RESULTS-L3-oracle-runs.md` has become stronger and should be rewritten, not quietly widened.
    """

    @pytest.mark.parametrize(
        ("label", "source"),
        [
            (
                "digest truncated by the caller",
                "import hashlib\ndef k(u):\n"
                "    return hashlib.sha256(u.encode()).hexdigest()[:8]\n",
            ),
            (
                "caller ignores its input",
                'import hashlib\ndef k(u):\n    return hashlib.sha256(b"c").hexdigest()\n',
            ),
        ],
    )
    def test_call_site_misuse_is_not_detected(self, label: str, source: str) -> None:
        assert _oracle(source)["status"] == "pass", label
