"""A rule's `gone`/`weakness_gone` criterion must be able to fail for every algorithm the rule
itself matches. When it cannot -- when the criterion is VACUOUS for some algorithm the rule
claims -- the pre-flight probe in `generate_patch` reads "cannot fail" as "already migrated,"
raises `AlreadySatisfied`, and no model is ever called. A genuinely unmigrated finding is then
recorded as `deferred/satisfied` with nothing having happened.

This is a distinct failure mode from a rule that is simply wrong: the rule LOOKS complete (it
matches the algorithm, it has a target, it has prompt guidance) and silently never fires on a
subset of what it claims to handle. See RESUME.md "BUG 9" and "SYSTEMATIC VACUITY AUDIT" for how
this class was found: audit every rule declaring a `gone` list for algorithms it matches that the
list does not cover, then confirm live impact by calling `_stage_rescan` directly rather than
inferring it from `resolution` state (an earlier attempt at this got the wrong answer that way --
`unresolved`/`ready` is not evidence either way about vacuity).
"""

from __future__ import annotations

from qubit_migrate.transform.rules import load_rules
from qubit_migrate.transform.validate import _stage_rescan


class TestPyRsaKexGonePrefix:
    """`py-rsa-kex-01` declared `gone: algorithm_prefix: ["RSA-"]`. `"RSA".startswith("RSA-")`
    is False, so a file whose ONLY RSA usage the scanner resolves to bare `RSA` -- the key comes
    from a variable rather than a literal, exactly `wrap_data_key`/`unwrap_data_key`'s shape --
    could never fail this criterion. Live in the corpus only when a `.py` file's RSA is ALL
    size-less (verified: none in this corpus qualify, so the fix recovers no round-4 migration,
    but the defect is real and reproducible on the shape below).
    """

    SOURCE = (
        "from cryptography.hazmat.primitives import hashes\n"
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
        "\n"
        "def wrap_data_key(public_key, data_key):\n"
        '    """Wrap the per-referral data key for transport."""\n'
        "    return public_key.encrypt(\n"
        "        data_key,\n"
        "        padding.OAEP(\n"
        "            mgf=padding.MGF1(algorithm=hashes.SHA256()),\n"
        "            algorithm=hashes.SHA256(),\n"
        "            label=None,\n"
        "        ),\n"
        "    )\n"
    )

    def test_bare_rsa_is_not_vacuously_satisfied(self) -> None:
        rule = next(r for r in load_rules() if r.id == "py-rsa-kex-01")

        result = _stage_rescan(
            self.SOURCE,
            rule,
            "python",
            asset_algorithm="RSA",
            original_source=self.SOURCE,
            asset_line=6,
            target_rel_path="k.py",
        )

        assert not getattr(result, "vacuous", False), (
            f"criterion should be failable for bare RSA; got vacuous with detail: {result.detail}"
        )

    def test_a_sized_rsa_finding_is_unaffected(self) -> None:
        """Regression guard: RSA-2048 already worked before this fix and must still work after."""
        source = self.SOURCE.replace("public_key.encrypt", "public_key.encrypt  # RSA-2048")
        rule = next(r for r in load_rules() if r.id == "py-rsa-kex-01")

        result = _stage_rescan(
            source,
            rule,
            "python",
            asset_algorithm="RSA-2048",
            original_source=source,
            asset_line=6,
            target_rel_path="k.py",
        )

        assert not getattr(result, "vacuous", False)
