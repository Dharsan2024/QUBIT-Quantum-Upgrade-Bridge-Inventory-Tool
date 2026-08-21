"""A migration task owns ONE finding, and must be judged on that one.

One file routinely holds several findings of the SAME algorithm, each planned as its own task. The
polyglot corpus has three MD5 findings in `V3__hash_passwords.sql` — MySQL's `MD5(password)` on
line 1, pgcrypto's `digest(payload,'md5')` on line 6, and `gen_salt('md5')` on line 9 — and two in
`Vault.cs`, on lines 5 and 13.

Exactly one of the three SQL occurrences is expressible as a token swap. MySQL's `MD5(x)` is
excluded by design because its replacement changes the call's arity, and `gen_salt` is a salt
generator rather than a digest. So the rescan's question — "is MD5 gone from this file?" — could
not be answered yes by any patch, and ALL THREE tasks failed validation, including the one whose
own occurrence had been migrated correctly. Six of the corpus's six validation failures were this.

Two changes, pinned here:

* the rescan asks whether THIS finding went away, exactly when the patch preserved the line count
  and by occurrence count when it did not; and
* a codemod whose edits never touch the flagged line reports that instead of recording someone
  else's rewrite as this task's patch.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.orchestrator import _flagged_line_untouched
from qubit_migrate.transform.codemods import run_codemod
from qubit_migrate.transform.rules import load_rules, match_rule
from qubit_migrate.transform.validate import _stage_rescan

# Three MD5 findings; only the pgcrypto `digest(...)` on line 6 is a token swap.
SQL = (
    "SELECT MD5(password) FROM users;\n"
    "SELECT SHA2(password, 256) FROM users;\n"
    "SELECT PASSWORD('secret');\n"
    "SELECT DES_ENCRYPT(card_number, @key) FROM cards;\n"
    "SELECT AES_ENCRYPT(ssn, @key) FROM staff;\n"
    "SELECT digest(payload, 'md5') FROM events;\n"
    "SELECT hmac(payload, secret, 'sha1') FROM events;\n"
    "SELECT encrypt(ssn, :key, 'des') FROM staff;\n"
    "INSERT INTO u(pw) VALUES (crypt(:pw, gen_salt('md5')));\n"
    "SELECT HASHBYTES('SHA2_256', pw) FROM dbo.Users;\n"
)


def _asset(line: int, algorithm: str = "MD5", path: str = "V3__hash_passwords.sql") -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=False, attack=QuantumAttack.grover),
        evidence=Evidence(),
        discovered_at=utcnow(),
    )


def _sql_rule():  # type: ignore[no-untyped-def]
    rule = match_rule(_asset(6), load_rules())
    assert rule is not None, "no migration rule matches an MD5 finding in .sql"
    return rule


@pytest.fixture
def patched(tmp_path: Path) -> tuple[str, str]:
    """The codemod's real output for this file, generated once."""
    target = tmp_path / "V3__hash_passwords.sql"
    target.write_text(SQL, encoding="utf-8")
    rule = _sql_rule()
    assert rule.codemod
    result = run_codemod(rule.codemod, _asset(6, path=str(target)), target)
    assert result, "the pgcrypto digest() call is expressible; the codemod must produce a change"
    return result


class TestRescanJudgesTheFlaggedOccurrence:
    def test_the_expressible_occurrence_passes(self, patched: tuple[str, str]) -> None:
        orig, new = patched
        result = _stage_rescan(new, _sql_rule(), "sql", "MD5", original_source=orig, asset_line=6)
        assert result.status != "fail", (
            f"line 6 IS the occurrence this patch migrated: {result.detail}"
        )

    @pytest.mark.parametrize("line", [1, 9])
    def test_an_occurrence_the_patch_did_not_reach_still_fails(
        self, patched: tuple[str, str], line: int
    ) -> None:
        """The check must not become a rubber stamp: other MD5s are other tasks, not this one."""
        orig, new = patched
        result = _stage_rescan(
            new, _sql_rule(), "sql", "MD5", original_source=orig, asset_line=line
        )
        assert result.status == "fail"
        assert str(line) in result.detail, f"the failure must name the line: {result.detail}"

    def test_without_a_line_the_whole_file_rule_still_applies(
        self, patched: tuple[str, str]
    ) -> None:
        """No occurrence info and no baseline is no licence to pass something unchecked."""
        _, new = patched
        result = _stage_rescan(new, _sql_rule(), "sql", "MD5")
        assert result.status == "fail"

    def test_a_rewrite_that_changed_nothing_is_rejected_by_count(self) -> None:
        """When lines moved, the fallback is occurrence count — and an unchanged file removes none.

        This is the case that catches a model "migrating" RSA-1024 to RSA-2048: same count, still
        vulnerable, correctly refused.
        """
        moved = SQL + "-- a trailing comment moves nothing but changes the line count\n"
        result = _stage_rescan(moved, _sql_rule(), "sql", "MD5", original_source=SQL, asset_line=6)
        assert result.status == "fail"
        assert "removed none of it" in result.detail

    def test_a_clean_flagged_line_is_not_enough_on_its_own(self) -> None:
        """A rewrite that MOVES the algorithm clears the flagged line and fixes nothing.

        The line check answers "is it still here?"; only the count answers "did this patch remove
        one?". Requiring just the first would accept a patch that shuffled the file.
        """
        lines = SQL.splitlines()
        # Take the MD5 off line 6 and put an equivalent one on a line that had no finding.
        lines[5] = "SELECT 1 FROM events;"
        lines[9] = "SELECT digest(payload, 'md5') FROM events;"
        shuffled = "\n".join(lines) + "\n"
        result = _stage_rescan(
            shuffled, _sql_rule(), "sql", "MD5", original_source=SQL, asset_line=6
        )
        assert result.status == "fail", (
            "line 6 is clean, but the same three MD5 findings are still in the file — accepting "
            "this would let a shuffle count as a migration"
        )
        assert "removed none of it" in result.detail


class TestACodemodMustTouchTheLineItClaims:
    def test_an_untouched_flagged_line_is_reported(self, patched: tuple[str, str]) -> None:
        orig, new = patched
        reason = _flagged_line_untouched(orig, new, _asset(1))
        assert reason is not None, (
            "the codemod rewrote line 6, not line 1 — recording that as line 1's patch is how "
            "two tasks came to own a rewrite that does not address them"
        )
        assert "line 1" in reason
        assert "advice" in reason

    def test_the_line_the_codemod_did_rewrite_is_accepted(self, patched: tuple[str, str]) -> None:
        orig, new = patched
        assert _flagged_line_untouched(orig, new, _asset(6)) is None

    def test_a_codemod_that_changed_nothing_is_not_blamed(self) -> None:
        """ "No change at all" has its own, more accurate message upstream; do not shadow it."""
        assert _flagged_line_untouched(SQL, SQL, _asset(1)) is None

    def test_a_line_count_change_disables_the_check(self) -> None:
        """Line numbers stop corresponding, so the rescan's occurrence check takes over instead."""
        assert _flagged_line_untouched(SQL, SQL + "SELECT 1;\n", _asset(1)) is None

    def test_an_asset_with_no_location_is_not_blamed(self) -> None:
        asset = _asset(1)
        asset.location = None
        assert _flagged_line_untouched(SQL, SQL.replace("digest", "DIGEST"), asset) is None
