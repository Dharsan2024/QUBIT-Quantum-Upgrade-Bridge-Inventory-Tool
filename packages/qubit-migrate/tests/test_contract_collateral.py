"""A refusal must survive another finding's patch to the same file.

`external_contract` runs once per finding, before generation. That leaves a hole a file-scoped
codemod walks straight through: the guard refuses finding B, and the patch generated for finding A
in the same file rewrites B anyway. The refusal is recorded, the advice is written, and the change
still happens.

Found on the MediVault twin, not by reasoning about it. `documents.py` holds two SHA-1 findings:
`document_fingerprint`, which is migratable, and `archive_entry_id`, which the guard refuses on
`sha1_hash = hashlib.sha1(`. A `template` run rewrote both, the second task reported *"already
migrated by an earlier py-weakhash-01 patch to this file"* and parked itself as satisfied, and the
application's own suite caught it three tests later. Every gate in the pipeline had passed.
"""

from __future__ import annotations

from qubit_core.schemas import (
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
)
from qubit_migrate.orchestrator import _contract_collateral

#: The two-finding file, reduced to what matters. Line 5 is migratable; line 9 is not.
ORIGINAL = """import hashlib


def document_fingerprint(body: bytes) -> str:
    return hashlib.sha1(body).hexdigest()


def archive_entry_id(body: bytes) -> str:
    sha1_hash = hashlib.sha1()
    sha1_hash.update(body)
    return sha1_hash.hexdigest()
"""

#: What the file-scoped codemod actually produced: both occurrences swapped.
BOTH = ORIGINAL.replace("hashlib.sha1(", "hashlib.sha256(")

#: What a line-scoped patch for the same finding would produce.
ONLY_MINE = ORIGINAL.replace(
    "    return hashlib.sha1(body).hexdigest()", "    return hashlib.sha256(body).hexdigest()"
)

#: A finding whose refusal signal is on the line BELOW it, which is the normal shape for a wire
#: format: the algorithm is chosen on one line and named on the next.
#:
#: `_KEY` rather than `SECRET` deliberately — a credential-looking name would make
#: `_CREDENTIAL_DIGEST` match the bare line, and then this fixture would not test the window at
#: all. It is the `sha1=` prefix two lines down that has to be reached.
WINDOWED = """import hashlib
import hmac

_KEY = b"placeholder"


def digest_body(body: bytes) -> str:
    return hashlib.sha1(body).hexdigest()


def sign_for_the_insurer(payload: bytes) -> str:
    mac = hmac.new(_KEY, payload, hashlib.sha1)
    return f"sha1={mac.hexdigest()}"
"""

WINDOWED_BOTH = WINDOWED.replace("hashlib.sha1", "hashlib.sha256")

#: Only line 12 changed — the finding's own line, and a protocol-mandated one.
WINDOWED_OWN_LINE = WINDOWED.replace(
    "    mac = hmac.new(_KEY, payload, hashlib.sha1)",
    "    mac = hmac.new(_KEY, payload, hashlib.sha256)",
)


def _asset(line: int | None) -> CryptoAsset:
    return CryptoAsset(
        source_scanner="code",
        algorithm="SHA-1",
        asset_type="algorithm-use",
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        location=Location(file_path="app/services/documents.py", line=line),
    )


class TestTheCollateralIsCaught:
    def test_a_patch_that_also_rewrites_a_refused_line_is_rejected(self) -> None:
        reason = _contract_collateral(ORIGINAL, BOTH, _asset(5))
        assert reason is not None
        assert "line 9" in reason
        assert "sha1_hash = hashlib.sha1(" in reason

    def test_a_patch_scoped_to_its_own_finding_is_allowed(self) -> None:
        """The control. Without this the check could pass by rejecting everything.

        Also what makes removing the own-line exemption safe: line 5 is judged like any other, and
        a migratable finding stays migratable.
        """
        assert _contract_collateral(ORIGINAL, ONLY_MINE, _asset(5)) is None

    def test_the_signal_may_be_on_a_NEIGHBOURING_line(self) -> None:
        """The reason the check reads a window rather than the changed line alone.

        `mac = hmac.new(_KEY, payload, hashlib.sha1)` names no algorithm and holds no credential;
        on its own it looks migratable. The `sha1=` two lines down is the insurer's wire format,
        and it is the only evidence that this hash is not ours to change.
        """
        reason = _contract_collateral(WINDOWED, WINDOWED_BOTH, _asset(8))
        assert reason is not None
        assert "line 12" in reason
        assert "sha1=" in reason

    def test_the_findings_OWN_line_is_judged_too(self) -> None:
        """Why there is no own-line exemption.

        The pre-generation guard reads `asset.evidence.snippet` — recorded at scan time, redacted
        before storage, and empty for some scanners. This reads the file as it is now. Where they
        agree the guard already refused and generation never started, so judging the line again
        costs nothing; where they disagree, this is the only thing standing between a refused
        finding and a patch. Exempting the line would trade a real catch for no benefit.
        """
        reason = _contract_collateral(WINDOWED, WINDOWED_OWN_LINE, _asset(12))
        assert reason is not None
        assert "line 12" in reason

    def test_a_bare_line_check_would_not_be_enough(self) -> None:
        """States the negative directly, so the test above cannot pass for the wrong reason."""
        from qubit_migrate.protocol_contract import external_contract

        bare = "    mac = hmac.new(_KEY, payload, hashlib.sha1)"
        assert external_contract("SHA-1", "app/x.py", bare) is None

    def test_an_unchanged_file_touches_nothing(self) -> None:
        assert _contract_collateral(ORIGINAL, ORIGINAL, _asset(5)) is None

    def test_a_structural_rewrite_is_out_of_scope_rather_than_guessed_at(self) -> None:
        """When the line count changes, "the context around line N" has no answer. Returning None
        is the honest result; the rescan and `behaves` still gate the patch."""
        assert _contract_collateral(ORIGINAL, BOTH + "\n# a trailing line\n", _asset(5)) is None

    def test_an_asset_with_no_line_does_not_crash(self) -> None:
        # No own-line exemption is available, so every changed line is judged — including line 5,
        # which the guard clears anyway.
        assert _contract_collateral(ORIGINAL, ONLY_MINE, _asset(None)) is None


class TestItIsWiredIntoGeneration:
    """A mutation deleting the call site left every test above green.

    So the wiring is asserted directly, the same way `TestTheGuardIsActuallyWiredIn` does for the
    pre-generation guard: a check that exists but is never called is worth nothing.
    """

    def test_generate_patch_calls_it_before_validating(self) -> None:
        import inspect

        from qubit_migrate import orchestrator

        # `_generate_patch` is where generation actually happens; `generate_patch` is the public
        # wrapper around it.
        src = inspect.getsource(orchestrator.MigrationOrchestrator._generate_patch)
        call = src.index("_contract_collateral(")
        validate = src.index("def _validate(candidate: str)")
        assert call < validate, "the collateral check must run before validation, not after"

        # It must ACT on the verdict, not merely compute it. Scoped to the end of the enclosing
        # statement block rather than a fixed character window, which silently stopped covering
        # the raise once the surrounding code grew.
        after = src[call : src.index("def _validate(candidate: str)")]
        assert "GuidedRemediation" in after, "the verdict must be raised, not discarded"
        assert "resolve_guided" in after, "the operator still needs the advice"


class TestAKnownOverReach:
    """The cost of refusing the WHOLE patch, asserted rather than left to be discovered.

    `_CREDENTIAL_DIGEST` matches `new(...secret`, which is deliberately broad — it is the rule that
    caught pyload's five broken wire-format patches. Applying the guard to collateral lines extends
    that breadth from "a finding on this line" to "any patch that touches this line", so a
    multi-line migration that incidentally moves an `hmac.new(self.secret, ...)` call is refused
    whole.

    That is the module's stated trade-off (*"a false verdict costs an advisory on a finding that
    could have been auto-migrated"*, and the other direction costs a broken patch), applied wider.
    It is recorded here as behaviour rather than described in a docstring, so that narrowing
    `_CREDENTIAL_DIGEST` later makes this test fail and forces the record to be updated instead of
    quietly going stale.
    """

    #: A module whose weak hash is genuinely migratable, next to an unrelated HMAC over a secret.
    MIXED = """import hashlib
import hmac


class Client:
    def cache_key(self, url):
        return hashlib.md5(url.encode()).hexdigest()

    def sign(self, body):
        return hmac.new(self.secret, body, hashlib.sha256).hexdigest()
"""

    def test_a_patch_that_reformats_an_unrelated_hmac_line_is_refused(self) -> None:
        patched = self.MIXED.replace(
            "        return hashlib.md5(url.encode()).hexdigest()",
            "        return hashlib.sha256(url.encode()).hexdigest()",
        ).replace(
            "        return hmac.new(self.secret, body, hashlib.sha256).hexdigest()",
            "        return hmac.new(self.secret, body, hashlib.sha256).hexdigest()  # noqa",
        )
        reason = _contract_collateral(self.MIXED, patched, _asset(7))
        assert reason is not None, "documented over-reach; see this class's docstring"
        assert "line 10" in reason
        assert "digest over a credential" in reason

    def test_the_same_patch_without_that_line_is_allowed(self) -> None:
        """The control: the over-reach is about touching the line, not about the file containing
        it. A migration that leaves the HMAC alone still goes through."""
        patched = self.MIXED.replace(
            "        return hashlib.md5(url.encode()).hexdigest()",
            "        return hashlib.sha256(url.encode()).hexdigest()",
        )
        assert _contract_collateral(self.MIXED, patched, _asset(7)) is None
