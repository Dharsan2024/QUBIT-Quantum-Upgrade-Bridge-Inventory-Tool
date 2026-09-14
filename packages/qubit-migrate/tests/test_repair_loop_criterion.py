"""The repair loop must judge a candidate by the SAME rule that will accept it.

`_stage_rescan` narrows its `gone` check from "this algorithm appears nowhere in the file" to
"THIS task's occurrence of it went away" -- but only when handed a baseline to diff against.
Without one it falls back to the whole-file rule (`_occurrence_survived`).

`validate_patch` always passes that baseline. The LLM repair loop did not, so the loop rejected
candidates by a strictly harsher standard than the validator that would ultimately have accepted
them, spent all three attempts "correcting" work that was already right, and recorded a real
migration as a failure.

Measured across five real repositories (paramiko, forge, gliderlabs/ssh, java-jwt, ruby-jwt):
18 of 22 `code-kex-01` rejections were `Expected 'RSA' gone, but still found: ['RSA']`. The rule's
OWN `prompt_constraints` tell the model to "keep the old decrypt path so already-encrypted data can
still be read" -- so the loop was ordering the model to delete the compatibility path the rule
requires, then failing it for having followed instructions.
"""

from __future__ import annotations

from qubit_migrate.transform.rules import load_rules
from qubit_migrate.transform.validate import _stage_rescan

# Two RSA call sites. A migration owns ONE of them; the other belongs to a different task, and a
# backward-compatible decrypt path is expected to survive by design.
BEFORE = """\
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

func seal(pub *rsa.PublicKey, payload []byte) ([]byte, error) {
    return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, payload, nil)
}

func openLegacy(priv *rsa.PrivateKey, blob []byte) ([]byte, error) {
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, blob, nil)
}
"""

# The flagged `seal` site migrated to ML-KEM. `openLegacy` deliberately still uses RSA so data
# encrypted under the old scheme remains readable -- exactly what the rule asks for.
AFTER = """\
package main

import (
    "crypto/mlkem"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

func seal(ek *mlkem.EncapsulationKey768, payload []byte) ([]byte, error) {
    sharedSecret, encapsulation := ek.Encapsulate()
    _ = sharedSecret
    return encapsulation, nil
}

func openLegacy(priv *rsa.PrivateKey, blob []byte) ([]byte, error) {
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, blob, nil)
}
"""

FLAGGED_LINE = 10  # the `rsa.EncryptOAEP` call inside `seal`


def _kex_rule():
    return next(r for r in load_rules() if r.id == "code-kex-01")


def test_without_a_baseline_the_check_is_the_strict_whole_file_rule() -> None:
    """Pins the fallback that caused the defect, so the difference is visible and deliberate.

    This is not a bug in `_stage_rescan` -- with no baseline it cannot tell which occurrence was
    this task's, and guessing would be worse than being strict. The bug was calling it this way
    from the repair loop.
    """
    result = _stage_rescan(AFTER, _kex_rule(), "go", "RSA")

    assert result.status == "fail", result
    assert result.expectation == "gone"
    assert "still found" in result.detail


def test_with_a_baseline_a_migrated_occurrence_passes_despite_a_kept_legacy_path() -> None:
    """The criterion the validator actually uses, and now the one the repair loop uses too.

    One of two RSA occurrences was migrated; the other is a deliberate compatibility path. That is
    a successful migration of this task's finding, and must be reported as one.
    """
    result = _stage_rescan(
        AFTER,
        _kex_rule(),
        "go",
        "RSA",
        original_source=BEFORE,
        asset_line=FLAGGED_LINE,
    )

    assert result.status != "fail", (
        f"a migrated occurrence beside a kept legacy path must pass: {result.detail}"
    )


def test_a_rewrite_that_migrated_nothing_still_fails_with_a_baseline() -> None:
    """The narrowing must not become a way to pass by doing nothing.

    Same baseline, but the candidate is the unchanged original: no occurrence was removed, so the
    count cannot have fallen and the check has to fail. Without this, "compare against a baseline"
    would be indistinguishable from "stop checking".
    """
    result = _stage_rescan(
        BEFORE,
        _kex_rule(),
        "go",
        "RSA",
        original_source=BEFORE,
        asset_line=FLAGGED_LINE,
    )

    assert result.status == "fail", "an unchanged file must never pass the gone check"
    assert result.expectation == "gone"
