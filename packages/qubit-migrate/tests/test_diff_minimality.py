"""A migration diff should contain the migration, and not much else.

A model asked to migrate a file is handed the whole file and returns the whole file, so what comes
back carries its formatting habits along with the fix. Measured on certbot's
`certbot-ci/src/certbot_integration_tests/utils/misc.py`: the ML-DSA rewrite was right -- the right
import, the right key type, the right branch in `generate_csr` -- and it also collapsed PEP 8's
two-blank-line separators to one throughout the file, in functions the finding never touched.

Nothing in the validation gate can object, and nothing should: blank lines change no parse, no
symbol, no compilation and no rescan result. Every stage passed. What reached the operator was a
correct migration inside forty lines of reformatting nobody asked for -- a diff certbot's own CI
would fail on style, and a reviewer would refuse without ever reaching the cryptography.

That is worth naming precisely, because it is the difference between the two claims this project
can make. "Every gate passed" is a statement about QUBIT. "A maintainer would merge this" is a
statement about the migration, and it is the one that matters.
"""

from __future__ import annotations

from qubit_migrate.transform.diffing import old_new_to_diff, restore_incidental_blank_lines

ORIGINAL = '''"""Module docstring."""

import hashlib


def first() -> None:
    """First."""
    return None


def second(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def third() -> None:
    return None
'''


def test_blank_lines_the_model_dropped_come_back() -> None:
    """The measured failure: a correct change arriving inside a whole-file reformat."""
    reformatted = ORIGINAL.replace("\n\n\n", "\n").replace(
        "hashlib.md5(data)", "hashlib.sha256(data)"
    )
    assert "\n\n\n" not in reformatted, "the fixture must actually strip the separators"

    restored = restore_incidental_blank_lines(ORIGINAL, reformatted)

    assert "sha256" in restored, "the migration itself must survive"
    assert "md5" not in restored
    assert restored == ORIGINAL.replace("hashlib.md5(data)", "hashlib.sha256(data)"), (
        "nothing but the algorithm should differ from the original"
    )


def test_the_diff_that_reaches_the_operator_is_the_change_and_nothing_else() -> None:
    """What the reviewer actually sees. The unit under test is the diff, not the source."""
    reformatted = ORIGINAL.replace("\n\n\n", "\n").replace(
        "hashlib.md5(data)", "hashlib.sha256(data)"
    )

    before = old_new_to_diff("m.py", ORIGINAL, reformatted)
    after = old_new_to_diff("m.py", ORIGINAL, restore_incidental_blank_lines(ORIGINAL, reformatted))

    changed = [ln for ln in after.splitlines() if ln.startswith(("+", "-"))]
    changed = [ln for ln in changed if not ln.startswith(("+++", "---"))]
    assert len(changed) == 2, f"one line replaced, so two diff lines; got {changed}"
    assert any("sha256" in ln for ln in changed)

    noisy = [ln for ln in before.splitlines() if ln.startswith(("+", "-"))]
    assert len(noisy) > len(changed), "the fixture must reproduce the noise being removed"


def test_code_the_model_deliberately_removed_stays_removed() -> None:
    """The restoration must not resurrect a deletion. A run of lines containing anything real is
    the model removing code, which is its job -- only runs that are entirely blank are put back."""
    without_third = ORIGINAL.replace("\n\ndef third() -> None:\n    return None\n", "\n")

    restored = restore_incidental_blank_lines(ORIGINAL, without_third)

    assert "def third" not in restored
    assert restored == without_third


def test_a_blank_line_the_model_added_is_left_alone() -> None:
    """Only deletions are undone. An added blank line is at worst harmless, and second-guessing
    the model's spacing in both directions would mean rewriting output that is not wrong."""
    spaced = ORIGINAL.replace("def third", "\ndef third")

    assert restore_incidental_blank_lines(ORIGINAL, spaced) == spaced


def test_an_unchanged_file_is_returned_unchanged() -> None:
    """The identity case, which is also the negative control for the whole transform: if this ever
    returns something different, every patch is being altered on its way to the gate."""
    assert restore_incidental_blank_lines(ORIGINAL, ORIGINAL) == ORIGINAL


def test_trailing_whitespace_counts_as_blank() -> None:
    """A "blank" line in real code often carries indentation left by an editor. Treating those as
    content would leave exactly the files most likely to be reformatted unprotected."""
    with_indent = ORIGINAL.replace("\n\n\ndef second", "\n   \n\ndef second")
    stripped = with_indent.replace("\n   \n\ndef second", "\ndef second")

    assert restore_incidental_blank_lines(with_indent, stripped) == with_indent
