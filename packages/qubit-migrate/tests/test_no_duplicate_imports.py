"""Migrating two weak modules in one file must import the replacement exactly once.

Go rejects a repeated import with `sha256 redeclared in this block`, so this is a build break rather
than an untidiness. Measured on `sentinel-idp`, through the desktop app: `internal/cryptox` came out
with two and three `"crypto/sha256"` lines across three files and the package did not compile.

Two distinct paths produce it, and both are covered here:

* one file importing both `crypto/md5` and `crypto/sha1`, whose two swaps each independently decided
  to write `crypto/sha256`;
* two separate task patches applied one after the other, where the second ran against a file the
  first had already migrated.

The second is the one that matters in practice, because line-scoped codemods mean every file with
several findings is patched exactly that way.
"""

from __future__ import annotations

from qubit_migrate.transform.codemods import _apply_hash_swap

TWO_WEAK_IMPORTS = (
    "package x\n"
    "\n"
    "import (\n"
    '\t"crypto/md5"\n'
    '\t"crypto/sha1"\n'
    '\t"fmt"\n'
    ")\n"
    "\n"
    "func One(b []byte) string {\n"
    '\treturn fmt.Sprintf("%x", md5.Sum(b))\n'
    "}\n"
    "\n"
    "func Two(b []byte) string {\n"
    '\treturn fmt.Sprintf("%x", sha1.Sum(b))\n'
    "}\n"
)

# Line numbers into TWO_WEAK_IMPORTS, 1-based.
MD5_CALL = 10
SHA1_CALL = 14


def test_migrating_both_call_sites_imports_the_replacement_once():
    """The sequential case: one patch per finding, exactly as the orchestrator applies them."""
    first, changed = _apply_hash_swap(TWO_WEAK_IMPORTS, "go", only_line=MD5_CALL)
    assert changed
    second, changed = _apply_hash_swap(first, "go", only_line=SHA1_CALL)
    assert changed

    count = second.count('"crypto/sha256"')
    assert count == 1, f"imported the replacement {count} times:\n{second}"
    assert '"crypto/md5"' not in second
    assert '"crypto/sha1"' not in second
    assert second.count("sha256.Sum256") == 2


def test_the_intermediate_state_is_also_valid():
    """After only the first finding is migrated, both imports must still be correct.

    This is not a hypothetical state: it is what is on disk whenever one patch is accepted and the
    next is still being generated, and it is what `compiles` judges.
    """
    first, _ = _apply_hash_swap(TWO_WEAK_IMPORTS, "go", only_line=MD5_CALL)
    assert first.count('"crypto/sha256"') == 1
    assert '"crypto/md5"' not in first, "md5 lost its last caller; the import should have gone"
    assert '"crypto/sha1"' in first, "sha1 is still called further down"
    assert first.count("sha1.Sum") == 1


def test_a_file_already_importing_the_target_does_not_gain_a_second():
    source = TWO_WEAK_IMPORTS.replace('\t"fmt"\n', '\t"crypto/sha256"\n\t"fmt"\n')
    out, _ = _apply_hash_swap(source, "go", only_line=MD5_CALL + 1)
    assert out.count('"crypto/sha256"') == 1


def test_the_old_import_is_dropped_not_left_blank():
    """A redundant import is removed outright.

    Rewriting it in place is what produced the duplicates; leaving an empty line would be legal Go
    but would show up as noise in every review of a migration diff.
    """
    first, _ = _apply_hash_swap(TWO_WEAK_IMPORTS, "go", only_line=MD5_CALL)
    second, _ = _apply_hash_swap(first, "go", only_line=SHA1_CALL)
    import_block = second[second.index("import ("): second.index(")\n")]
    assert [ln for ln in import_block.splitlines() if not ln.strip()] == [], import_block
