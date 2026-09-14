"""The non-Python hash swap must touch ONE finding, not every match in the file.

A migration task owns exactly one finding. The other occurrences of the same algorithm in the same
file are separate tasks with their own dispositions, and on a real codebase several of them are
deliberate refusals — a content address other systems already store, a digest a signature commits
to, a thumbprint a certificate authority owns.

Measured on the Ruby twin through the desktop app before this was scoped: one patch rewrote all five
SHA-1 call sites in `crypto/documents.rb`, four of them refusals. `parses`, `symbols`, `compiles`
and `rescan` all passed it, the patch was applied, and the twin's own suite went red.

Imports are the one thing that is correctly file-wide, and they cut both ways: a Go file that
imports `crypto/sha1` without calling it does not compile, and neither does one that calls
`sha1.Sum` after its import was rewritten away. Both directions are tested here.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform.codemods import _apply_hash_swap

RUBY_TWO_SITES = """\
module Documents
  def content_digest(bytes)
    OpenSSL::Digest::SHA1.hexdigest(bytes)
  end

  def cache_key(bytes)
    OpenSSL::Digest::SHA1.hexdigest(bytes)
  end
end
"""

GO_SOLE_USER = """\
package x

import (
\t"crypto/sha1"
\t"fmt"
)

func One(b []byte) string {
\treturn fmt.Sprintf("%x", sha1.Sum(b))
}
"""

GO_SECOND_USER = """\
package x

import (
\t"crypto/sha1"
\t"fmt"
)

func One(b []byte) string {
\treturn fmt.Sprintf("%x", sha1.Sum(b))
}

func Two(b []byte) string {
\treturn fmt.Sprintf("%x", sha1.Sum(b))
}
"""

JAVA_TWO_SITES = """\
class Vault {
    String tokenFor(byte[] pan) throws Exception {
        return hex(MessageDigest.getInstance("SHA-1").digest(pan));
    }

    String cacheKey(byte[] pan) throws Exception {
        return hex(MessageDigest.getInstance("SHA-1").digest(pan));
    }
}
"""


class TestOnlyTheTargetLine:
    def test_ruby_leaves_the_sibling_call_site_alone(self):
        out, changed = _apply_hash_swap(RUBY_TWO_SITES, "ruby", only_line=3)
        assert changed
        assert out.count("SHA256") == 1, "swapped more than the one finding"
        assert out.count("SHA1") == 1, "the sibling refusal was rewritten"
        assert "SHA256.hexdigest(bytes)" in out.splitlines()[2]

    def test_java_leaves_the_sibling_call_site_alone(self):
        out, changed = _apply_hash_swap(JAVA_TWO_SITES, "java", only_line=3)
        assert changed
        assert out.count('"SHA-256"') == 1
        assert out.count('"SHA-1"') == 1

    def test_targeting_the_second_site_moves_the_edit(self):
        """Scoping must follow the line it is given, not simply hit the first match."""
        out, _ = _apply_hash_swap(RUBY_TWO_SITES, "ruby", only_line=7)
        assert "SHA256" in out.splitlines()[6]
        assert "SHA1" in out.splitlines()[2], "edited the first site instead of the one asked for"

    def test_a_line_with_nothing_to_swap_produces_no_patch(self):
        out, changed = _apply_hash_swap(RUBY_TWO_SITES, "ruby", only_line=1)
        assert not changed
        assert out == RUBY_TWO_SITES

    def test_a_line_outside_the_file_produces_no_patch(self):
        """Never fall back to a whole-file swap: that is how a refusal becomes a migration."""
        out, changed = _apply_hash_swap(RUBY_TWO_SITES, "ruby", only_line=9999)
        assert not changed
        assert out == RUBY_TWO_SITES

    def test_no_line_still_swaps_the_whole_file(self):
        """The unscoped call is still available for callers that genuinely own every site."""
        out, changed = _apply_hash_swap(RUBY_TWO_SITES, "ruby", only_line=None)
        assert changed
        assert out.count("SHA256") == 2


class TestImportsAreHandledFileWide:
    def test_import_is_replaced_when_the_last_caller_goes(self):
        out, changed = _apply_hash_swap(GO_SOLE_USER, "go", only_line=9)
        assert changed
        assert '"crypto/sha256"' in out
        assert '"crypto/sha1"' not in out, "unused import left behind; the file will not compile"

    def test_import_is_kept_when_another_caller_remains(self):
        out, changed = _apply_hash_swap(GO_SECOND_USER, "go", only_line=9)
        assert changed
        assert '"crypto/sha1"' in out, "import removed while sha1.Sum is still called"
        assert '"crypto/sha256"' in out, "new import missing"
        assert out.count("sha1.Sum") == 1, "the other call site was rewritten"
        assert out.count("sha256.Sum256") == 1


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ('"crypto/sha1"', True),
        ('"golang.org/x/crypto/blake2b"', True),
        ("sha1.New(", False),
        ("crypto.SHA1", False),
        ('MessageDigest.getInstance("SHA-1")', False),
    ],
)
def test_import_classification(token, expected):
    from qubit_migrate.transform.codemods import _is_import_swap

    assert _is_import_swap(token) is expected
