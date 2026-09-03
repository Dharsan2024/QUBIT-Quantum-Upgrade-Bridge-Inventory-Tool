"""A constraint written in prose, two lines above the code that would break it.

The scanner's evidence is a +/-2 line window. It is enough to see a call and nothing at all about
what happens to the result — and the reason a digest must not change is almost never on the call
line. It is in the docstring: "persisted as document.content_digest", "the acquirer recomputes
this", "stored as a primary key a retry must resolve to".

Measured across the four twins in the first complete run: refusals whose manifest evidence class is
`prose` were **4 of the 9 false migrations**, and every one had its constraint written down in the
file, above the code that was rewritten.

**Two honest caveats, both of which belong in the write-up.**

First, this vocabulary was written while looking at the applications that also score it — the same
caveat `_CONTRACT_URLS` carries. Recall measured on these twins is not an independent measurement of
this rule.

Second, and the reason it is usable at all: the twins were built so the same primitive appears on
both sides of the line. `Internal.render_cache_key` sits nine lines from `Documents.content_digest`
and uses the same call. A rule that keyed on "this text mentions storage" would refuse both, and the
negative vocabulary is what makes it discriminate rather than simply refuse.

Measured on the four twins' real source (not the manifest's prose, which would be circular):
**precision 91%, recall 58%** — 21 refusals protected, 2 migratable findings routed to guidance.
"""

from __future__ import annotations

import pytest

from qubit_migrate.protocol_contract import documented_constraint, enclosing_documentation

RUBY_PERSISTED = '''\
module Documents
  # The content address a document is stored and de-duplicated by.
  #
  # Expected disposition: REFUSE. Every document already in storage carries this digest.
  def content_digest(bytes)
    OpenSSL::Digest::SHA1.hexdigest(bytes)
  end
end
'''

RUBY_REGENERABLE = '''\
module Internal
  # Key for the rendered-PDF cache.
  #
  # MD5 as an in-process cache key. The cache is empty at boot; a miss costs one re-render.
  def render_cache_key(template_id)
    Digest::MD5.hexdigest(template_id)
  end
end
'''

PYTHON_DOCSTRING_BELOW = '''\
def note_checksum(body: str) -> str:
    """The digest persisted as encounter.note_checksum and re-derived on every read."""
    return hashlib.sha1(body.encode()).hexdigest()
'''


class TestTheDiscrimination:
    def test_a_persisted_identity_is_refused(self) -> None:
        verdict = documented_constraint(enclosing_documentation(RUBY_PERSISTED, 6))
        assert verdict is not None, "a documented content address was left migratable"
        assert "outlives" in verdict.reason

    def test_a_cache_key_with_the_same_primitive_is_not(self) -> None:
        """The pair that makes this rule meaningful rather than a blanket refusal."""
        assert documented_constraint(enclosing_documentation(RUBY_REGENERABLE, 6)) is None

    def test_recomputed_every_request_is_regenerable_not_persisted(self) -> None:
        """This phrase was in the PERSISTED list, and flagged both twins' rate-limit buckets —
        the most obviously ephemeral values in the whole corpus."""
        text = "The bucket key, recomputed every request from the principal and the window."
        assert documented_constraint(text) is None

    def test_re_derived_from_a_stored_value_is_still_persisted(self) -> None:
        """The near-miss of the case above: `re-derived` means derived again from something kept."""
        text = "Stored as merchant.api_key_digest and re-derived on every request."
        assert documented_constraint(text) is not None


class TestTheWindow:
    def test_a_python_docstring_below_the_def_is_read(self) -> None:
        """Python and Ruby put the docstring INSIDE the definition.

        A walk that only looks upward finds the decorator and nothing else, which is how every
        medivault-emr refusal was missed on the first measurement.
        """
        context = enclosing_documentation(PYTHON_DOCSTRING_BELOW, 1)
        assert "persisted" in context
        assert documented_constraint(context) is not None

    def test_a_neighbouring_symbol_s_documentation_is_not_read(self) -> None:
        """The bug that made the first version worse than useless.

        The walk ran a fixed 40 lines and swallowed the MODULE docstring, which on inkwell-esign
        contains the sentence "A signed PDF is not a cache entry". That one word vetoed a correct
        refusal of a persisted content address.
        """
        source = (
            "# A signed PDF is not a cache entry: it is evidence, retained for years.\n"
            "module M\n"
            "  def unrelated_helper(x)\n"
            "    x\n"
            "  end\n"
            "\n"
            "  # The de-duplication key, stored against every row.\n"
            "  def digest(x)\n"
            "    Digest::SHA1.hexdigest(x)\n"
            "  end\n"
            "end\n"
        )
        context = enclosing_documentation(source, 8)
        assert "cache entry" not in context, "read a different symbol's documentation"
        assert documented_constraint(context) is not None

    def test_no_documentation_produces_no_verdict(self) -> None:
        """Absence of a comment is not evidence that the choice is free."""
        assert documented_constraint(enclosing_documentation("def f(x)\n  x\nend\n", 1)) is None

    @pytest.mark.parametrize("line", [0, -1, 9999])
    def test_a_line_outside_the_file_is_survivable(self, line: int) -> None:
        assert enclosing_documentation(RUBY_PERSISTED, line) == ""


class TestItOnlyEverAddsRefusals:
    def test_an_empty_context_is_not_a_verdict(self) -> None:
        assert documented_constraint("") is None
        assert documented_constraint(None) is None

    def test_the_regenerable_half_always_wins(self) -> None:
        """Both vocabularies present means the value is documented as regenerable AND stored.

        A cache is written somewhere too. Deferring to the regenerable reading keeps the migratable
        half of every twin reachable, which is the cost this rule has to keep paying to be worth
        having at all.
        """
        both = "Stored in the cache and re-derived on every request."
        assert documented_constraint(both) is None
