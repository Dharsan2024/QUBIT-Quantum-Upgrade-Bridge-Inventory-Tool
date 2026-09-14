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
from qubit_migrate.protocol_contract import (
    documented_constraint,
    enclosing_documentation,
    module_declares_no_third_party,
)

RUBY_PERSISTED = """\
module Documents
  # The content address a document is stored and de-duplicated by.
  #
  # Expected disposition: REFUSE. Every document already in storage carries this digest.
  def content_digest(bytes)
    OpenSSL::Digest::SHA1.hexdigest(bytes)
  end
end
"""

RUBY_REGENERABLE = """\
module Internal
  # Key for the rendered-PDF cache.
  #
  # MD5 as an in-process cache key. The cache is empty at boot; a miss costs one re-render.
  def render_cache_key(template_id)
    Digest::MD5.hexdigest(template_id)
  end
end
"""

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

    def test_recomputed_for_verification_is_persisted_not_regenerable(self) -> None:
        """A second near-miss the rate-limit fix above created, found by re-running this rule
        against the pristine twin source directly rather than trusting an aggregate score.

        `inkwell-esign`'s `Documents.content_digest` (manifest id IE-01) is PERSISTED as
        `document.content_digest`, and its own docstring says it is "recomputed every time a
        signed PDF is verified" — recomputed FOR COMPARISON against an already-stored value,
        the opposite of the rate-limit idiom above (`recomputed every window`, nothing stored
        to compare against). Measured: this exact text vetoed the persisted verdict via the
        bare `recomputed every` match, so IE-01 was migrated in every campaign run despite its
        own docstring saying "Expected disposition: REFUSE" in as many words — 100%
        reproducible against the pristine source, not routing noise. `verif` (verify/verified/
        verification/verifies) within six words of the match is the signal that distinguishes
        this case from the rate-limit one.
        """
        text = (
            "Persisted as document.content_digest and recomputed every time a signed PDF is "
            "verified, de-duplicated, or fetched by content address."
        )
        verdict = documented_constraint(text)
        assert verdict is not None, "a recompute-and-compare digest was left migratable"

    def test_recomputed_on_every_verification_is_also_persisted(self) -> None:
        """The `on every` spelling of the same idiom, measured on the same finding's class-level
        summary comment (`Documents`' own module docstring, one line up from the method)."""
        text = "persisted as +document.content_digest+, recomputed on every verification"
        assert documented_constraint(text) is not None

    def test_must_resolve_to_is_the_same_constraint_as_must_match(self) -> None:
        """A vocabulary gap, not a veto: `must match`/`must agree` already fired, but a retry,
        re-upload or re-presented header more often "must resolve to" the same stored row —
        the identical constraint in the idempotency/dedup idiom's own words.

        Measured missing on three real refusals before this test: `inkwell-esign`
        template_digest ("must resolve to the existing version", manifest IE-04),
        `paymesh-gateway` cardToken ("must resolve to the same vault row", PM-07) and
        idempotencyDigest ("must resolve to this same row", PM-09).
        """
        text = "Presenting the same card twice must resolve to the same vault row."
        verdict = documented_constraint(text)
        assert verdict is not None, "a must-resolve-to constraint was left migratable"

    def test_unchangeable_is_recognised_on_its_own(self) -> None:
        """The bare adjective, measured on the same `cardToken` docstring one clause later:
        "...which is what makes the algorithm unchangeable." — no `persisted`/`stored`/`must`
        anywhere in THIS clause, so it needs its own entry rather than riding another match."""
        assert documented_constraint("It is also what makes the algorithm unchangeable.") is not None


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


class TestProtocolMandated:
    """PM-04, and the reason it was invisible for two full evaluation rounds.

    `legacyPortalToken`'s constraint is recorded only in its javadoc — the variable is named
    `digest`, the material is a joined string, and nothing within five lines of the call mentions
    a portal. The fixture calls it "the deliberate prose-evidence case" and marks its evidence
    class `prose`, so prose is where it has to be caught; the vocabulary simply did not carry the
    phrase the authors used.

    It went unnoticed because both earlier rounds left the task unfinished — `generating` and
    `deferred/unresolved` both score as "not migrated", so a finding nothing ever got round to
    looks identical to one that was correctly refused. The round that finally settled it migrated
    it. A verdict this module never reached was being read as a verdict it had made.
    """

    #: `paymesh-gateway/.../ProviderSignatures.java`, verbatim.
    PORTAL_TOKEN = """\
    /**
     * Daily token for the reconciliation portal.
     *
     * <p>QUBIT-FIXTURE: code-weakhash-02 — MD5, protocol-mandated, with the constraint recorded
     * ONLY here. Nothing in the five lines around the call says a portal exists, so no static rule
     * can refuse this one. It is the deliberate `prose`-evidence case.
     */
"""

    def test_the_portal_token_is_refused(self) -> None:
        verdict = documented_constraint(self.PORTAL_TOKEN)
        assert verdict is not None, "a protocol-mandated digest was left migratable"
        assert "protocol-mandated" in verdict.signal

    def test_a_daily_value_is_still_refused(self) -> None:
        """Checked ahead of the regenerable veto, and this is why.

        The token expires within a day. Its lifetime is irrelevant: the reconciliation portal
        recomputes the same MD5 and compares, so a shorter life does not make the algorithm this
        codebase's to choose. A mandate is not undone by expiry.
        """
        both = (
            "Daily token, discarded after this session. "
            "The algorithm is protocol-mandated by the portal."
        )
        assert documented_constraint(both) is not None

    def test_the_spaced_spelling_is_caught_too(self) -> None:
        assert documented_constraint("This digest is protocol mandated by the acquirer.") is not None


class TestModuleDeclaresNoThirdParty:
    """The MV-10 fix: a module docstring can say the "other half" of an exchange is itself.

    Real case: `medivault-emr/app/services/keyexchange.py` opens "Both ends of this exchange are
    MediVault. There is no third party whose format is fixed" -- a fact `enclosing_documentation`
    cannot see because it deliberately never reads past the nearest function's own documentation
    (see its docstring). `generate_referral_keypair`, one function below, says "Our half of the
    exchange" and was refused on that phrase alone, though ground truth calls it MIGRATE.
    """

    MODULE_HEADER = (
        '"""Referral channel to a partner clinic running this same software.\n\n'
        "Both ends of this exchange are MediVault. There is no third party whose format is "
        'fixed, and no stored artefact in the old format.\n"""\n'
    )

    def test_the_real_medivault_header_is_recognised(self) -> None:
        assert module_declares_no_third_party(self.MODULE_HEADER) is True

    def test_a_file_that_never_says_so_is_not_assumed(self) -> None:
        assert module_declares_no_third_party('"""Just a docstring, no claim either way."""\n') is False

    def test_an_undocumented_file_is_not_assumed(self) -> None:
        assert module_declares_no_third_party("def f(x):\n    return x\n") is False

    def test_the_flag_suppresses_only_the_counterparty_reading(self) -> None:
        """The near miss that keeps this from becoming a blanket override.

        The same context, with and without the flag: without it, a counterparty statement is a
        verdict; with it, the same text produces none — but a genuinely persisted value in that
        same context must still refuse, flag or no flag.
        """
        context = "Our half of the exchange, plus the public point to send to the partner clinic."
        assert documented_constraint(context) is not None
        assert documented_constraint(context, module_declares_no_third_party=True) is None

    def test_the_flag_does_not_clear_an_independently_persisted_value(self) -> None:
        context = "Our half of the exchange. Also persisted as the row's primary key."
        verdict = documented_constraint(context, module_declares_no_third_party=True)
        assert verdict is not None, "a persisted value must still refuse when the veto is suppressed"
        assert "outlives" in verdict.reason
