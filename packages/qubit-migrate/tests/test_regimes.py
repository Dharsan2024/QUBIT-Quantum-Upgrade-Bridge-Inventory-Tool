"""The regime engine: what each regulator actually requires, and where they disagree.

The disagreement is the reason this exists. Every automated migration tool surveyed picks ONE
target per finding, and is therefore wrong in at least one jurisdiction. These tests pin the
specific facts that a "hybrid vs pure" model of the problem gets backwards.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_core import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.agility import load_agility_policy, resolve_target
from qubit_migrate.regimes import (
    Regime,
    check_target,
    family_of,
    grade_of,
    load_regimes,
    resolve_all_regimes,
)
from qubit_migrate.transform.synthesized import synthesize_rule

#: The industry default. Browsers ship it; BSI requires this shape; CNSA 2.0 rejects it.
INDUSTRY_DEFAULT = {"algorithm": "X25519MLKEM768", "hybrid_group": "X25519MLKEM768"}


def _blocking(conflicts: list) -> list[str]:
    return [c.rule for c in conflicts if c.blocking]


def _rules(conflicts: list) -> set[str]:
    return {c.rule for c in conflicts}


class TestTheCatalogLoads:
    def test_five_regimes(self) -> None:
        catalog = load_regimes()
        assert set(catalog.regimes) == {
            "cnsa-2.0",
            "anssi",
            "bsi-tr-02102",
            "asd-ism",
            "nist-civil",
        }

    def test_the_default_is_the_least_opinionated_one(self) -> None:
        """An install that has chosen nothing must not be handed a mandate it never opted into."""
        catalog = load_regimes()
        assert catalog.default_regime == "nist-civil"
        assert catalog.regimes["nist-civil"].construction == "either"

    def test_confidence_is_recorded_per_regime(self) -> None:
        """No regime claims `primary` except the one read from the standard itself.

        `asd-ism` was `secondary` — in neither reference implementation, inferred from prose. It
        is now `verified-secondary`, having been raised by citing its own control text (ISM-1917).
        A reader must still be able to tell it apart from a regime read out of the primary
        standard.
        """
        catalog = load_regimes()
        # Raised to `primary` as each publisher's own document was read; all four are in
        # `qubit-v2/vendor/standards/`. Two of these upgrades CORRECTED the entry rather than
        # confirming it, which is the argument for the field existing at all.
        for name in ("cnsa-2.0", "bsi-tr-02102", "anssi", "nist-civil"):
            assert catalog.regimes[name].confidence == "primary", name
        # Still second-hand. ASD ISM is read from a source quoting it, and a reader must be able
        # to tell that apart from the four above without taking the table's word for it.
        assert catalog.regimes["asd-ism"].confidence == "verified-secondary"

    def test_every_primary_entry_names_the_section_it_was_read_from(self) -> None:
        """`primary` is a claim, and this is what makes it checkable.

        "We read the standard" is an assertion; "§2.2 of Version 2026-01" is an address a reviewer
        can go to. An entry claiming `primary` with no section is claiming more than it shows.
        """
        for name, regime in load_regimes().regimes.items():
            if regime.confidence == "primary" and name != "nist-civil":
                assert regime.source_section, f"{name} claims primary with no section"


class TestGradeParsing:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("ML-KEM-768", 768),
            ("ML-KEM-1024", 1024),
            ("ML-DSA-87", 87),
            ("X25519MLKEM768", 768),
            # The classical curve's own number comes FIRST. Reading it would judge the hybrid on
            # its classical half and let a sub-1024 lattice component through.
            ("SecP384r1MLKEM1024", 1024),
            ("SecP256r1MLKEM768", 768),
            (None, None),
        ],
    )
    def test_the_last_number_is_the_grade(self, name: str | None, expected: int | None) -> None:
        assert grade_of(name) == expected

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("ML-KEM-768", "ML-KEM"),
            # Hybrid group names carry no separators, so a prefix match on "ML-KEM" fails and the
            # grade minimum would silently never apply.
            ("X25519MLKEM768", "ML-KEM"),
            ("SecP384r1MLKEM1024", "ML-KEM"),
            ("ML-DSA-87", "ML-DSA"),
            ("SLH-DSA-SHA2-128s", "SLH-DSA"),
            ("RSA-2048", None),
        ],
    )
    def test_family_survives_the_hybrid_spelling(self, name: str, expected: str | None) -> None:
        assert family_of(name) == expected


class TestTheRealConflict:
    """It is NOT hybrid versus pure. It is parameter grade."""

    def test_cnsa2_rejects_the_industry_default_on_the_grade_not_the_hybrid(self) -> None:
        conflicts = resolve_all_regimes(**INDUSTRY_DEFAULT)["cnsa-2.0"]
        assert _blocking(conflicts) == ["below-minimum-grade"]
        assert "hybrid-required" not in _rules(conflicts)
        # The message must say so, because an operator told "CNSA rejects hybrids" will make the
        # wrong change: they will drop the classical half instead of raising the grade.
        assert "NOT to the hybrid construction" in conflicts[0].detail

    def test_bsi_and_anssi_accept_the_same_target_cnsa2_rejects(self) -> None:
        verdicts = resolve_all_regimes(**INDUSTRY_DEFAULT)
        assert verdicts["bsi-tr-02102"] == []
        assert verdicts["anssi"] == []
        assert _blocking(verdicts["cnsa-2.0"])

    def test_a_pure_top_grade_target_flips_the_disagreement(self) -> None:
        """`ML-KEM-1024` satisfies CNSA 2.0 outright and deviates from BSI's recommendation.

        **Corrected against the primary German text.** This asserted a BSI *violation*, which was
        wrong: TR-02102-1 §2.2 says `empfiehlt` — recommends — not `fordert` or `muss`. The
        disagreement is real and still worth reporting, but it is advice against permission, not
        two mandates in conflict.
        """
        verdicts = resolve_all_regimes(algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024")
        assert verdicts["cnsa-2.0"] == []
        assert _rules(verdicts["bsi-tr-02102"]) == {"hybrid-recommended"}
        assert not _blocking(verdicts["bsi-tr-02102"]), "BSI recommends; it does not require"


class TestSeverityIsDeclaredNotInferred:
    """BSI and ANSSI impose the SAME requirement and differ only in strength."""

    def test_the_two_european_regimes_both_advise_rather_than_block(self) -> None:
        """**Corrected.** This asserted BSI blocks where ANSSI warns. Both advise.

        BSI §2.2 says `empfiehlt`; ANSSI's advisory role "encourages". The place they diverge is
        certification — ANSSI's Phase 2 says post-quantum algorithms "shall" be hybridised for a
        French security visa, and BSI has no such second mode. That is tested separately.
        """
        verdicts = resolve_all_regimes(algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024")
        (anssi,) = verdicts["anssi"]
        (bsi,) = verdicts["bsi-tr-02102"]
        assert anssi.rule == bsi.rule == "hybrid-recommended"
        assert not anssi.blocking and not bsi.blocking

    def test_severity_comes_from_the_field_not_from_the_prose(self) -> None:
        """It was previously read by grepping `rationale` for the word "advisory", so an editorial
        edit to the prose would silently flip a regime between warning and blocking."""
        regime = Regime(
            construction="hybrid",
            hybrid_severity="advisory",
            rationale="This text does not contain the word, and must not need to.",
        )
        (conflict,) = check_target(regime, "probe", "ML-KEM-1024", "ML-KEM-1024")
        assert conflict.severity == "advisory"


class TestExclusions:
    def test_cnsa2_excludes_slh_dsa_despite_fips_205(self) -> None:
        """No amount of reasoning from "is it standardised" produces this rule."""
        conflicts = resolve_all_regimes(algorithm="SLH-DSA", parameter_set="SLH-DSA-SHA2-128s")
        (excluded,) = [c for c in conflicts["cnsa-2.0"] if c.rule == "excluded-algorithm"]
        assert excluded.blocking
        assert "DESPITE FIPS 205" in excluded.detail

    def test_bsi_approves_what_cnsa2_excludes(self) -> None:
        assert "SLH-DSA" in load_regimes().regimes["bsi-tr-02102"].also_approved
        assert "SLH-DSA" in load_regimes().regimes["cnsa-2.0"].excluded

    def test_an_excluded_algorithm_is_not_also_reported_as_below_grade(self) -> None:
        """Reporting a grade problem for an algorithm accepted at NO grade sends the reader to
        raise a parameter that was never the problem.

        Against a SYNTHETIC regime, deliberately. No shipped regime both excludes an algorithm and
        sets a grade minimum for it, so the same assertion against `cnsa-2.0` holds no matter what
        the code does — it was passing without exercising the guard at all.
        """
        both = Regime(
            construction="hybrid",
            excluded=["ML-KEM"],
            minimum_grade={"ML-KEM": 1024},
        )
        conflicts = check_target(both, "probe", "ML-KEM-512", "ML-KEM-512")
        assert _rules(conflicts) == {"excluded-algorithm"}

    def test_an_excluded_algorithm_is_not_told_to_become_a_hybrid_either(self) -> None:
        """Same guard, other direction: do not invite a hybrid built from a banned component."""
        both = Regime(construction="hybrid", excluded=["SLH-DSA"])
        conflicts = check_target(both, "probe", "SLH-DSA", "SLH-DSA-SHA2-128s")
        assert _rules(conflicts) == {"excluded-algorithm"}


class TestRuleAttribution:
    def test_no_regime_borrows_another_regimes_rule_id(self) -> None:
        """`cnsa2-hybrid-sub-1024` is the id in CNSA 2.0's OWN reference implementation.

        ASD-ISM has the same grade minimum and objects to the same target, but it is a different
        authority citing a different document — attaching CNSA's id to its finding misattributes
        the objection to a framework that never raised it.
        """
        asd = resolve_all_regimes(**INDUSTRY_DEFAULT)["asd-ism"]
        assert _blocking(asd) == ["below-minimum-grade"]
        assert all("cnsa2" not in c.rule for c in asd)

    def test_the_regimes_own_rule_reference_is_carried_in_the_detail(self) -> None:
        cnsa = resolve_all_regimes(**INDUSTRY_DEFAULT)["cnsa-2.0"]
        assert "cnsa2-hybrid-sub-1024" in cnsa[0].detail


class TestTheUniversalTarget:
    """2.6's hypothesis, resolved by running it rather than by arguing about it."""

    def test_one_target_is_permitted_by_every_regime(self) -> None:
        """**Refined, and the earlier assertion overstated it.**

        This test previously demanded ZERO objections from all five, and passed — because the
        engine could not yet express "permitted but not preferred". It can now, and the honest
        result is narrower: `SecP384r1MLKEM1024` is BLOCKED by none, *compliant* under BSI and
        ANSSI, and *permitted-but-not-preferred* under CNSA 2.0 and ASD, both of which would
        rather see a pure target.

        No single target is compliant AND preferred everywhere: a pure ML-KEM-1024 satisfies NSA
        and ASD while violating BSI and ANSSI's hybrid mandates. That is a real property of the
        regulatory landscape, not a gap in the model, and the claim to make is "blocked by none".
        """
        verdicts = resolve_all_regimes(
            algorithm="SecP384r1MLKEM1024", hybrid_group="SecP384r1MLKEM1024"
        )
        blocked = {name: cs for name, cs in verdicts.items() if _blocking(cs)}
        assert blocked == {}, blocked
        assert [c.severity for c in verdicts["cnsa-2.0"]] == ["notice"]
        assert verdicts["bsi-tr-02102"] == []

    def test_a_declared_hybrid_group_is_honoured_even_when_the_name_says_nothing(self) -> None:
        """`hybrid_group` must be a signal in its own right.

        The other hybrid names carry a recognisable classical curve (`X25519`, `SecP384r1`), so a
        name-only check happens to get them right and the `hybrid_group` path goes unexercised. A
        rule that declares a group QUBIT has never seen must still count as hybrid, or BSI blocks a
        compliant target.
        """
        conflicts = check_target(
            load_regimes().regimes["bsi-tr-02102"],
            "bsi-tr-02102",
            algorithm="ML-KEM-1024",
            hybrid_group="some-house-composite-group",
        )
        assert conflicts == []

    def test_a_plus_in_the_algorithm_counts_as_hybrid(self) -> None:
        """`ML-DSA-65+Ed25519` is how a composite rule spells its target.

        The same spelling drives the orchestrator's `construction` choice and the oracle's
        composite shape lookup, so if it did not read as hybrid here, BSI would block a compliant
        composite while the harness verified it as one.

        `Ed25519` deliberately, not `ECDSA-P256`: the curve-name fallback recognises `P256`, so a
        `+ECDSA-P256` target reads as hybrid even with this branch removed and the assertion holds
        without exercising it. `ED25519` contains no recognised curve token, so the separator is
        the only signal — and it is the classical half the composite oracle fixture actually uses.
        """
        conflicts = check_target(
            load_regimes().regimes["bsi-tr-02102"],
            "bsi-tr-02102",
            algorithm="ML-DSA-65+Ed25519",
        )
        assert conflicts == []

    def test_and_it_is_the_only_listed_hybrid_that_does(self) -> None:
        """The other two approved hybrid groups are sub-1024 and fail CNSA 2.0 and ASD-ISM."""
        for group in ("X25519MLKEM768", "SecP256r1MLKEM768"):
            verdicts = resolve_all_regimes(algorithm=group, hybrid_group=group)
            assert _blocking(verdicts["cnsa-2.0"]), group


class TestAnUnconfiguredInstallIsUnchanged:
    """A hard requirement. Every number already measured was measured on this path."""

    @staticmethod
    def _asset(usage_context: UsageContext = UsageContext.kex) -> CryptoAsset:
        return CryptoAsset(
            algorithm="ECDH-P256",
            usage_context=usage_context,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="k.py", line=1),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
            sensitivity=Sensitivity.credentials,
            evidence=Evidence(),
            discovered_at=utcnow(),
        )

    def test_no_regime_named_resolves_exactly_as_before(self) -> None:
        policy = load_agility_policy()
        assert resolve_target(self._asset(), policy) == resolve_target(
            self._asset(), policy, regime=None
        )

    def test_an_unknown_regime_falls_through_rather_than_failing(self) -> None:
        """An operator's typo must not silently change the target, and must not crash the run."""
        policy = load_agility_policy()
        assert resolve_target(self._asset(), policy, regime="not-a-regime") == resolve_target(
            self._asset(), policy
        )

    def test_a_named_regime_does_change_the_target(self) -> None:
        """The control for the two above: they would also pass if `regime` did nothing at all."""
        policy = load_agility_policy()
        cnsa = resolve_target(self._asset(), policy, regime="cnsa-2.0")
        assert cnsa is not None
        assert cnsa.parameter_set == "ML-KEM-1024"
        assert "cnsa-2.0 default" in cnsa.rationale

    def test_a_hybrid_regime_marks_the_target_hybrid(self) -> None:
        """`mode` is what makes `behaves` select the COMPOSITE relation family. Without it a
        hybrid target is verified as a pure one — half of a two-half construction."""
        target = resolve_target(self._asset(), load_agility_policy(), regime="bsi-tr-02102")
        assert target is not None
        assert target.mode == "hybrid"
        assert target.hybrid_group == "X25519MLKEM768"

    def test_an_explicit_override_outranks_a_regime(self) -> None:
        """The operator's decision about their own system is not silently overruled by a
        regulator's default; the conflict is reported instead."""
        policy = load_agility_policy()
        if not policy.overrides:
            pytest.skip("the shipped policy declares no overrides to test precedence against")
        match = policy.overrides[0].match
        if not match.usage_context:
            pytest.skip("the first override does not match on usage_context")
        try:
            usage = UsageContext(match.usage_context)
        except ValueError:
            pytest.skip(f"override usage_context {match.usage_context!r} is not a UsageContext")
        asset = self._asset(usage)
        assert resolve_target(asset, policy, regime="cnsa-2.0") == policy.overrides[0].set


class TestARegimeReachesTheRule:
    """A recorded regime that does not change the target is a label, not a policy."""

    @staticmethod
    def _asset(algorithm: str = "ECDH-P256") -> CryptoAsset:
        return CryptoAsset(
            algorithm=algorithm,
            usage_context=UsageContext.kex,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="k.py", line=1),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
            sensitivity=Sensitivity.credentials,
            evidence=Evidence(),
            discovered_at=utcnow(),
        )

    def test_no_regime_synthesises_exactly_as_before(self) -> None:
        before = synthesize_rule(self._asset(), "python")
        after = synthesize_rule(self._asset(), "python", regime=None)
        assert before is not None
        assert before.target == after.target if after else False

    def test_a_regime_outranks_the_knowledge_base(self) -> None:
        """The KB holds generic guidance; a regime is a regulator's requirement.

        Letting the KB win means a deployment under CNSA 2.0 silently receiving ML-KEM-768, which
        that regime rejects — the tool would produce a non-compliant patch for an install that had
        explicitly said which rules it operates under.
        """
        plain = synthesize_rule(self._asset(), "python")
        governed = synthesize_rule(self._asset(), "python", regime="cnsa-2.0")
        assert plain is not None and governed is not None
        assert governed.target["algorithm"] == "ML-KEM-1024"
        assert plain.target["algorithm"] != governed.target["algorithm"], (
            "the KB default already equals the CNSA target, so this test proves nothing — "
            "pick a regime whose default differs"
        )

    def test_a_hybrid_regime_produces_a_composite_target(self) -> None:
        """BSI requires hybrid, so the rule's target must carry BOTH halves.

        This is what makes the downstream machinery correct: the composite relation family, the
        inverted rescan expectation, and the requirement that the classical component survive all
        key off the target string.
        """
        rule = synthesize_rule(self._asset(), "python", regime="bsi-tr-02102")
        assert rule is not None
        assert rule.target["algorithm"] == "X25519MLKEM768"

    def test_the_governed_target_satisfies_the_regime_that_produced_it(self) -> None:
        """The property that ties the two halves of the policy engine together.

        A resolver that emitted a target its own regime rejects would be worse than no resolver:
        the tool would generate the patch and then refuse it.

        Checked through `resolve_target`, which carries `mode`, rather than through the rule's
        target string. Passing a pure target as `hybrid_group` — the obvious shortcut — forces the
        hybrid signal true and would let a construction violation pass unnoticed.
        """
        for name in load_regimes().regimes:
            resolved = resolve_target(self._asset(), regime=name)
            assert resolved is not None, name
            conflicts = resolve_all_regimes(
                algorithm=resolved.target,
                parameter_set=resolved.parameter_set,
                hybrid_group=resolved.hybrid_group,
                mode=resolved.mode,
            )[name]
            assert not [c for c in conflicts if c.blocking], (name, resolved, conflicts)

    def test_that_check_would_notice_a_bad_resolution(self) -> None:
        """The control for the test above. `nist-civil`'s ML-KEM-768 default is a CNSA 2.0
        violation, so mis-routing a CNSA install to it must be visible."""
        wrong = resolve_target(self._asset(), regime="nist-civil")
        assert wrong is not None
        conflicts = resolve_all_regimes(
            algorithm=wrong.target,
            parameter_set=wrong.parameter_set,
            hybrid_group=wrong.hybrid_group,
            mode=wrong.mode,
        )["cnsa-2.0"]
        assert [c.rule for c in conflicts if c.blocking] == ["below-minimum-grade"]


class TestCorrectionsFromThePrimaryTexts:
    """Four corrections from an independent review of the primary standards.

    Each was wrong in a way the executable encodings did not catch, because the OQS compliance
    rules encode what is BLOCKING and these are distinctions between blocking, advisory,
    exempt and merely-not-preferred.
    """

    def test_a_standalone_hash_based_signature_is_not_a_bsi_violation(self) -> None:
        """**The false positive.** BSI permits hash-based signatures to run standalone, without
        hybridisation, because collision resistance rests on no structured-lattice assumption and
        there is nothing for a classical half to hedge.

        The engine reported a standalone SLH-DSA as `hybrid-required` VIOLATION under BSI — the
        regime that most explicitly approves it.
        """
        verdicts = resolve_all_regimes(algorithm="SLH-DSA", parameter_set="SLH-DSA-SHA2-128s")
        assert verdicts["bsi-tr-02102"] == []
        assert verdicts["anssi"] == [], "ANSSI's Phase 2 carves out hash-based signatures too"

    def test_the_exemption_does_not_leak_to_lattice_schemes(self) -> None:
        """The control. A standalone ML-KEM must still fail BSI — the exemption is for hash-based
        signatures, not a general amnesty."""
        verdicts = resolve_all_regimes(algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024")
        assert _rules(verdicts["bsi-tr-02102"]) == {"hybrid-recommended"}

    def test_anssi_is_stricter_for_certified_products(self) -> None:
        """ANSSI states it has "a twofold role... advisory and regulatory". For general industry
        it encourages hybrid; for French state certification its Phase 2 says post-quantum
        algorithms "SHALL continue to be systematically included inside hybrid mechanisms".

        One flat severity either blocks uncertified French deployments that are fine, or passes
        certified ones that are not.
        """
        general = resolve_all_regimes(
            algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024", certified=False
        )["anssi"]
        certified = resolve_all_regimes(
            algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024", certified=True
        )["anssi"]
        assert [c.severity for c in general] == ["advisory"]
        assert [c.severity for c in certified] == ["violation"]

    def test_certification_does_not_change_a_regime_with_one_role(self) -> None:
        """BSI has a single position — `empfiehlt`, in both modes. The flag must not alter it."""
        for certified in (False, True):
            verdicts = resolve_all_regimes(
                algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024", certified=certified
            )
            assert [c.severity for c in verdicts["bsi-tr-02102"]] == ["advisory"]

    def test_a_permitted_but_unpreferred_hybrid_is_a_notice_not_a_pass(self) -> None:
        """CNSA 2.0 and ASD both permit a hybrid at grade and prefer a pure target — NSA tolerates
        one only as a temporary bridge (protocol standardisation, product availability,
        interoperability). Reporting plain "ok" hides that from an operator choosing an
        architecture; reporting `advisory` would imply an action they need not take.
        """
        verdicts = resolve_all_regimes(
            algorithm="SecP384r1MLKEM1024", hybrid_group="SecP384r1MLKEM1024"
        )
        for regime in ("cnsa-2.0", "asd-ism"):
            (notice,) = verdicts[regime]
            assert notice.severity == "notice"
            assert notice.rule == "construction-not-preferred"
            assert not notice.blocking, "a notice must never change a verdict"

    def test_the_regimes_that_require_hybrid_raise_no_notice_for_one(self) -> None:
        """BSI and ANSSI prefer exactly what they require, so there is nothing to notice."""
        verdicts = resolve_all_regimes(
            algorithm="SecP384r1MLKEM1024", hybrid_group="SecP384r1MLKEM1024"
        )
        assert verdicts["bsi-tr-02102"] == []
        assert verdicts["anssi"] == []

    def test_a_notice_is_not_raised_when_something_blocking_already_is(self) -> None:
        """A sub-grade hybrid under CNSA 2.0 has a real problem; adding "and we prefer pure" to it
        buries the actionable finding."""
        conflicts = resolve_all_regimes(**INDUSTRY_DEFAULT)["cnsa-2.0"]
        assert [c.rule for c in conflicts] == ["below-minimum-grade"]

    def test_asd_carries_its_own_control_reference(self) -> None:
        """ISM-1917 (Rev 3, Sep-25): "ML-KEM-768 will not be approved beyond 2030." Cited rather
        than inferred, which is what lifted this regime off `confidence: secondary`."""
        asd = load_regimes().regimes["asd-ism"]
        assert asd.control_reference == "ISM-1917"
        assert asd.confidence == "verified-secondary"

    def test_cnsa_names_a_firmware_signing_target(self) -> None:
        """SLH-DSA is excluded despite FIPS 205, so firmware signing has nowhere else to go and
        the suite mandates stateful LMS/XMSS instead."""
        defaults = load_regimes().regimes["cnsa-2.0"].defaults
        assert "firmware_signature" in defaults
        assert defaults["firmware_signature"].algorithm == "LMS"


class TestBsiIsRecommendationNotRequirement:
    """Verified against BSI TR-02102-1 Version 2026-01 (23 Jan 2026), the German original.

    The document is in `qubit-v2/vendor/standards/BSI-TR-02102.pdf`. §2.2, verbatim:

        "Um die langfristige Sicherheit einer Schlüsseleinigung zu gewährleisten, EMPFIEHLT diese
         Technische Richtlinie daher den Einsatz eines hybriden Schlüsseleinigungsverfahrens, bei
         dem ein quantensicheres mit einem klassischen Verfahren kombiniert wird."

    `empfiehlt` is "recommends". Not `fordert`, not `muss`. A rules engine that FAILS a pure-PQC
    target under BSI is stricter than the German text and manufactures false positives against a
    guideline asking for best practice.
    """

    def test_bsi_is_sourced_from_the_primary_document(self) -> None:
        bsi = load_regimes().regimes["bsi-tr-02102"]
        assert bsi.confidence == "primary"
        assert "2.2" in bsi.source_section

    def test_a_pure_pqc_target_is_advised_against_not_failed(self) -> None:
        verdicts = resolve_all_regimes(algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024")
        (bsi,) = verdicts["bsi-tr-02102"]
        assert bsi.severity == "advisory"
        assert bsi.rule == "hybrid-recommended"
        assert "recommends" in bsi.detail

    def test_the_wording_tracks_the_severity(self) -> None:
        """`hybrid-required` may only be said where a regime actually requires it.

        Calling BSI's `empfiehlt` "required" misreports the guideline as stricter than it is —
        the same class of error as calling a criterion "verified" when it could not have failed.
        """
        certified = resolve_all_regimes(
            algorithm="ML-KEM-1024", parameter_set="ML-KEM-1024", certified=True
        )
        (anssi,) = certified["anssi"]
        assert anssi.rule == "hybrid-required"
        assert "requires" in anssi.detail
        (bsi,) = certified["bsi-tr-02102"]
        assert bsi.rule == "hybrid-recommended"
        assert "requires" not in bsi.detail

    def test_the_deadlines_are_tiered_and_attach_to_classical_only(self) -> None:
        """Both dates bind what QUBIT migrates AWAY from, not what it migrates TO.

            "Der alleinige Einsatz von klassischen Schlüsseleinigungsverfahren wird nur noch bis
             Ende 2031 empfohlen."
            "Für Anwendungen mit sehr hohem Schutzbedarf sollte die Umstellung auf quantensichere
             Verfahren bereits bis Ende 2030 erfolgen."

        So a pure ML-KEM target never trips them; a codebase still on classical-only does.
        """
        deadlines = load_regimes().regimes["bsi-tr-02102"].deadlines
        assert deadlines["classical_only_kex_general"]["deprecated_by"] == "2031-12-31"
        assert deadlines["classical_only_kex_high_protection"]["deprecated_by"] == "2030-12-31"

    def test_hash_based_signatures_are_exempt_in_the_primary_text_too(self) -> None:
        """Not only ANSSI. BSI §2.2 region, verbatim:

            "...können hashbasierte Signaturen ... grundsätzlich auch alleine (das heißt nicht
             hybrid) zum Einsatz kommen..."

        and it names "zustandsbehafteten und zustandslosen" — stateful AND stateless — so LMS,
        XMSS and SLH-DSA alike.
        """
        exempt = load_regimes().regimes["bsi-tr-02102"].standalone_exempt
        assert {"SLH-DSA", "LMS", "XMSS"} <= set(exempt)


class TestDraftAndBindingAreNotConflated:
    """NIST IR 8547 is still an Initial Public Draft; the binding US deadlines are elsewhere.

    An engine that enforces IR 8547's 2030/2035 dates is enforcing a draft. An engine that tracks
    ONLY IR 8547 would report an agency as compliant in 2031 that is in breach of Executive Order
    14412, whose deadlines are earlier and which reaches federal contractors through the FAR.
    """

    def test_the_draft_is_labelled_as_one(self) -> None:
        deadlines = load_regimes().regimes["nist-civil"].deadlines
        assert deadlines["nist_ir_8547_draft"]["status"] == "initial-public-draft"

    def test_the_binding_mandate_is_recorded_separately(self) -> None:
        deadlines = load_regimes().regimes["nist-civil"].deadlines
        binding = deadlines["eo_14412"]
        assert binding["status"] == "binding"
        assert binding["key_establishment"]["required_by"] == "2030-12-31"
        assert binding["digital_signatures"]["required_by"] == "2031-12-31"

    def test_the_binding_deadline_is_not_later_than_the_draft(self) -> None:
        """The reason both are kept. If the draft were the stricter one, tracking only it would be
        merely redundant; it is the looser one, so tracking only it under-reports."""
        deadlines = load_regimes().regimes["nist-civil"].deadlines
        draft = deadlines["nist_ir_8547_draft"]["rsa_2048_ecc_p256"]
        draft_disallowed = int(draft["disallowed_by"])
        binding_year = int(deadlines["eo_14412"]["digital_signatures"]["required_by"][:4])
        assert binding_year < draft_disallowed

    def test_it_records_what_the_order_superseded(self) -> None:
        """NSM-10 and M-23-02 are widely cited and no longer govern. A table that still names them
        as current sends an operator to the wrong document."""
        superseded = load_regimes().regimes["nist-civil"].deadlines["eo_14412"]["supersedes"]
        assert "NSM-10" in superseded


class TestTheAnssiPlatformCarveOut:
    """ANSSI's hybrid mandate depends on what KIND of product is being certified.

    Section 4 of the December 2023 follow-up paper splits products in two. An `end` product
    "shall implement hybridation". An `intermediate` one -- "platform products that provide raw
    cryptographic functionalities to an upper (applicative) layer" -- may ship pure PQC, because
    "hybridation will be part of upper user-oriented layers".

    A cryptographic library is an intermediate product, and libraries are most of what this tool
    migrates. Getting this wrong fails the majority case against a rule written for someone else.
    """

    def _kem(self, **kw: object) -> list[str]:
        catalog = load_regimes()
        conflicts = check_target(
            catalog.regimes["anssi"],
            "anssi",
            "ML-KEM",
            "ML-KEM-768",
            **kw,  # type: ignore[arg-type]
        )
        return [f"{c.rule}:{c.severity}" for c in conflicts if c.rule.startswith("hybrid")]

    def test_an_end_product_seeking_a_visa_must_hybridise(self) -> None:
        assert self._kem(certified=True, product_class="end") == ["hybrid-required:violation"]

    def test_a_platform_product_may_ship_pure_pqc(self) -> None:
        """The carve-out. Same algorithm, same certification track, different verdict."""
        assert self._kem(certified=True, product_class="intermediate") == [
            "hybrid-recommended:advisory"
        ]

    def test_an_unstated_product_class_gets_the_strict_answer(self) -> None:
        """Silence is not a claim to the exemption.

        A caller who does not say what they are building is answered as an end product, which is
        the stricter reading. The opposite default would hand every unlabelled migration a
        permission it never asked for and may not qualify for.
        """
        assert self._kem(certified=True) == ["hybrid-required:violation"]

    def test_the_carve_out_carries_the_conditions_it_is_conditional_on(self) -> None:
        """The whole reason this is a downgrade and not a pass.

        ANSSI "will require in that case" a test-purpose hybridation mode and a user-guidance
        recommendation. A downgrade that dropped them would turn a conditional permission into an
        unconditional one -- the same defect as a success criterion that cannot fail.
        """
        catalog = load_regimes()
        conflicts = check_target(
            catalog.regimes["anssi"],
            "anssi",
            "ML-KEM",
            "ML-KEM-768",
            certified=True,
            product_class="intermediate",
        )
        detail = next(c.detail for c in conflicts if c.rule.startswith("hybrid"))
        assert "test purposes" in detail
        assert "user guidance" in detail

    def test_the_carve_out_belongs_to_the_certification_track_only(self) -> None:
        """Outside certification there is no mandate to carve out of.

        Asserted against a SYNTHETIC regime rather than ANSSI, deliberately. ANSSI's general and
        intermediate severities are both `advisory`, so running this against the shipped entry
        compares two values that are equal whatever the code does -- it would pass with the
        `certified` check deleted entirely. This regime makes them differ, so the assertion has
        something to catch.
        """
        strict = Regime(
            authority="synthetic",
            construction="hybrid",
            hybrid_severity="violation",
            intermediate_product_severity="advisory",
        )
        # `product_class` passed here deliberately. Without it the call exercises the default
        # path, not the carve-out path, and the assertion holds with the `certified` gate deleted
        # -- which a mutation run confirmed before this line named the class.
        uncertified = check_target(
            strict, "synthetic", "ML-KEM", "ML-KEM-768", product_class="intermediate"
        )
        assert [c.severity for c in uncertified] == ["violation"]
        certified = check_target(
            strict,
            "synthetic",
            "ML-KEM",
            "ML-KEM-768",
            certified=True,
            product_class="intermediate",
        )
        assert [c.severity for c in certified] == ["advisory"]


class TestOneAlgorithmThreeVerdicts:
    """SLH-DSA is where the regimes diverge most, and every side is now a direct quote.

    ANSSI section 4 exempts "XMSS, LMS or SPHINCS+" from hybridation by name. BSI TR-02102-1
    section 2.2 exempts hash-based signatures "zustandsbehafteten und zustandslosen" -- stateful
    and stateless alike. The NSA's CNSA 2.0 FAQ says it "is not part of CNSA and is not approved
    for any use in NSS".

    Two regimes grant it a special exemption; the third bans it. No target satisfies all three,
    and that is the finding rather than a gap to be papered over.
    """

    def _verdict(self, regime_name: str) -> list[str]:
        catalog = load_regimes()
        return [
            c.rule
            for c in check_target(
                catalog.regimes[regime_name],
                regime_name,
                "SLH-DSA",
                "SLH-DSA-SHA2-192s",
                certified=True,
                product_class="end",
            )
        ]

    @pytest.mark.parametrize("regime_name", ["anssi", "bsi-tr-02102"])
    def test_the_european_regimes_exempt_it_even_under_certification(
        self, regime_name: str
    ) -> None:
        """Not merely "permitted" -- exempt from the hybrid requirement that binds everything
        else. ANSSI's certified track is a hard `shall`, and a standalone SLH-DSA still clears
        it."""
        assert self._verdict(regime_name) == []

    def test_cnsa_bans_the_algorithm_the_others_single_out_for_exemption(self) -> None:
        assert "excluded-algorithm" in self._verdict("cnsa-2.0")

    def test_no_construction_satisfies_all_three(self) -> None:
        """The claim the divergence rests on, asserted rather than described.

        Hybridising to appease CNSA does not work either: the exclusion is checked before grade
        and construction precisely because an excluded algorithm has no compliant form.
        """
        catalog = load_regimes()
        for group in (None, "ECDSA-P384+SLH-DSA"):
            conflicts = check_target(
                catalog.regimes["cnsa-2.0"], "cnsa-2.0", "SLH-DSA", "SLH-DSA-SHA2-192s", group
            )
            assert any(c.rule == "excluded-algorithm" for c in conflicts)


class TestTheUniversalTargetUnderCertification:
    """The universal target, re-checked under the strictest reading of every regime.

    `TestTheUniversalTarget` establishes that `SecP384r1MLKEM1024` is blocked by none in the
    general case. That is the weaker claim: ANSSI's certified track turns its hybrid advisory into
    a `shall`, and a target that clears the advisory version tells you nothing about the mandatory
    one. These re-run the sweep with `certified=True`, which is the context an operator seeking a
    French security visa is actually in.

    The hypothesis was blocked on a question the reference implementations could not answer -- they
    showed a sub-1024 hybrid violates CNSA, not whether CNSA objects to the hybrid CONSTRUCTION.
    The NSA's own FAQ settles it: "will not require" is not "will not permit".
    """

    def _worst(self, algorithm: str, parameter_set: str | None, group: str | None) -> str:
        catalog = load_regimes()
        worst = "clean"
        for name, regime in catalog.regimes.items():
            for conflict in check_target(
                regime,
                name,
                algorithm,
                parameter_set,
                group,
                certified=True,
                product_class="end",
            ):
                if conflict.severity == "violation":
                    return "violation"
                if conflict.severity == "advisory":
                    worst = "advisory"
                elif worst == "clean":
                    worst = "notice"
        return worst

    def test_it_survives_the_certified_track_too(self) -> None:
        """The claim the recommendation rests on. Its worst verdict anywhere, under the hardest
        reading available, is a preference."""
        assert self._worst("ML-KEM", "ML-KEM-1024", "SecP384r1MLKEM1024") == "notice"

    def test_a_pure_target_at_the_same_grade_does_not(self) -> None:
        """Grade alone is not sufficient, which is why the recommendation names a construction.

        ML-KEM-1024 standalone satisfies every grade minimum in the catalog and still trips
        ANSSI's certified mandate.
        """
        assert self._worst("ML-KEM", "ML-KEM-1024", None) == "violation"

    def test_but_a_pure_target_is_fine_for_a_platform_product(self) -> None:
        """And this is why `product_class` had to exist. Same algorithm, same certified track --
        a library is permitted what an end product is not."""
        catalog = load_regimes()
        conflicts = check_target(
            catalog.regimes["anssi"],
            "anssi",
            "ML-KEM",
            "ML-KEM-1024",
            certified=True,
            product_class="intermediate",
        )
        assert [c.severity for c in conflicts] == ["advisory"]

    def test_the_catalog_records_it_as_confirmed_and_names_what_settled_it(self) -> None:
        """A recommendation a reader cannot audit is worth less than none.

        The entry was `status: hypothesis, blocks_on: CNSA 2.0 primary text` for as long as that
        text was unread. Promoting it has to come with the document that unblocked it.
        """
        import yaml
        from qubit_migrate.regimes import _REGIMES_PATH

        raw = yaml.safe_load(_REGIMES_PATH.read_text(encoding="utf-8"))
        entry = raw["universal_target"]
        assert entry["status"] == "confirmed"
        assert entry["kex"] == "SecP384r1MLKEM1024"
        assert "FAQ" in entry["resolved_by"]


class TestTheCnsaTimelineIsPerAssetClass:
    """CNSA 2.0 has six deadlines, not one, and the spread between them is five years.

    Checked line by line against the NSA's own "Commercial National Security Algorithm Suite 2.0"
    PDF. This is the one part of the catalog the primary text CONFIRMED without correcting, and it
    was also the one part no test covered -- six dates that an edit could have silently changed.

    The per-class structure matters to a migration tool because the class is a property of the
    asset. Firmware signing must be exclusively CNSA 2.0 by 2030; a web server has until 2033.
    Collapsing them to a single date either raises false urgency on most assets or under-reports
    it on the ones that are genuinely nearest.
    """

    def _deadlines(self) -> dict[str, dict[str, int]]:
        return load_regimes().regimes["cnsa-2.0"].deadlines

    @pytest.mark.parametrize(
        ("asset_class", "support_by", "exclusive_by"),
        [
            ("software_firmware_signing", 2025, 2030),
            ("web_browsers_servers_cloud", 2025, 2033),
            ("traditional_networking", 2026, 2030),
            ("operating_systems", 2027, 2033),
            ("niche_equipment", 2030, 2033),
        ],
    )
    def test_each_class_carries_the_dates_the_advisory_states(
        self, asset_class: str, support_by: int, exclusive_by: int
    ) -> None:
        entry = self._deadlines()[asset_class]
        assert entry["support_by"] == support_by
        assert entry["exclusive_by"] == exclusive_by

    def test_custom_and_legacy_has_no_support_date_because_the_advisory_gives_none(self) -> None:
        """ "Custom applications and legacy equipment: update or replace by 2033" -- there is no
        prefer-by milestone for this class, and inventing one to make the table uniform would be
        asserting something the NSA did not say."""
        entry = self._deadlines()["custom_and_legacy"]
        assert entry["exclusive_by"] == 2033
        assert "support_by" not in entry

    def test_the_outer_horizon_is_not_earlier_than_any_class(self) -> None:
        """2035 is the whole-of-NSS completion date, "in line with NSM-10". A per-class deadline
        later than it would mean the table contradicts its own horizon."""
        horizon = self._deadlines()["all_nss_complete"]["exclusive_by"]
        assert horizon == 2035
        for name, entry in self._deadlines().items():
            if name != "all_nss_complete":
                assert entry["exclusive_by"] <= horizon, name

    def test_signing_is_the_most_urgent_class(self) -> None:
        """The property a report should lead with, asserted rather than assumed.

        Software and firmware signing is where CNSA 2.0 bites first -- 2030, and "begin
        transitioning immediately". A long-lived signing key is also the asset a
        harvest-now-decrypt-later adversary gains most from, so this ordering is not an accident
        of the table.
        """
        deadlines = self._deadlines()
        earliest = min(
            (n for n in deadlines if n != "all_nss_complete"),
            key=lambda n: (deadlines[n]["exclusive_by"], deadlines[n].get("support_by", 9999)),
        )
        assert earliest == "software_firmware_signing"


class TestEveryKeyInTheYamlReachesTheModel:
    """A key the model does not declare is silently dropped, and the catalog lies by omission.

    This is not hypothetical. `protocol_deadlines` was added to `regimes.yaml` with the BSI TLS
    horizons in it, the file loaded without error, and the data was inert -- pydantic ignored the
    unknown key and every reader saw an empty dict. Nothing failed; the fact simply was not there.

    A typo in a field name fails exactly the same way, which makes this the cheapest guard in the
    file: it turns a silent drop into a named failure.
    """

    def test_no_regime_carries_a_key_the_model_would_discard(self) -> None:
        import yaml
        from qubit_migrate.regimes import _REGIMES_PATH

        raw = yaml.safe_load(_REGIMES_PATH.read_text(encoding="utf-8"))
        declared = set(Regime.model_fields)
        for name, entry in raw["regimes"].items():
            unknown = set(entry) - declared
            assert not unknown, f"{name} carries keys the Regime model drops: {sorted(unknown)}"


class TestTlsOneTwoIsAMigrationBlocker:
    """BSI ends TLS 1.2's recommendation for a POST-QUANTUM reason, and that changes the advice.

    TR-02102-2 (the TLS profile, a different document from the -1 the rest of the entry comes
    from), Version 2026-01, section 3.2: TLS 1.2 is recommended "bis Ende 2031" -- and the stated
    ground is not that it is old or broken:

        "da nach derzeitigem Kenntnisstand keine quantensicheren Schlüsseleinigungsverfahren für
         TLS 1.2 standardisiert werden"

    No quantum-safe key agreement will be standardised for it. So a TLS 1.2 listener is not a
    weak-protocol finding that can be left until later; it is a path on which the hybrid group
    QUBIT installs can never be negotiated, at any date.
    """

    def test_the_horizon_and_its_reason_are_both_recorded(self) -> None:
        """The reason is load-bearing. "TLS 1.2 expires in 2031" invites an operator to schedule
        it like any other deprecation; "no PQC will ever be standardised for it" tells them the
        migration is blocked until they move."""
        entry = load_regimes().regimes["bsi-tr-02102"].protocol_deadlines["tls_1_2"]
        assert entry["recommended_until"] == 2031
        assert "PQC" in entry["reason"] or "quantum" in entry["reason"].lower()

    def test_tls_1_3_outlives_tls_1_2(self) -> None:
        deadlines = load_regimes().regimes["bsi-tr-02102"].protocol_deadlines
        assert str(deadlines["tls_1_3"]["recommended_until"]).startswith("2032")
        assert deadlines["tls_1_2"]["recommended_until"] < 2032

    def test_the_older_versions_are_not_merely_late_but_unrecommended(self) -> None:
        """TLS 1.0/1.1 and SSLv2/v3 carry no date at all. Giving them one would imply they are
        acceptable until then, and `cfg-tls-01` removes them outright."""
        deadlines = load_regimes().regimes["bsi-tr-02102"].protocol_deadlines
        assert "TLS 1.0" in deadlines["not_recommended"]
        assert "SSLv3" in deadlines["not_recommended"]
        for version in deadlines["not_recommended"]:
            assert version.replace(" ", "_").replace(".", "_").lower() not in deadlines

    def test_the_config_rule_cites_the_standard_for_the_compromise_it_makes(self) -> None:
        """`cfg-tls-01` deliberately RETAINS TLS 1.2, because dropping it breaks clients. That is
        the right behaviour and the wrong thing to leave unexplained: a reader should be able to
        tell a considered, dated compromise from an oversight.
        """
        rule = Path(
            "packages/qubit-migrate/src/qubit_migrate/transform/rules/cfg-tls-01.yaml"
        ).read_text(encoding="utf-8")
        assert "TR-02102-2" in rule
        assert "2031" in rule
        # And it still retains TLS 1.2 -- the citation explains the compromise, it does not undo it.
        assert "Never remove TLSv1.2" in rule


class TestIntendedIsNotApproved:
    """BSI names two SSH hybrid KEX algorithms it will recommend *once the RFC is adopted*.

    TR-02102-4 Version 2026-01 section 3.1.3: it intends to recommend `mlkem768nistp256-sha256`
    and `mlkem1024nistp384-sha384` "sobald der zugehörige RFC verabschiedet wurde". Neither is
    approved yet, and neither is negotiable by any shipped SSH server.

    This is the same trap as NIST IR 8547: a draft treated as current makes the tool report a
    requirement nobody has issued, and here it would additionally make it emit a config that
    cannot be negotiated at all. The catalog keeps the two in separate fields so they cannot be
    read as one.
    """

    def test_the_intended_algorithms_are_not_in_any_approved_list(self) -> None:
        regime = load_regimes().regimes["bsi-tr-02102"]
        intended = regime.intended_recommendations["ssh_hybrid_kex"]["algorithms"]
        assert intended  # the fixture is only meaningful if there is something to confuse
        approved = {a.upper() for a in regime.approved_hybrid_kex + regime.also_approved}
        for algorithm in intended:
            assert algorithm.upper() not in approved, f"{algorithm} is listed as approved"

    def test_the_entry_says_it_is_pending(self) -> None:
        """A reader who sees only the algorithm names would take them as current. The status and
        the draft it comes from have to travel with them."""
        entry = load_regimes().regimes["bsi-tr-02102"].intended_recommendations["ssh_hybrid_kex"]
        assert "pending" in entry["status"].lower()
        assert "draft" in entry["source"].lower()

    def test_classical_ssh_kex_has_the_same_2031_horizon_as_tls(self) -> None:
        """The two profiles agree, and both give the post-quantum reason. That consistency is
        worth pinning: a divergence between them would be a transcription error, not a policy."""
        deadlines = load_regimes().regimes["bsi-tr-02102"].protocol_deadlines
        assert deadlines["ssh_classical_kex"]["recommended_until"] == 2031
        assert deadlines["tls_1_2"]["recommended_until"] == 2031

    def test_the_ssh_rule_emits_what_openssh_can_actually_negotiate(self) -> None:
        """The rule stays on `sntrup761x25519-sha512` deliberately.

        It is NTRU Prime rather than ML-KEM, so it is post-quantum but not on the standards track
        BSI names. Emitting BSI's intended pair instead would produce a config no shipped server
        negotiates -- which fails at the apply stage, never mind the rescan. The gap is recorded in
        the rule rather than quietly left for a reader to discover.
        """
        rule = Path(
            "packages/qubit-migrate/src/qubit_migrate/transform/rules/cfg-ssh-01.yaml"
        ).read_text(encoding="utf-8")
        assert "sntrup761x25519-sha512" in rule
        assert "NTRU Prime" in rule
        assert "TR-02102-4" in rule
        # And it does NOT emit the intended-but-unstandardised algorithms.
        for algorithm in ("mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"):
            assert f"KexAlgorithms {algorithm}" not in rule
