"""Rung 3 of the evidence ladder, in Ruby.

`_stage_behaves` refused every language but Python, so the rung that runs the migrated cryptography
and checks it both works and *fails when it should* was unreachable for three of the four twins.

These tests are the admission controls plus the traps that were measured while building the harness.
Each trap would, on its own, have made the oracle useless in a specific direction — and two of them
were found by the controls failing, not by reading documentation:

* **Ruby's signature `verify` returns a boolean; Python's raises.** A negative written the Python way
  never fires, so a `verify` that ignores its arguments passes all three negatives and the harness
  licenses itself while catching nothing.
* **AEAD rejection is the opposite — it raises.** Within one library the two families need opposite
  handling, and neither can be inferred from the other.
* **GCM accepts a TRUNCATED tag.** 15 bytes verify; so do 8. Truncation is a valid GCM
  configuration (RFC 5116), not tampering — only a *modified* tag byte is rejected. Python's
  `AESGCM` enforces a minimum length, so the same relation is a real negative there and a
  correct-patch-rejector here. It failed the admission control before it was measured.

Marked `docker` because every one of them runs a real container: an oracle asserted about rather
than executed is the thing the admission gate exists to prevent.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from qubit_migrate.oracles.ruby_harness import (
    RUBY_SHAPES,
    UNSUPPORTED,
    _RB_AEAD_CORRECT,
    _RB_AEAD_IGNORES_TAG,
    _RB_SIG_ACCEPTS_ANYTHING,
    _RB_SIG_CORRECT,
    build,
    parameter_set,
    ruby_controls,
)

_IMAGE = "qubit-eval/inkwell:sandbox"


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(
        ["docker", "image", "inspect", _IMAGE], capture_output=True, timeout=60
    )
    return probe.returncode == 0


docker_required = pytest.mark.skipif(
    not _docker_ready(), reason=f"{_IMAGE} is not built; QUBIT never pulls an image itself"
)


# ─────────────────────────────────────────────────────────── the parts that need no container ──


class TestPlanConstruction:
    def test_the_parameter_set_comes_from_the_patch(self) -> None:
        """Reading it from the patch is what makes the oracle exercise the patch's OWN choice.

        A rewrite naming a parameter set the provider lacks then fails at construction, with a
        verdict against the patch — something a harness hardcoding the rule's target could never
        discover.
        """
        assert parameter_set('k = OpenSSL::PKey.generate_key("ML-DSA-87")', "ML-DSA-65") == "ML-DSA-87"

    def test_the_rule_target_is_the_fallback(self) -> None:
        assert parameter_set("nothing here", "ML-DSA-65") == "ML-DSA-65"

    def test_one_file_with_several_primitives_gives_each_family_its_own(self) -> None:
        """The bug that made the oracle reject correct patches.

        `inkwell-esign`'s `internal.rb` holds five weak-hash findings and one AES-GCM call. An
        unfiltered scan returned the first literal in the file — `aes-256-gcm` — for every one of
        them, the hash setup ran `OpenSSL::Digest.new("aes-256-gcm")`, and all five correct patches
        failed with `Unsupported digest algorithm`.

        No unit fixture could catch it: each names one primitive, so any selection rule looks right.
        It took a run against a real file through the app.
        """
        source = (
            'def cache_key(x) = OpenSSL::Digest.new("sha256").hexdigest(x)\n'
            'def seal(x) = OpenSSL::Cipher.new("aes-256-gcm")\n'
            'def key = OpenSSL::PKey.generate_key("ML-DSA-65")\n'
        )
        assert parameter_set(source, "SHA-256", "hash") == "sha256"
        assert parameter_set(source, "AES", "aead") == "aes-256-gcm"
        assert parameter_set(source, "ML-DSA-65", "signature") == "ML-DSA-65"

    def test_a_family_target_the_provider_cannot_use_falls_back_to_a_usable_default(self) -> None:
        """`code-weakcipher-01` targets bare `AES` — no key size, no mode.

        No provider accepts that as a cipher name, so passing it through would guarantee a
        construction failure on every correct patch the rule produced.
        """
        assert parameter_set("no literals here", "AES", "aead") == "aes-256-gcm"

    def test_kex_is_reported_unsupported_rather_than_approximated(self) -> None:
        """Ruby's binding has no encapsulate/decapsulate. A KEM relation built on `derive` would
        be exercising a different operation and calling it agreement."""
        from types import SimpleNamespace

        plan = build(SimpleNamespace(family="kex", relations=[]), "x = 1", "ML-KEM-768")
        assert not plan.runnable
        assert "derive" in plan.skip_reason
        assert "kex" in UNSUPPORTED

    def test_an_unprobed_family_produces_no_plan(self) -> None:
        """Never a runnable plan for a family nobody has probed: it would report `pass` for
        relations that never ran."""
        from types import SimpleNamespace

        plan = build(SimpleNamespace(family="mac", relations=[]), "x = 1", "HMAC-SHA256")
        assert not plan.runnable

    @pytest.mark.parametrize(
        ("family", "usage"),
        [("signature", "signature"), ("aead", "data_at_rest"), ("hash", "hash")],
    )
    def test_every_shape_op_names_a_real_relation(self, family: str, usage: str) -> None:
        """A shape keyed on an id the relation table does not use is a relation that silently never
        runs — measured: writing `aead-tampered-tag` for the table's `aead-truncated-tag` cost two
        of five AEAD relations, and nothing reported it."""
        from qubit_migrate.oracles.relations import relations_for

        known = {r.id for r in relations_for(usage, "pure").relations}
        unknown = set(RUBY_SHAPES[family].ops) - known
        assert not unknown, f"{family} names relations the table does not define: {sorted(unknown)}"


# ──────────────────────────────────────────────────────────────────── the oracle, executed ──


@docker_required
class TestTheOracleDiscriminates:
    """The only property that matters. An oracle that cannot fail is indistinguishable from one
    that passes everything, and its verdicts are not evidence."""

    def _run(self, source: str, usage: str, target: str) -> dict:
        from qubit_migrate.transform.validate import _run_ruby_oracle

        return _run_ruby_oracle(source, target, usage, "pure")

    def test_a_correct_signature_migration_passes(self) -> None:
        verdict = self._run(_RB_SIG_CORRECT, "signature", "ML-DSA-65")
        assert verdict["status"] == "pass", verdict.get("reason")

    def test_a_verify_that_accepts_anything_is_caught(self) -> None:
        """And is caught ONLY by the negatives — the claim the whole ladder rests on."""
        verdict = self._run(_RB_SIG_ACCEPTS_ANYTHING, "signature", "ML-DSA-65")
        assert verdict["status"] == "fail"
        outcomes = {r["id"]: r["outcome"] for r in verdict["relations"]}
        assert outcomes["sig-roundtrip"] == "pass", (
            "the round trip must still pass: a no-op verify trivially round-trips, which is why a "
            "smoke test cannot replace this stage"
        )
        for negative in ("sig-wrong-key", "sig-tampered-message", "sig-truncated"):
            assert outcomes[negative] == "fail", negative

    def test_a_correct_aead_migration_passes(self) -> None:
        verdict = self._run(_RB_AEAD_CORRECT, "data_at_rest", "AES-256-GCM")
        assert verdict["status"] == "pass", verdict.get("reason")

    def test_a_decrypt_that_ignores_the_tag_is_caught(self) -> None:
        verdict = self._run(_RB_AEAD_IGNORES_TAG, "data_at_rest", "AES-256-GCM")
        assert verdict["status"] == "fail"
        outcomes = {r["id"]: r["outcome"] for r in verdict["relations"]}
        assert outcomes["aead-roundtrip"] == "pass", "the data still round-trips; that is the trap"
        assert outcomes["aead-wrong-key"] == "fail"
        assert outcomes["aead-tampered-ciphertext"] == "fail"

    def test_a_parameter_set_the_provider_lacks_is_a_verdict_on_the_patch(self) -> None:
        """Distinct from a relation failure: "the primitive misbehaved" and "the primitive could
        not be made" are different findings, and a repair loop needs different feedback."""
        # The source must LOAD cleanly: a file that raises on load is `compiles`' verdict, and the
        # harness says so rather than blaming the cryptography. What is under test here is the
        # SETUP failing — the harness asking the provider for a parameter set it does not have.
        verdict = self._run('ALGORITHM = "ML-DSA-999"', "signature", "ML-DSA-65")
        assert verdict["status"] == "fail", verdict
        assert "could not construct" in verdict["reason"]

    def test_a_file_that_raises_on_load_is_not_blamed_on_the_cryptography(self) -> None:
        verdict = self._run('OpenSSL::PKey.generate_key("ML-DSA-999")', "signature", "ML-DSA-65")
        assert verdict["status"] == "skipped"
        assert "did not load" in verdict["reason"]

    def test_a_file_that_does_not_parse_is_skipped_not_failed(self) -> None:
        """`compiles` owns that verdict. Counting it here would report one defect twice."""
        verdict = self._run("def broken(\n", "signature", "ML-DSA-65")
        assert verdict["status"] == "skipped"
        assert "did not load" in verdict["reason"]


@docker_required
class TestAdmission:
    def test_both_families_are_licensed_by_their_own_controls(self) -> None:
        """A licence is a statement about one harness against one library.

        Python's positive control asserts a broken verify RAISES; Ruby's returns false. Letting
        either license the other would hand a licence to the harness with no working negatives.
        """
        import qubit_migrate.transform.validate as validate

        validate._verified_ruby_families = None
        families = validate.verified_ruby_families()
        assert {"signature", "aead"} <= families, validate.ruby_control_report()

    def test_every_control_behaved(self) -> None:
        import qubit_migrate.transform.validate as validate

        validate._verified_ruby_families = None
        validate.verified_ruby_families()
        report = validate.ruby_control_report()
        assert report is not None
        bad = [(o.control.id, o.detail) for o in report.outcomes if not o.ok]
        assert not bad, bad

    def test_the_control_set_covers_both_directions_per_family(self) -> None:
        """One direction licenses nothing: a family with only a correct-patch control cannot
        distinguish a working oracle from one that always passes."""
        directions: dict[str, set[str]] = {}
        for control in ruby_controls():
            directions.setdefault(control.family, set()).add(control.expect)
        for family, seen in directions.items():
            assert seen == {"pass", "fail"}, f"{family} has only {seen}"


@docker_required
def test_gcm_accepts_a_truncated_tag() -> None:
    """The measurement behind the missing relation, pinned so nobody re-adds it.

    A 15-byte tag verifies and so does an 8-byte one: GCM permits shorter tags, so truncation is a
    configuration rather than tampering. Implementing `aead-truncated-tag` for Ruby on Python's
    reading of it made the correct-AEAD control fail.
    """
    script = (
        'require "openssl"\n'
        "key = OpenSSL::Random.random_bytes(32); n = OpenSSL::Random.random_bytes(12)\n"
        'pt = "probe"\n'
        'c = OpenSSL::Cipher.new("aes-256-gcm"); c.encrypt; c.key = key; c.iv = n\n'
        "ct = c.update(pt) + c.final; tag = c.auth_tag\n"
        'd = OpenSSL::Cipher.new("aes-256-gcm"); d.decrypt; d.key = key; d.iv = n\n'
        "d.auth_tag = tag[0, 8]\n"
        "begin; puts((d.update(ct) + d.final) == pt ? 'ACCEPTED' : 'MISMATCH')\n"
        "rescue OpenSSL::Cipher::CipherError; puts 'REJECTED'; end\n"
    )
    result = subprocess.run(
        ["docker", "run", "--rm", "--network=none", _IMAGE, "ruby", "-e", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    assert result.stdout.strip() == "ACCEPTED", result.stdout + result.stderr
