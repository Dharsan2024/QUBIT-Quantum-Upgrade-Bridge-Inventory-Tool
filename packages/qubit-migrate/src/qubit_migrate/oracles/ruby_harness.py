"""The metamorphic oracle for Ruby patches.

`harness.py` generates a Python driver and `_stage_behaves` refused every other language, which made
rung 3 of the evidence ladder unreachable outside Python. This is its Ruby counterpart: the same
relation families from `params/relations.yaml`, driven against the primitive the patch actually
named, inside the same offline container the tests stage uses.

**Every fact below was probed against the installed library**, on 2026-09-03 inside
`qubit-eval/inkwell:sandbox` (Ruby 3.3, OpenSSL 3.5.7), because Ruby's conventions differ from
Python's in ways that would each make the harness useless:

1. **ML-DSA `verify` RETURNS `false`; it does not raise.** Python's raises `InvalidSignature`, and
   the Python shapes are written around that. A Ruby negative written the Python way — expecting an
   exception — would never fire, so all three signature negatives would pass for a `verify` that
   ignores its arguments entirely. This is the single most important difference here.
2. **AEAD rejection is the opposite: it RAISES** `OpenSSL::Cipher::CipherError`, with an empty
   message. So within one library the two families need opposite handling, and neither can be
   inferred from the other.
3. **An explicit digest is refused for ML-DSA.** `sk.sign(OpenSSL::Digest::SHA256.new, msg)` raises
   `Explicit digest not supported for ML-DSA operations`, and `sign_raw` raises
   `provider signature not supported`. Only `sk.sign(nil, msg)` works — the opposite of every
   classical signature call in the same codebase, where the digest argument is mandatory.
4. **ML-KEM exposes only `derive`.** Ruby's binding has no encapsulate/decapsulate, so the `kex`
   family cannot be expressed and is reported as such rather than approximated. A KEM relation
   built on `derive` would be testing a different operation and calling it agreement.
5. ML-DSA-65 signatures measure **3309 bytes**, matching the Python probe — so the size advisory
   transfers unchanged.

Re-probe on an OpenSSL bump: `sign(nil, ...)` is provider behaviour, not language behaviour.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The parameter set the patch itself named, as a literal.
#:
#: Extracted rather than assumed, so the harness exercises the patch's OWN choice. A patch that
#: wrote `"ML-DSA-999"` fails at construction with a verdict against the patch, which is correct and
#: is not something a harness hardcoding `ML-DSA-65` could ever discover.
_PARAMETER_SET = re.compile(
    r"""["'](?P<name>
        ML-DSA-\d+ | ML-KEM-\d+
      | SLH-DSA[\w-]* | aes-256-gcm | aes-256-cbc | AES-256-GCM
      | sha256 | SHA256 | sha384 | sha512
    )["']""",
    re.VERBOSE,
)


@dataclass(frozen=True)
class RubyShape:
    """How to build and exercise one primitive family in Ruby.

    `setup` binds the names the ops use; `ops` are keyed by the relation id they serve, exactly as
    in `shapes.py`, so both languages are driven from one relation table.
    """

    family: str
    setup: str
    ops: dict[str, str]


#: `record` is defined by the driver template. Each op sets `ok` to the relation's truth value.
RUBY_SHAPES: dict[str, RubyShape] = {
    "signature": RubyShape(
        family="signature",
        # `generate_key` on the parameter set the patch named. A name the provider does not know
        # raises here, and that is a verdict on the patch rather than a relation failure.
        setup=(
            "sk  = OpenSSL::PKey.generate_key(PARAM)\n"
            "sk2 = OpenSSL::PKey.generate_key(PARAM)\n"
            "sig = sk.sign(nil, MSG)\n"
        ),
        ops={
            # Probed: verify RETURNS a boolean. Written as an equality on purpose -- an
            # exception-based negative would be vacuous here and would pass a no-op verify.
            "sig-roundtrip": (
                'record("sig-roundtrip", "positive", sk.verify(nil, sig, MSG) == true)'
            ),
            "sig-wrong-key": (
                'record("sig-wrong-key", "negative", sk2.verify(nil, sig, MSG) == false)'
            ),
            "sig-tampered-message": (
                'record("sig-tampered-message", "negative", '
                "sk.verify(nil, sig, MSG_TAMPERED) == false)"
            ),
            "sig-truncated": (
                'record("sig-truncated", "negative", sk.verify(nil, sig[0..-2], MSG) == false)'
            ),
            "sig-size-class": (
                'record("sig-size-class", "advisory", sig.bytesize > 1000, "#{sig.bytesize} bytes")'
            ),
        },
    ),
    "aead": RubyShape(
        family="aead",
        setup=(
            "key = OpenSSL::Random.random_bytes(32)\n"
            "n1  = OpenSSL::Random.random_bytes(12)\n"
            "ct, tag = qubit_seal(key, n1, MSG)\n"
        ),
        ops={
            "aead-roundtrip": (
                'record("aead-roundtrip", "positive", qubit_open(key, n1, ct, tag) == MSG)'
            ),
            # Probed: rejection RAISES CipherError, the opposite of the signature family above.
            # `qubit_open` returns nil on any CipherError so a raise reads as rejection.
            "aead-wrong-key": (
                'record("aead-wrong-key", "negative", '
                "qubit_open(OpenSSL::Random.random_bytes(32), n1, ct, tag).nil?)"
            ),
            "aead-tampered-ciphertext": (
                'record("aead-tampered-ciphertext", "negative", '
                'qubit_open(key, n1, ct[0..-2] + "X", tag).nil?)'
            ),
            # `aead-truncated-tag` is DELIBERATELY not implemented for Ruby, and this is a
            # per-language difference rather than an omission.
            #
            # Probed: OpenSSL's GCM ACCEPTS a truncated tag. A 15-byte tag verifies, and so does an
            # 8-byte one -- GCM permits shorter tags (RFC 5116), so truncation is a valid
            # configuration and not tampering. A MODIFIED tag byte is rejected.
            #
            # Python's `AESGCM` enforces a minimum tag length, so the same relation is a real
            # negative there. Implementing it here on that basis would have failed the correct-AEAD
            # admission control -- which is exactly what it did before this was measured, and is
            # how a harness comes to reject every good patch in a language.
            #
            # The bit-flip case that IS a rejection has no id in the relation table, so it is not
            # invented here; `aead-wrong-key` and `aead-tampered-ciphertext` both caught the
            # ignores-the-tag control on their own.
            # A constant nonce is invisible to every other gate and directly observable here.
            "aead-nonce-uniqueness": (
                'record("aead-nonce-uniqueness", "negative", '
                "qubit_seal(key, OpenSSL::Random.random_bytes(12), MSG)[0] != ct)"
            ),
            # GCM appends a 16-byte tag, so an authenticated ciphertext is strictly longer
            # than its plaintext. A rewrite that dropped authentication is visible here too.
            "aead-ciphertext-expansion": (
                'record("aead-ciphertext-expansion", "advisory", '
                "(ct.bytesize + tag.bytesize) > MSG.bytesize, "
                '"#{ct.bytesize}+#{tag.bytesize} vs #{MSG.bytesize}")'
            ),
        },
    ),
    "hash": RubyShape(
        family="hash",
        setup="digest = OpenSSL::Digest.new(PARAM)\n",
        ops={
            # The ids are the relation table's, not descriptive names of my choosing. A shape keyed
            # on an id the table does not define is a relation that silently never runs, and the
            # stage still reports `pass` for the ones that did -- so the gate looks healthy while
            # testing less than it claims. All three of these were originally misnamed.
            "hash-determinism": (
                'record("hash-determinism", "positive", '
                "digest.digest(MSG) == OpenSSL::Digest.new(PARAM).digest(MSG))"
            ),
            "hash-distinct-inputs": (
                'record("hash-distinct-inputs", "negative", '
                "OpenSSL::Digest.new(PARAM).digest(MSG) != "
                "OpenSSL::Digest.new(PARAM).digest(MSG_TAMPERED))"
            ),
            "hash-digest-length": (
                'record("hash-digest-length", "advisory", '
                "OpenSSL::Digest.new(PARAM).digest(MSG).bytesize >= 32, "
                '"#{OpenSSL::Digest.new(PARAM).digest(MSG).bytesize} bytes")'
            ),
        },
    ),
}

#: Families Ruby's binding cannot express, with the reason. Reported rather than approximated: a
#: KEM relation built on `derive` would be exercising a different operation and calling it
#: agreement, which is how an oracle comes to pass everything.
UNSUPPORTED: dict[str, str] = {
    "kex": (
        "Ruby's OpenSSL binding exposes only `derive` for ML-KEM, with no encapsulate/decapsulate, "
        "so KEM agreement cannot be stated as a relation rather than approximated"
    ),
}

_TEMPLATE = """\
# Generated by qubit_migrate.oracles.ruby_harness -- do not edit.
require "openssl"
require "json"

MSG = "qubit-oracle-probe-message"
MSG_TAMPERED = "qubit-oracle-probe-messagX"
PARAM = __PARAM__

RESULTS = []

def record(rid, kind, ok, detail = "")
  RESULTS << {"id" => rid, "kind" => kind,
              "outcome" => (ok ? "pass" : "fail"), "detail" => detail.to_s[0, 400]}
rescue => e
  RESULTS << {"id" => rid, "kind" => kind, "outcome" => "fail",
              "detail" => "#{e.class}: #{e.message[0, 200]}"}
end

# AEAD rejection RAISES rather than returning a value, so the helpers below turn a raise into nil.
# Every negative in that family is written against nil, which keeps "rejected" one shape.
def qubit_seal(key, nonce, pt, aad = nil)
  c = OpenSSL::Cipher.new("aes-256-gcm")
  c.encrypt; c.key = key; c.iv = nonce; c.auth_data = aad.to_s
  [c.update(pt) + c.final, c.auth_tag]
end

def qubit_open(key, nonce, ct, tag, aad = nil)
  c = OpenSSL::Cipher.new("aes-256-gcm")
  c.decrypt; c.key = key; c.iv = nonce; c.auth_tag = tag; c.auth_data = aad.to_s
  c.update(ct) + c.final
rescue OpenSSL::Cipher::CipherError
  nil
end

def bail(reason)
  puts JSON.generate({"status" => "skipped", "reason" => reason, "relations" => RESULTS})
  exit 0
end

begin
  load __MODULE_PATH__
rescue Exception => e
  # Not a verdict on the cryptography: the file did not load, which `compiles` already judges.
  # Skipped so one failure is not counted twice under two names.
  bail("patched file did not load: #{e.class}: #{e.message[0, 200]}")
end

begin
__SETUP__
rescue Exception => e
  # A construction failure IS a verdict on the patch -- the primitive it named cannot be built the
  # way its family is built -- but it is distinct from a relation failure, and a repair loop needs
  # different feedback for each.
  puts JSON.generate({
    "status" => "fail",
    "reason" => "could not construct #{PARAM}: #{e.class}: #{e.message[0, 200]}",
    "relations" => RESULTS,
  })
  exit 0
end

__BODY__

failed = RESULTS.select { |r| r["outcome"] == "fail" && r["kind"] != "advisory" }
puts JSON.generate({
  "status" => failed.empty? ? "pass" : "fail",
  "reason" => failed.map { |r| "#{r['id']}: #{r['detail']}" }.join("; "),
  "relations" => RESULTS,
})
"""


@dataclass(frozen=True)
class RubyPlan:
    """A driver ready to run, or the reason there is none."""

    source: str = ""
    skip_reason: str = ""

    @property
    def runnable(self) -> bool:
        return bool(self.source)


#: Which parameter sets belong to which family, so a file containing several does not hand one
#: family another's name.
_FAMILY_PARAMETERS: dict[str, re.Pattern[str]] = {
    # `ML-DSA-\d+`, not just the three real ones: a patch naming `ML-DSA-999` must be CLAIMED by
    # this family so it reaches the provider and fails at construction. Excluding it here would
    # hand the family its default instead, and a rewrite naming a parameter set that does not
    # exist would be silently corrected into one that does.
    "signature": re.compile(r"^(ML-DSA-\d+|SLH-DSA)", re.IGNORECASE),
    "aead": re.compile(r"^(aes-256-gcm|AES-256-GCM|chacha20-poly1305)$", re.IGNORECASE),
    "hash": re.compile(r"^(sha256|sha384|sha512|SHA-?256|SHA-?384|SHA-?512)$", re.IGNORECASE),
}

#: What to hand the provider when the patch names nothing this family can use.
_FAMILY_DEFAULT: dict[str, str] = {
    "signature": "ML-DSA-65",
    "aead": "aes-256-gcm",
    "hash": "sha256",
}


def parameter_set(patched_source: str, target_algorithm: str, family: str = "") -> str:
    """The parameter set THIS patch named for THIS family, falling back to the rule's target.

    Reading it from the patch is what makes the oracle exercise the patch's own choice: a rewrite
    naming a parameter set the provider does not have fails at construction, with a verdict against
    the patch. A harness that hardcoded the rule's target could never find that.

    **Filtered by family, because one file holds several.** `inkwell-esign`'s `internal.rb` contains
    five weak-hash findings and one AES-GCM call, and an unfiltered scan returned the first literal
    in the file — `aes-256-gcm` — for every one of them. The hash setup then ran
    `OpenSSL::Digest.new("aes-256-gcm")` and every correct patch failed with
    `Unsupported digest algorithm`. Five of the twin's findings were rejected by their own oracle.

    Unit fixtures could not catch that: each names one primitive, so any selection rule looks right.
    It took a run against a real file through the app.
    """
    wanted = _FAMILY_PARAMETERS.get(family)
    for match in _PARAMETER_SET.finditer(patched_source):
        name = match.group("name")
        if wanted is None or wanted.match(name):
            return name
    if wanted is not None and not wanted.match(target_algorithm):
        # The rule's target does not belong to this family either — a hash rule targeting `SHA-256`
        # is fine, but `code-weakcipher-01` targets `AES` with no key size and no mode, which is not
        # a name any provider accepts. Use the family's own default rather than a guaranteed
        # failure.
        return _FAMILY_DEFAULT.get(family, target_algorithm)
    return target_algorithm


def build(relation_set: object, patched_source: str, target_algorithm: str) -> RubyPlan:
    """A Ruby driver for `relation_set`, or a plan that says why there is none."""
    family = str(getattr(relation_set, "family", "") or "")
    if not family:
        return RubyPlan(skip_reason="no relation family applies to this finding")
    if family in UNSUPPORTED:
        return RubyPlan(skip_reason=UNSUPPORTED[family])
    shape = RUBY_SHAPES.get(family)
    if shape is None:
        return RubyPlan(skip_reason=f"no Ruby shape has been probed for the {family!r} family")

    wanted = [
        r.id for r in getattr(relation_set, "relations", ()) if getattr(r, "id", None) in shape.ops
    ]
    if not wanted:
        return RubyPlan(skip_reason=f"none of the {family!r} relations has a probed Ruby form")

    param = parameter_set(patched_source, target_algorithm, family)
    setup = "\n".join("  " + line for line in shape.setup.strip().splitlines())
    body = "\n".join(shape.ops[rid] for rid in wanted)
    source = (
        _TEMPLATE.replace("__PARAM__", repr(param).replace("'", '"'))
        .replace("__SETUP__", setup)
        .replace("__BODY__", body)
    )
    return RubyPlan(source=source)


#: A correct Ruby ML-DSA migration. If the oracle fails this, it rejects good patches.
_RB_SIG_CORRECT = """\
require "openssl"

# A migration to ML-DSA-65. Nothing here overrides the primitive; the oracle exercises the
# provider's own implementation, which is the point of a negative control.
def signing_key
  OpenSSL::PKey.generate_key("ML-DSA-65")
end

def sign_document(key, bytes)
  key.sign(nil, bytes)
end
"""

#: A rewrite whose `verify` accepts anything.
#:
#: This is the patch the whole evidence ladder exists to catch, and every other gate passes it: it
#: applies, it parses, its names resolve, it compiles, and the scanner reports ML-DSA-65 where SHA-1
#: used to be, so `rescan` passes too. Measured in `qubit-eval/inkwell:sandbox`: its ROUND TRIP also
#: passes, and its signature is a real 3309-byte ML-DSA signature so the size advisory reads
#: correct.
#: Only the three negatives catch it.
_RB_SIG_ACCEPTS_ANYTHING = """\
require "openssl"

# A migration to ML-DSA-65 -- with a verify that never says no.
module OpenSSL
  module PKey
    class PKey
      def verify(*) = true
    end
  end
end
"""

#: A correct AES-256-GCM migration.
_RB_AEAD_CORRECT = """\
require "openssl"

# A migration to aes-256-gcm with a fresh nonce per message and the tag retained.
def seal(key, plaintext)
  c = OpenSSL::Cipher.new("aes-256-gcm")
  c.encrypt
  c.key = key
  nonce = c.random_iv
  [nonce, c.update(plaintext) + c.final, c.auth_tag]
end
"""

#: An AEAD rewrite whose decryption ignores the authentication tag.
#:
#: The AEAD counterpart of the always-true `verify`, and the same shape of disaster: the data still
#: round-trips, so a smoke test is satisfied, and every syntactic gate passes because the algorithm
#: name really did change to `aes-256-gcm`. What is gone is the authentication — the entire reason
#: to move off unauthenticated CBC in the first place.
_RB_AEAD_IGNORES_TAG = """\
require "openssl"

# A migration to aes-256-gcm -- with a decrypt that never checks the tag.
module OpenSSL
  class Cipher
    # An endless-method definition is a syntax error for a setter, which the harness reports as
    # "patched file did not load" rather than as a relation failure — correctly: a file that does
    # not parse is `compiles`' verdict to give, not this stage's.
    def auth_tag=(_value)
      nil
    end

    alias_method :qubit_original_final, :final
    def final
      qubit_original_final
    rescue OpenSSL::Cipher::CipherError
      ""
    end
  end
end
"""

#: A correct SHA-256 migration.
_RB_HASH_CORRECT = """\
require "openssl"

# A migration from SHA-1 to SHA-256.
def content_digest(bytes)
  OpenSSL::Digest.new("sha256").hexdigest(bytes)
end
"""

#: A digest that ignores its input.
#:
#: The hash family's version of the always-true `verify`. Determinism still holds — it returns the
#: same value every time, which is exactly what a deterministic-hash relation asks — and the digest
#: is a real 32 bytes, so the length advisory reads correct too. Only `hash-distinct-inputs`, which
#: demands that DIFFERENT inputs give different outputs, can tell it from a working hash.
#:
#: Hash is the family that matters most on the Ruby twin: 13 of its findings are SHA-1, and without
#: a licensed hash family rung 3 is unreachable for almost all of them.
_RB_HASH_CONSTANT = """\
require "openssl"

# A migration to SHA-256 -- with a digest that ignores what it is given.
module OpenSSL
  class Digest
    def digest(_data)
      "\\x00" * 32
    end

    def hexdigest(_data)
      "00" * 32
    end
  end
end
"""


#: The controls that must behave before a Ruby family's verdicts count as evidence.
#:
#: The same admission discipline `CONTROLS` applies to Python, with fixtures measured against Ruby's
#: own conventions. It is not optional here and it is not a formality: Ruby's signature `verify`
#: RETURNS a boolean while Python's raises, so a Ruby harness written from the Python shapes would
#: have all three negatives pass vacuously — and would license itself while catching nothing. These
#: controls are what makes that impossible rather than merely unlikely.
def ruby_controls() -> tuple[object, ...]:
    """Built lazily so `controls.Control` is imported only where it is used."""
    from .controls import Control

    return (
        Control(
            id="ruby-signature-negative",
            family="signature",
            usage_context="signature",
            target="ML-DSA-65",
            source=_RB_SIG_CORRECT,
            expect="pass",
            rationale="A correct ML-DSA migration in Ruby. Failing it means good patches are lost.",
        ),
        Control(
            id="ruby-signature-positive",
            family="signature",
            usage_context="signature",
            target="ML-DSA-65",
            source=_RB_SIG_ACCEPTS_ANYTHING,
            expect="fail",
            caught_by=frozenset({"sig-wrong-key", "sig-tampered-message", "sig-truncated"}),
            survives=frozenset({"sig-roundtrip", "sig-size-class"}),
            rationale=(
                "Verifies anything. Measured: the round trip and the 3309-byte size advisory both "
                "still pass, so only the negatives separate it from a correct migration."
            ),
        ),
        Control(
            id="ruby-hash-negative",
            family="hash",
            usage_context="hash",
            target="sha256",
            source=_RB_HASH_CORRECT,
            expect="pass",
            rationale="A correct SHA-256 migration — the commonest shape in the corpus.",
        ),
        Control(
            id="ruby-hash-positive",
            family="hash",
            usage_context="hash",
            target="sha256",
            source=_RB_HASH_CONSTANT,
            expect="fail",
            caught_by=frozenset({"hash-distinct-inputs"}),
            survives=frozenset({"hash-determinism", "hash-digest-length"}),
            rationale=(
                "A digest that ignores its input. It is perfectly deterministic and exactly 32 "
                "bytes, so both the positive and the advisory pass; only distinct-inputs "
                "catches it."
            ),
        ),
        Control(
            id="ruby-aead-negative",
            family="aead",
            usage_context="data_at_rest",
            target="AES-256-GCM",
            source=_RB_AEAD_CORRECT,
            expect="pass",
            rationale=(
                "A correct AEAD migration. Ruby rejects by RAISING, unlike its own signatures."
            ),
        ),
        Control(
            id="ruby-aead-positive",
            family="aead",
            usage_context="data_at_rest",
            target="AES-256-GCM",
            source=_RB_AEAD_IGNORES_TAG,
            expect="fail",
            caught_by=frozenset({"aead-wrong-key", "aead-tampered-ciphertext"}),
            survives=frozenset({"aead-roundtrip", "aead-nonce-uniqueness"}),
            rationale=(
                "Decrypts without checking the tag. The data still round-trips and the nonce is "
                "still fresh, so only the tampering negatives separate it from a real migration — "
                "and authentication is the whole reason to leave unauthenticated CBC."
            ),
        ),
    )
