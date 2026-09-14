"""Six patches that changed a cryptographic contract shared with something outside the file.

A full run over `medivault-emr` produced 7 patches. All 7 passed `applies`, `parses`, `compiles`
and `rescan` — the scanner confirmed the vulnerable algorithm was gone in every one. **Six then
broke the repository's own test suite**, and only the `tests` gate saw it. `protocol_contract` fired
on none of them.

They are three classes, and they do NOT share a remedy:

* **persisted format** — `encounters.seal_note`/`unseal_note`, AES-ECB rewritten to AES-GCM.
  Cryptographically correct, operationally catastrophic: every existing `Encounter.sealed_note` row
  was written in the old layout and the new reader parses `nonce | ciphertext | tag`. Broke
  `test_a_legacy_note_decrypts` and `test_a_legacy_checksum_still_verifies`. A dual-path read IS a
  correct migration here, so the remedy is a CONSTRAINT on generation, not a refusal.
* **two-party agreement** — `keyexchange.generate_referral_keypair`/`negotiate_referral_key`. Broke
  `test_both_clinics_derive_the_same_secret` and `test_a_third_party_derives_something_else`. No
  patch confined to this file can be correct, so the remedy IS a refusal: `guided`, reached before
  the first model call rather than after the third.
* **tamper detection** — `exports.py`. Broke `test_tampering_is_detected`, which exercises
  `seal_export_manifest`/`open_export_manifest` — AES-256-GCM, the file's declared NEGATIVE CONTROL,
  and not the finding at all. Decided from the evidence to be an in-repo control the patch broke as
  collateral, not a contract with a remote verifier: `exports.py` says "nothing keeps a bundle past
  its collection ... both ends of the format live in this module", `tests/test_exports.py` says "no
  golden ciphertext anywhere in this file", and both call the bundle cipher an expected MIGRATE. So
  the remedy is again a constraint, and the export cipher must stay migratable.

**The single defect underneath five of the six** is in `enclosing_documentation`: a Python docstring
is not a `#` comment, so the upward walk charged past it as body code and returned `""` for every
finding in a documented Python function. Whatever the prose vocabulary knew, it never saw any input.

The excerpts below are copied verbatim from `demo-lab/medivault-emr`;
`TestTheExcerptsAreTheRealCode` re-checks them against the twin when it is present, so a test that
passes against invented source cannot masquerade as a measurement.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_migrate.protocol_contract import (
    digest_names_stored_state,
    documented_constraint,
    enclosing_definition_name,
    enclosing_documentation,
    external_contract,
    module_declares_no_third_party,
)
from qubit_migrate.transform.rules import load_rules

# ── the real code, verbatim ──────────────────────────────────────────────────────────────────────

#: `app/services/encounters.py`. `seal_note` writes the column, `unseal_note` is its only reader,
#: and `note_checksum` is re-verified on every read.
ENCOUNTERS = '''\
def seal_note(note: str) -> bytes:
    """Encrypt a clinical note for storage.

    QUBIT-FIXTURE: py-weakcipher-01 / code-ecb-01 — AES-ECB, no authentication.
    """
    cipher = Cipher(algorithms.AES(derive_record_key()), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(_pad(note.encode())) + encryptor.finalize()


def unseal_note(sealed: bytes) -> str:
    """Decrypt a stored note. The only reader of every row in `Encounter.sealed_note`."""
    cipher = Cipher(algorithms.AES(derive_record_key()), modes.ECB())
    decryptor = cipher.decryptor()
    return _unpad(decryptor.update(sealed) + decryptor.finalize()).decode()


def note_checksum(note: str) -> str:
    """Integrity digest over the plaintext note, stored alongside the ciphertext.

    QUBIT-FIXTURE: py-weakhash-01 — MD5 over a persisted, re-verified value.
    """
    return hashlib.md5(note.encode()).hexdigest()
'''

#: `app/services/keyexchange.py`, the agreement half.
KEYEXCHANGE_AGREEMENT = '''\
def generate_referral_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Our half of the exchange, plus the public point to send to the partner clinic.

    QUBIT-FIXTURE: py-ecdh-kex-01 — P-256 ephemeral key agreement.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_bytes


def negotiate_referral_key(
    private_key: ec.EllipticCurvePrivateKey, peer_public_pem: bytes
) -> bytes:
    """Agree the shared secret for one referral.

    QUBIT-FIXTURE: py-ecdh-kex-01 — classical-only ECDH.
    """
    peer_public = serialization.load_pem_public_key(peer_public_pem)
    assert isinstance(peer_public, ec.EllipticCurvePublicKey)
    return private_key.exchange(ec.ECDH(), peer_public)
'''

#: `app/services/keyexchange.py`, WITH its module docstring — MV-10 as it actually reaches the
#: pipeline. `KEYEXCHANGE_AGREEMENT` above deliberately omits this, to test the local-only view;
#: this is the real file's module docstring, verbatim, ahead of the same two functions.
KEYEXCHANGE_MODULE_DOCSTRING = '''\
"""Referral channel to a partner clinic running this same software.

DELIBERATELY VULNERABLE — a QUBIT scanning target. Do not deploy.

## Planted findings, and what SHOULD happen to each

Both ends of this exchange are MediVault. There is no third party whose format is fixed, and no
stored artefact in the old format — a channel is negotiated fresh per referral. So both findings
here are the repository's own choice, and both are exactly what post-quantum migration is for.

* `negotiate_referral_key` — ephemeral **ECDH on P-256**. Recorded traffic is decryptable in
  retrospect once the curve falls, and a referral contains a full clinical history.
  **Expected disposition: MIGRATE** to a hybrid ML-KEM exchange.
* `wrap_data_key` / `unwrap_data_key` — **RSA-OAEP** key transport for the per-referral data key.
  Same exposure, same fix. **Expected disposition: MIGRATE** to ML-KEM encapsulation.
* `referral_channel_key` — NEGATIVE CONTROL. HKDF-SHA256 over the agreed secret, already correct.
"""
'''
KEYEXCHANGE_WITH_MODULE_HEADER = KEYEXCHANGE_MODULE_DOCSTRING + "\n" + KEYEXCHANGE_AGREEMENT

#: `lib/inkwell/crypto/partners.rb`, IE-08 — out-of-band distribution, the constraint class none
#: of the others have. The comment says so explicitly; the vocabulary just never had the word.
PARTNERS_SIGNING_LINK_TOKEN = """\
      # The signing token embedded in a signer's emailed link.
      #
      # QUBIT-FIXTURE: code-weakhash-02 — MD5 over submitter and secret.
      #
      # Expected disposition: REFUSE, and for a reason none of the other findings has: the value is
      # ALREADY IN SOMEBODY'S INBOX. Links were emailed to signers days or weeks ago and are still
      # being clicked. Change the derivation and every outstanding signature request 404s, with no
      # way to reach the people holding the old links.
      #
      # The constraint lives only in this comment. Nothing at the call site says the output is
      # mailed to a human.
      def signing_link_token(submitter_id, secret)
        Digest::MD5.hexdigest("#{submitter_id}:#{secret}")
      end
"""

#: `app/services/keyexchange.py`, the transport half — the near-miss that keeps the rule above
#: honest. Same file, same partner clinic, and expected MIGRATE.
KEYEXCHANGE_TRANSPORT = '''\
def wrap_data_key(peer_public: rsa.RSAPublicKey, data_key: bytes) -> bytes:
    """Wrap a per-referral data key for transport to the partner clinic.

    QUBIT-FIXTURE: py-rsa-kex-01 — RSA-OAEP key transport.
    """
    return peer_public.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_data_key(private_key: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
'''

#: `app/services/exports.py`. The same rule and the same primitive as `encounters.seal_note`, and
#: the opposite correct answer — plus the AEAD control the patch broke on its way past.
EXPORTS = '''\
def encrypt_export_bundle(bundle: bytes) -> bytes:
    """Encrypt tonight's bundle for the spool directory.

    QUBIT-FIXTURE: py-weakcipher-01 / code-ecb-01 — AES-ECB on transient data.
    """
    cipher = Cipher(algorithms.AES(derive_record_key()), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(_pad(bundle)) + encryptor.finalize()


def decrypt_export_bundle(blob: bytes) -> bytes:
    """Read a bundle back. The only reader, and only of bundles written the same night."""
    cipher = Cipher(algorithms.AES(derive_record_key()), modes.ECB())
    decryptor = cipher.decryptor()
    return _unpad(decryptor.update(blob) + decryptor.finalize())


def seal_export_manifest(manifest: bytes) -> bytes:
    """Seal the manifest that accompanies the bundle.

    NEGATIVE CONTROL: AES-256-GCM, fresh 96-bit nonce, nonce prefixed to the ciphertext.
    """
    key = (derive_record_key() * 2)[:32]
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, manifest, None)
'''

#: The other three twins' migratable findings whose documentation names a second party — the cases
#: that decide how wide `_COUNTERPARTY_LANGUAGE` is allowed to be. Verbatim, from
#: `paymesh-gateway/.../crypto/InternalDigests.java`, `sentinel-idp/internal/cryptox/internal.go`
#: and `inkwell-esign/lib/inkwell/crypto/internal.rb`.
PAYMESH_REPORT_BUNDLE = """\
    /**
     * Encrypt the finance report bundle for the spool directory.
     *
     * <p>QUBIT-FIXTURE: code-ecb-01 / code-weakcipher-01 — AES-CBC, unauthenticated. Migratable
     * where {@link CardVault#encryptPan} is not: the bundle is rebuilt from the ledger on demand,
     * collected the same night, and both ends of the format are the two methods below.
     */
    public byte[] encryptReportBundle(byte[] bundle) {
        try {
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
"""

SENTINEL_EXPORT_BUNDLE = """\
// EncryptExportBundle encrypts the nightly tenant-activity export.
//
// QUBIT-FIXTURE: code-ecb-01 — AES in CBC mode with no authentication.
//
// Expected disposition: MIGRATE. The bundle is rebuilt from the event log on demand and collected
// the same night; both ends of the format are the two functions here. Contrast with the refresh
// token hash in credentials.go: same "it's just a stored blob" appearance, and the export is the
// one that is actually free, because nothing keeps a bundle past its collection.
func EncryptExportBundle(plaintext []byte) ([]byte, error) {
\tblock, err := aes.NewCipher(exportKey)
"""

INKWELL_AUDIT_SIGNATURE = """\
      # Sign one internal audit entry.
      #
      # QUBIT-FIXTURE: code-signature-01 — RSA-2048 over SHA-1.
      #
      # Expected disposition: MIGRATE to ML-DSA. verify_audit_record below is the only consumer.
      # Compare Signing.sign_document: identical primitives, identical rule, and that one is
      # verified by counterparties holding countersigned copies. The difference is entirely in who
      # reads the output, and nothing at either call site shows it.
      def sign_audit_record(record)
        audit_key.sign(OpenSSL::Digest::SHA1.new, canonical_record(record))
"""

#: `sentinel-idp/internal/cryptox/tokens.go`, SN-04 — the whole function, deliberately, because
#: what makes this finding hard is the 20 body lines between the RSA call and its own docstring.
SENTINEL_ISSUE_ID_TOKEN = """\
// IssueIDToken mints a signed OIDC ID token.
//
// QUBIT-FIXTURE: code-signature-01 — RS256 (RSA-2048 with PKCS#1 v1.5).
//
// Expected disposition: REFUSE, and for a different reason from the stored digests. RSA is
// quantum-vulnerable and a signature over an identity assertion is worth forging, so the case for
// migrating is real. But `alg: RS256` appears in the JWKS document every relying party has cached,
// and this issuer does not know who they are. Moving to ML-DSA is a coordinated rotation — publish
// the new key alongside the old, wait out the cache, then retire — and none of that is an edit to
// this function.
func IssueIDToken(subject, audience, tenant string, ttl time.Duration) (string, error) {
\tkey, kid := SigningKey()

\theader := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
\tnow := time.Now().UTC()
\tclaims := map[string]any{
\t\t"iss":       "https://sentinel.example",
\t\t"sub":       subject,
\t\t"aud":       audience,
\t\t"tenant":    tenant,
\t\t"iat":       now.Unix(),
\t\t"exp":       now.Add(ttl).Unix(),
\t\t"auth_time": now.Unix(),
\t}

\tsigningInput, err := joinSegments(header, claims)
\tif err != nil {
\t\treturn "", err
\t}

\tdigest := sha256.Sum256([]byte(signingInput))
\tsignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
"""

#: `sentinel-idp/internal/cryptox/credentials.go`, SN-03 — a format version stamped onto the
#: digest's OUTPUT, which is the whole tell. Its manifest evidence class is `code`, so no
#: docstring was ever going to reach it.
SENTINEL_SESSION_COOKIE = """\
func SignSessionCookie(payload string, key []byte) string {
\tmac := hmac.New(sha1.New, key)
\tmac.Write([]byte(payload))
\treturn fmt.Sprintf("v1.%s", hex.EncodeToString(mac.Sum(nil)))
}
"""

#: The near-miss that decides how wide `_VERSIONED_OUTPUT` may be: the same file's own ETag, and
#: the two other twins' copies of it. All three are expected MIGRATE, all three prefix a digest,
#: and none carries a version token. Verbatim from `sentinel-idp/internal/cryptox/internal.go`,
#: `inkwell-esign/lib/inkwell/crypto/internal.rb` and
#: `paymesh-gateway/.../crypto/InternalDigests.java`.
MIGRATABLE_PREFIXED_DIGESTS = (
    'return `W/"` + hex.EncodeToString(sum[:]) + `"`',
    '%(W/"#{OpenSSL::Digest::SHA1.hexdigest(body)}")',
    'md5.Sum([]byte(fmt.Sprintf("%s:%d", principal, windowStart)))',
    'Digest::MD5.hexdigest("#{document_id}:page=#{page}")',
    'return "sha1=" + hex.EncodeToString(mac.Sum(nil))',
)

#: The positive control for the same vocabulary: `paymesh-gateway/.../ProviderSignatures.java`,
#: expected REFUSE, where the acquirer is the party COMPUTING the value rather than receiving it.
PAYMESH_WEBHOOK_HEADER = """\
    /**
     * The header the acquirer sends with every webhook, in the acquirer's own format.
     *
     * <p>QUBIT-FIXTURE: code-mac-01 — HMAC-SHA1 under a {@code sha1=} wire prefix.
     */
    public String providerWebhookSignature(byte[] rawBody, String webhookSecret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
"""

DEMO_LAB = Path(__file__).resolve().parents[3] / "demo-lab"


def line_of(source: str, needle: str, occurrence: int = 1) -> int:
    """The 1-based line carrying ``needle``: how a scanner `location.line` is expressed here.

    ``occurrence`` selects between identical call sites, which is the shape that matters here — the
    two ECB lines in `encounters.py` are byte-identical and one of them writes a column while the
    other reads it, so a helper that could only reach the first would leave the more interesting
    half of every pair untested.
    """
    seen = 0
    for number, text in enumerate(source.splitlines(), 1):
        if needle in text:
            seen += 1
            if seen == occurrence:
                return number
    raise AssertionError(f"{needle!r} does not occur {occurrence} time(s) in the excerpt")


def verdict_for(source: str, needle: str, algorithm: str, occurrence: int = 1):
    """The verdict the orchestrator would reach for a finding on the line carrying ``needle``.

    Both rungs, in the order `MigrationOrchestrator.generate_patch` consults them: the +/-2 line
    snippet first, then the enclosing documentation. Written out rather than imported because the
    orchestrator's own helper reads a file from disk.
    """
    line = line_of(source, needle, occurrence)
    lines = source.splitlines()
    snippet = "\n".join(lines[max(0, line - 3) : line + 2])
    return external_contract(algorithm, "app/services/x.py", snippet) or documented_constraint(
        enclosing_documentation(source, line),
        module_declares_no_third_party=module_declares_no_third_party(source),
    )


@pytest.fixture(scope="module")
def rules():
    return {rule.id: rule for rule in load_rules()}


# ── class 1: a format that outlived the code ─────────────────────────────────────────────────────


class TestThePersistedFormat:
    """`Encounter.sealed_note` holds rows nothing else can read.

    The remedy is deliberately NOT a refusal. A dual-path read — decrypt the new layout, fall back
    to the old one for rows written before the change — is a correct migration, and refusing here
    would trade a data-loss patch for a lost migration. So what these assert is that the evidence
    now REACHES the rule, and that the rule tells the model to write the fallback.
    """

    def test_the_documentation_that_says_so_is_now_readable(self):
        """The defect underneath five of the six misses.

        A Python docstring is not a `#` comment, so `_is_comment` could not see it, the upward walk
        counted it as body code, and this returned "" for every finding inside a documented Python
        function. The prose vocabulary was never given anything to match on.
        """
        context = enclosing_documentation(ENCOUNTERS, line_of(ENCOUNTERS, "modes.ECB()"))
        assert "Encrypt a clinical note for storage" in context

    def test_the_stored_checksum_beside_it_is_refused(self):
        """`note_checksum` is the same file's other persisted value, and its docstring says so.

        The twin records this one's evidence class as `prose` and its expected disposition as
        REFUSE. It was unreachable for the same reason, and it is the finding that shows the fix is
        about the walk rather than about ECB.
        """
        verdict = verdict_for(ENCOUNTERS, "hashlib.md5(note.encode())", "MD5")
        assert verdict is not None, "a digest documented as stored alongside the ciphertext"
        assert "outlives" in verdict.reason

    @pytest.mark.parametrize(
        ("occurrence", "which"), [(1, "seal_note, the writer"), (2, "unseal_note, the reader")]
    )
    def test_the_cipher_itself_stays_migratable(self, occurrence, which):
        """Not a refusal, and that is the point.

        `unseal_note` says "The only reader of every row in `Encounter.sealed_note`" — persistence
        stated in words the vocabulary happens not to carry, and now that the docstring is readable
        the temptation is to add them. Adding "every row" would cost the dual-path migration that
        IS available here; the rule's constraint is the remedy, not a verdict.

        Both call sites, because they are byte-identical and only the reader's docstring carries
        the language a future vocabulary change would key on.
        """
        assert verdict_for(ENCOUNTERS, "modes.ECB()", "AES-256", occurrence) is None, which

    def test_the_rule_demands_a_backward_compatible_read_path(self, rules):
        """And demands it BEFORE it starts talking about GCM.

        The requirement was already in the rule, fifth of six bullets, phrased as a preference. The
        model dropped it and the patch passed four gates. It now leads, and it is conditional on a
        decision the model has to make and report — because the same rule migrates
        `exports.encrypt_export_bundle`, where a legacy path would be dead code.
        """
        constraints = rules["code-ecb-01"].prompt_constraints
        leading = " ".join(constraints[:2]).lower()
        assert "still exists" in leading, "the model is never asked whether old ciphertext exists"
        assert "mandatory" in leading, "the fallback is still phrased as a preference"
        assert "fall back" in leading
        # The condition, without which this becomes a blanket rule that breaks the migratable half.
        assert "if old ciphertext exists" in leading


# ── class 2: an agreement with a counterparty ────────────────────────────────────────────────────


class TestTheTwoPartyAgreement:
    """Here a refusal IS the remedy, and reaching it costs no model calls.

    `test_both_clinics_derive_the_same_secret` asserts
    `negotiate(ours, their_public) == negotiate(theirs, our_public)` — a symmetry ECDH has and a KEM
    does not, because one side encapsulates and the other decapsulates. Every candidate patch either
    keeps ECDH, and `rescan` rejects it, or drops the symmetry, and the two clinics stop agreeing.
    The patch space is empty, and three model attempts searched it anyway.
    """

    def test_the_agreement_call_is_refused_on_code_evidence(self):
        verdict = verdict_for(KEYEXCHANGE_AGREEMENT, "exchange(ec.ECDH()", "ECDH-P256")
        assert verdict is not None, "one side of a key agreement was migrated unilaterally"
        assert "both ends must be upgraded together" in verdict.reason

    def test_the_keypair_that_feeds_it_is_refused_on_prose(self):
        """A different rung for a different finding, and the one the veto used to swallow.

        `ec.generate_private_key(ec.SECP256R1())` has no counterparty in its +/-2 window; the
        docstring above it says "Our half of the exchange". That docstring also says "P-256
        **ephemeral** key agreement", and `ephemeral` is `_REGENERABLE_LANGUAGE` — so the veto fired
        first and cleared a finding whose refusal was written two lines up. Ephemerality is about
        the key's lifetime and says nothing about whether the far end still agrees.
        """
        verdict = verdict_for(KEYEXCHANGE_AGREEMENT, "ec.generate_private_key", "ECDSA-P256")
        assert verdict is not None, "the regenerable veto swallowed a counterparty statement"
        assert "agreed with another party" in verdict.reason

    def test_the_module_docstring_clears_it_when_present(self):
        """MV-10, fixed. Ground truth calls this MIGRATE; the code agrees with itself.

        Same finding, same function, same "Our half of the exchange" phrase as the test above —
        the only difference is that this fixture carries the file's real module docstring, which
        says outright there is no third party. `enclosing_documentation` still cannot see that far
        (by design); `module_declares_no_third_party` is the separate, narrow read that can, and
        `verdict_for` now consults it exactly as the orchestrator does.
        """
        assert (
            verdict_for(KEYEXCHANGE_WITH_MODULE_HEADER, "ec.generate_private_key", "ECDSA-P256")
            is None
        ), "the module's own 'no third party' statement should have cleared this"

    def test_a_published_key_set_is_refused_across_a_long_body(self):
        """SN-04, fixed. Two things had to be true at once for this one: the finding's own
        docstring had to become reachable across 20 lines of body code (`_MAX_BODY_SKIP`,
        checked only past the finding's own `def`/`func` line now, not before it), and
        "coordinated rotation" had to be checked ahead of the regenerable veto — the same
        docstring also says "cached", which is `_REGENERABLE_LANGUAGE`'s own word, but for
        caches this codebase does not control rather than its own.
        """
        verdict = verdict_for(SENTINEL_ISSUE_ID_TOKEN, "rsa.SignPKCS1v15", "RSA-2048")
        assert verdict is not None, "a published, cached key set was left migratable"
        assert "coordinated rotation" in verdict.signal

    def test_key_transport_to_the_same_partner_stays_migratable(self):
        """The near-miss, one function below, that stops this being a blanket refusal.

        `wrap_data_key` names the same partner clinic and is expected MIGRATE: key TRANSPORT has a
        message already going to the peer, so a KEM ciphertext travels inside the blob that is
        already sent, and `TestDataKeyTransport` stays green through a KEM-DEM rewrite. A rule keyed
        on "the partner appears in the docstring" refuses this too.
        """
        assert verdict_for(KEYEXCHANGE_TRANSPORT, "peer_public.encrypt(", "RSA-2048") is None

    def test_an_undocumented_function_does_not_borrow_its_neighbour(self):
        """`unwrap_data_key` has no docstring and sits directly under one that does.

        The same mistake `_MAX_BODY_SKIP` was added to stop for comment blocks. Docstrings needed
        their own boundary, because a `#` block ABOVE a definition is legitimately that symbol's and
        a docstring above one is the PREVIOUS symbol's.
        """
        context = enclosing_documentation(
            KEYEXCHANGE_TRANSPORT, line_of(KEYEXCHANGE_TRANSPORT, "private_key.decrypt(")
        )
        assert "Wrap a per-referral data key" not in context, "read the neighbour's docstring"

    @pytest.mark.parametrize(
        ("rule_id", "phrase"),
        [
            # The rule's own example used to compute an encapsulation ciphertext and never return
            # it — demonstrating, in the few-shot, the bug the constraint has to prevent.
            ("py-ecdh-kex-01", "has to reach the peer"),
            ("py-ecdh-kex-01", "wire-protocol change and not a source edit"),
            # `py-signature-01` claimed the EC keygen in `generate_referral_keypair`, whose public
            # half is serialised and sent to the partner. Nothing signs with that key.
            ("py-signature-01", "a signature key and a kem key are not interchangeable"),
        ],
    )
    def test_the_rules_say_what_a_kem_costs(self, rules, rule_id, phrase):
        joined = " ".join(rules[rule_id].prompt_constraints).lower()
        assert phrase in joined, f"{rule_id} does not tell the model {phrase!r}"


# ── class 3: an in-repo control the patch broke on its way past ──────────────────────────────────


class TestTheTamperDetection:
    """Decided from the code: NOT a contract with a remote verifier.

    `test_tampering_is_detected` exercises `seal_export_manifest`/`open_export_manifest`, which the
    file labels a NEGATIVE CONTROL and which are not the finding. `exports.py` says the bundle is
    "rebuilt from the database on demand", "nothing keeps a bundle past its collection" and "both
    ends of the format live in this module"; `tests/test_exports.py` says there is "no golden
    ciphertext anywhere in this file". Nothing outside the repository owns any of it, so there is
    nothing for the ownership guard to refuse — the patch simply edited code that was already
    correct, and the place to stop that is the instruction that produced it.
    """

    @pytest.mark.parametrize("needle", ["_pad(bundle)", "_unpad(decryptor.update(blob)"])
    def test_the_export_cipher_stays_migratable(self, needle):
        """The deliberate contrast with `encounters.seal_note`: same rule, same primitive, opposite
        answer. A guard that refuses this has stopped discriminating and started refusing."""
        assert verdict_for(EXPORTS, needle, "AES-256") is None

    def test_the_already_correct_control_is_not_refused_either(self):
        """Refusing the GCM sealer would be the wrong fix in the other direction.

        Routing it to `guided` would put an already-correct AEAD on the operator's report as an
        unresolved contract. It is neither a finding nor a contract; it is code the patch had no
        business touching.
        """
        assert verdict_for(EXPORTS, "AESGCM(key).encrypt(", "AES-256") is None

    def test_the_rule_forbids_reworking_the_neighbouring_aead(self, rules):
        constraints = " ".join(rules["code-ecb-01"].prompt_constraints).lower()
        assert "change only the flagged function" in constraints
        assert "tag verification" in constraints, "nothing forbids dropping the integrity check"


# ── class 3b: a format the code stamps a version onto ───────────────────────────────────────────


class TestVersionedOutput:
    """SN-03. Not prose at all — the constraint is the SHAPE of the returned value.

    `fmt.Sprintf("v1.%s", ...)` says the author expected to have to tell versions apart one day,
    which is only true of a value somebody else is holding. Browsers hold these cookies; re-signing
    them under a new algorithm logs everyone out. Before this it reached `deferred/unresolved` —
    not migrated, but only because a generation attempt failed, which is luck rather than a
    decision.
    """

    def test_the_session_cookie_is_refused_on_its_own_shape(self):
        from qubit_migrate.protocol_contract import _VERSIONED_OUTPUT, required_algorithm_in_body

        line = line_of(SENTINEL_SESSION_COOKIE, "hmac.New(sha1.New")
        body = required_algorithm_in_body(SENTINEL_SESSION_COOKIE, line)

        match = _VERSIONED_OUTPUT.search(body)
        assert match is not None, "a version-stamped digest was left migratable"
        assert "v1." in match.group(0)

    def test_the_mangled_spelling_is_caught_too(self):
        """The evaluation's own GitHub mirror carries `s1.` here — an earlier run's patch bumped
        the version marker along with the algorithm. The rule keys on the SHAPE, not on `v`."""
        from qubit_migrate.protocol_contract import _VERSIONED_OUTPUT

        assert _VERSIONED_OUTPUT.search(
            'return fmt.Sprintf("s1.%s", hex.EncodeToString(mac.Sum(nil)))'
        )

    @pytest.mark.parametrize("source", MIGRATABLE_PREFIXED_DIGESTS)
    def test_a_prefixed_digest_that_is_not_versioned_stays_migratable(self, source):
        """The guard that keeps this from becoming "any prefix means stored format".

        Every one of these prefixes a digest and every one is expected MIGRATE. The ETags carry no
        digits; the cache and rate-limit keys put their delimiter on the hashed INPUT, not on the
        rendered output; `sha1=` is a wire prefix `_CONTRACT_FIELDS` already owns.
        """
        from qubit_migrate.protocol_contract import _VERSIONED_OUTPUT

        assert _VERSIONED_OUTPUT.search(source) is None, source

    def test_a_go_package_reference_is_not_a_version_token(self):
        """`pbkdf2.Key(...)` is `<letters><digits>.` too. Five letters is what keeps it out."""
        from qubit_migrate.protocol_contract import _VERSIONED_OUTPUT

        assert (
            _VERSIONED_OUTPUT.search(
                'pbkdf2.Key([]byte(password), salt, iterations, length, sha1.New)'
            )
            is None
        )


# ── class 3c: the other half of a signature pair ────────────────────────────────────────────────


class TestSigningCounterpart:
    """IE-06, the last false migration left in `inkwell-esign`.

    `sign_document` carries four paragraphs about why it must not change and is correctly refused
    on them. `verify_document`, seventeen lines below, has one bare line — "Must keep accepting
    everything ever signed" — carrying no vocabulary this module knows, and was migrated in every
    run: SHA-1 swapped underneath a verifier whose entire job is to keep accepting SHA-1.

    The constraint was written down. It was written down next to the other half.
    """

    #: `lib/inkwell/crypto/signing.rb`, both halves and the documentation that separates them.
    #: Verbatim — `TestTheExcerptsAreTheRealCode` re-checks it against the twin.
    SIGNING_PAIR = '''\
      # Sign a document.
      #
      # QUBIT-FIXTURE: code-signature-01 — RSA-2048 over a SHA-1 digest.
      #
      # Expected disposition: REFUSE, and this is the sharpest refusal in any of the twins.
      #
      # RSA is quantum-vulnerable, SHA-1 is collision-broken, and a signed contract is retained for
      # a decade or more — so the case for migrating is stronger here than anywhere else in the
      # corpus. It is still not an edit to this method. Every signature already produced was made
      # with this algorithm pair; +verify_document+ has to keep verifying them, and a counterparty
      # holding a countersigned copy verifies it with their own software. The migration is a new
      # signature VERSION applied to new documents, with the old path retained for old ones — which
      # is a schema change, a policy decision and a retention plan, not a constant.
      #
      # A tool that swaps SHA1 for SHA256 here has produced a service that cannot verify its own
      # archive, and every syntactic gate will pass it.
      def self.sign_document(bytes)
        digest = Documents.signed_digest(bytes)
        signing_key.sign_raw(OpenSSL::Digest::SHA1.new, digest)
      rescue NoMethodError
        # sign_raw arrived in Ruby 3.0's openssl; the fallback keeps the twin runnable on older
        # builds without changing what is signed.
        signing_key.sign(OpenSSL::Digest::SHA1.new, bytes)
      end

      # Verify a document signature. Must keep accepting everything ever signed.
      def self.verify_document(bytes, signature)
        signing_key.public_key.verify(OpenSSL::Digest::SHA1.new, signature, bytes)
      rescue OpenSSL::PKey::PKeyError
        false
      end
'''

    def test_the_verifier_inherits_the_signers_refusal(self):
        from qubit_migrate.protocol_contract import inherited_from_signing_counterpart

        line = line_of(self.SIGNING_PAIR, "signing_key.public_key.verify")
        verdict = inherited_from_signing_counterpart(self.SIGNING_PAIR, line)

        assert verdict is not None, "a verifier was left free to abandon its own archive"
        assert "signing half" in verdict.signal
        assert "move together or not at all" in verdict.reason

    @pytest.mark.parametrize("needle", ["sign_raw(OpenSSL", "signing_key.sign(OpenSSL"])
    def test_the_signer_does_not_inherit_from_itself(self, needle):
        """One-directional, and self-inheritance would prove nothing.

        Both of `sign_document`'s branches are the SIGNING half. The body window around either one
        reaches into the verifier below, so the side has to be read off the finding's own line
        rather than off that window — this is the case that caught it.
        """
        from qubit_migrate.protocol_contract import inherited_from_signing_counterpart

        line = line_of(self.SIGNING_PAIR, needle)
        assert inherited_from_signing_counterpart(self.SIGNING_PAIR, line) is None

    def test_a_free_signer_propagates_nothing(self):
        """The guard that keeps this from refusing every verifier in the corpus.

        `Internal.sign_audit_record` is the deliberate contrast: identical primitives, identical
        rule, and expected MIGRATE, because it is cleared by `only consumer` in its own block. A
        pair whose signing half is free stays free on both sides.
        """
        from qubit_migrate.protocol_contract import inherited_from_signing_counterpart

        free_pair = (
            "      # Sign one internal audit entry.\n"
            "      #\n"
            "      # Expected disposition: MIGRATE to ML-DSA. verify_audit_record below is the\n"
            "      # only consumer.\n"
            "      def sign_audit_record(record)\n"
            "        audit_key.sign(OpenSSL::Digest::SHA1.new, canonical_record(record))\n"
            "      end\n"
            "\n"
            "      # Check one.\n"
            "      def verify_audit_record(record, signature)\n"
            "        audit_key.public_key.verify(OpenSSL::Digest::SHA1.new, signature, record)\n"
            "      end\n"
        )
        line = line_of(free_pair, "audit_key.public_key.verify")
        assert inherited_from_signing_counterpart(free_pair, line) is None


# ── class 4: a value already handed to someone outside the system ───────────────────────────────


class TestOutOfBandDistribution:
    """IE-08. Not persisted, not agreed with a counterparty in code — already sitting in an
    inbox, out of the repository's reach entirely, which is a third constraint class with no
    remedy but refusal.
    """

    def test_the_signing_link_token_is_refused(self):
        verdict = verdict_for(
            PARTNERS_SIGNING_LINK_TOKEN, 'Digest::MD5.hexdigest("#{submitter_id}', "MD5"
        )
        assert verdict is not None, "a value already emailed out was left migratable"
        assert "INBOX" in verdict.signal.upper()


# ── the guard against fixing this by refusing everything ─────────────────────────────────────────


class TestItStillDiscriminates:
    """Every phrase that skips the regenerable veto is a phrase that can refuse migratable code.

    These are the three candidates that failed that bar on the twins, and they are the reason
    `_COUNTERPARTY_LANGUAGE` is as narrow as it is. All three are real sentences from real
    expected-MIGRATE findings.
    """

    @pytest.mark.parametrize(
        ("label", "source", "needle"),
        [
            ("paymesh InternalDigests.encryptReportBundle", PAYMESH_REPORT_BUNDLE, "AES/CBC"),
            ("sentinel cryptox EncryptExportBundle", SENTINEL_EXPORT_BUNDLE, "aes.NewCipher"),
            ("inkwell Internal.sign_audit_record", INKWELL_AUDIT_SIGNATURE, "audit_key.sign"),
        ],
    )
    def test_migratable_prose_that_names_two_ends_is_not_refused(self, label, source, needle):
        """All three are expected-MIGRATE findings whose documentation names a second party.

        "both ends of the format are the two methods below" says there is NO counterparty; the
        counterparties in `sign_audit_record`'s block belong to the function it is being CONTRASTED
        with. Each is cleared by a regenerable word in the same block — `rebuilt`, `nothing keeps`,
        `only consumer` — which is exactly what the veto is for, and exactly what a phrase promoted
        past the veto would override.
        """
        assert verdict_for(source, needle, "AES-256") is None, label

    def test_a_party_that_computes_the_value_is_still_refused(self):
        """The other side of the `to the partner` lookbehind, and the reason it is safe.

        Every refusal measured on paymesh, sentinel and inkwell is the party ACTING — "the acquirer
        sends", "the scheme recomputes this", "using the scheme they specified". None is phrased
        "to the <party>", so excluding delivery keeps all of them.
        """
        verdict = verdict_for(PAYMESH_WEBHOOK_HEADER, "Mac.getInstance", "SHA-1")
        assert verdict is not None, "the acquirer's own webhook format was left migratable"
        # The signal, not just the outcome: this must be the clause the lookbehind narrows, or the
        # test would keep passing on some other rule while that clause quietly stopped working.
        assert "the acquirer" in verdict.signal

    def test_a_string_literal_in_a_body_is_not_documentation(self):
        """An assigned multi-line string closes on its own line and looks like a docstring from
        below. Reading a SQL body as documentation is the same class of mistake as reading a
        neighbouring symbol's comment block."""
        source = (
            "def f(rows):\n"
            '    sql = """\n'
            "    SELECT * FROM documents stored in the archive, retained for seven years\n"
            '    """\n'
            "    return hashlib.md5(sql.encode()).hexdigest()\n"
        )
        assert documented_constraint(enclosing_documentation(source, 5)) is None


# ── fidelity ─────────────────────────────────────────────────────────────────────────────────────


class TestTheExcerptsAreTheRealCode:
    """A test that passes against invented source is not a measurement of anything.

    Skipped rather than failed when the twin is absent, so the package's tests stay runnable on
    their own — the assertion is about honesty, not about the twin being installed.
    """

    @pytest.mark.parametrize(
        ("relative_path", "excerpt"),
        [
            ("medivault-emr/app/services/encounters.py", ENCOUNTERS),
            ("medivault-emr/app/services/keyexchange.py", KEYEXCHANGE_AGREEMENT),
            ("medivault-emr/app/services/keyexchange.py", KEYEXCHANGE_MODULE_DOCSTRING),
            ("inkwell-esign/lib/inkwell/crypto/partners.rb", PARTNERS_SIGNING_LINK_TOKEN),
            (
                "inkwell-esign/lib/inkwell/crypto/signing.rb",
                TestSigningCounterpart.SIGNING_PAIR,
            ),
            ("sentinel-idp/internal/cryptox/credentials.go", SENTINEL_SESSION_COOKIE),
            ("medivault-emr/app/services/keyexchange.py", KEYEXCHANGE_TRANSPORT),
            ("medivault-emr/app/services/exports.py", EXPORTS),
            (
                "paymesh-gateway/src/main/java/example/paymesh/crypto/InternalDigests.java",
                PAYMESH_REPORT_BUNDLE,
            ),
            (
                "paymesh-gateway/src/main/java/example/paymesh/crypto/ProviderSignatures.java",
                PAYMESH_WEBHOOK_HEADER,
            ),
            ("sentinel-idp/internal/cryptox/internal.go", SENTINEL_EXPORT_BUNDLE),
            ("sentinel-idp/internal/cryptox/tokens.go", SENTINEL_ISSUE_ID_TOKEN),
            ("inkwell-esign/lib/inkwell/crypto/internal.rb", INKWELL_AUDIT_SIGNATURE),
        ],
    )
    def test_the_excerpt_still_matches_the_twin(self, relative_path, excerpt):
        path = DEMO_LAB / relative_path
        if not path.exists():
            pytest.skip(f"{path} is not checked out here")
        assert excerpt in path.read_text(encoding="utf-8"), (
            f"{relative_path} has changed under this test; re-copy the excerpt, or the "
            f"regression is measuring code that no longer exists"
        )


class TestDigestNamesStoredState:
    """The constraint nobody wrote down.

    Every other rule in this module reads PROSE, which works on code documented with an eye to
    what must not change and fails on ordinary repositories that simply name the function after
    what it returns. Measured on scrapy -- chosen for round 4 precisely because nothing in it was
    written for this tool -- all five of its persisted-digest sites produced no verdict from any
    prose rule, and every one is a value the project stores and reads back: the dupefilter
    fingerprint, two stored filenames, a thumbnail path and the scheduler's queue directory.
    """

    SCRAPY_FILE_PATH = (
        "class FilesPipeline:\n"
        "    def file_path(\n"
        "        self,\n"
        "        request,\n"
        "    ) -> str:\n"
        "        media_guid = hashlib.sha1(to_bytes(request.url)).hexdigest()\n"
        '        return f"full/{media_guid}"\n'
    )

    #: The header sits 60+ lines above the digest, all of it docstring -- the shape that defeats
    #: any fixed lookback and forces the enclosing-definition search to go by indentation.
    SCRAPY_FINGERPRINT = (
        "def fingerprint(\n"
        "    request,\n"
        "    *,\n"
        "    include_headers=None,\n"
        ") -> bytes:\n"
        '    """Return the request fingerprint.\n'
        "\n" + "    filler documentation line\n" * 60 + '    """\n'
        "    if cache_key not in cache:\n"
        "        cache[cache_key] = hashlib.sha1(\n"
        "            fingerprint_json.encode()\n"
        "        ).digest()\n"
        "    return cache[cache_key]\n"
    )

    def test_a_digest_returned_from_a_path_function_is_refused(self) -> None:
        verdict = digest_names_stored_state(self.SCRAPY_FILE_PATH, 6)

        assert verdict is not None
        assert "file_path" in verdict.signal

    def test_the_enclosing_definition_is_found_past_a_long_docstring(self) -> None:
        """Indentation, not distance. A 40-line lookback found nothing here, because scrapy's
        `fingerprint` opens 60+ lines above the digest it computes and all of it is docstring."""
        line = self.SCRAPY_FINGERPRINT.splitlines().index("        cache[cache_key] = hashlib.sha1(") + 1

        assert enclosing_definition_name(self.SCRAPY_FINGERPRINT, line) == "fingerprint"

    def test_a_bare_fingerprint_helper_is_NOT_refused(self) -> None:
        """A recorded limitation, pinned so it cannot be widened without a decision.

        scrapy's `fingerprint()` really is persisted -- the dupefilter writes it to
        `requests.seen` -- but nothing in the function says so, and an unqualified `fingerprint`
        helper is just as often recomputed every call. Refusing on the name alone rejected the
        textbook migratable case below. This rule is restricted to the filesystem vocabulary,
        where persistence follows from the construction rather than from a guess.
        """
        source = (
            "def fingerprint(payload: bytes) -> str:\n"
            "    return hashlib.md5(payload).hexdigest()\n"
        )

        assert digest_names_stored_state(source, 2) is None

    def test_a_top_level_digest_has_no_enclosing_definition(self) -> None:
        """A statement at column 0 is inside nothing, and must not borrow the name of whatever
        function happens to end above it."""
        source = "def helper_path():\n    pass\n\n\ndigest = hashlib.md5(b'x').hexdigest()\n"

        assert enclosing_definition_name(source, 5) is None
        assert digest_names_stored_state(source, 5) is None

    def test_a_cache_key_function_is_not_refused(self) -> None:
        """`key` is deliberately absent from the vocabulary: a cache key is the canonical
        MIGRATABLE case, recomputed from live inputs with nothing reading it back after a
        restart. Including it would refuse the findings this tool exists to fix."""
        source = (
            "def cache_key(tenant, subject):\n"
            "    return hashlib.md5(f'{tenant}:{subject}'.encode()).hexdigest()\n"
        )

        assert digest_names_stored_state(source, 2) is None

    def test_a_path_function_without_a_digest_is_not_refused(self) -> None:
        """Both signals are required. The name alone would refuse any cryptography that happens
        to sit in a path helper."""
        source = "def file_path(self, request):\n    return os.path.join(self.base, request.url)\n"

        assert digest_names_stored_state(source, 2) is None

    def test_a_go_method_receiver_does_not_swallow_the_name(self) -> None:
        source = (
            "func (s *Store) objectPath(url string) string {\n"
            "\tsum := sha1.Sum([]byte(url))\n"
            "\treturn hex.EncodeToString(sum[:])\n"
            "}\n"
        )

        assert enclosing_definition_name(source, 2) == "objectPath"
