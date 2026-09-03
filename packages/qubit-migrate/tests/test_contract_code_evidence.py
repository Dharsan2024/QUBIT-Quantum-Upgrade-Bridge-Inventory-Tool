"""Two refusals whose evidence is in the code, that the guard could not see.

Each twin's manifest records, for every refusal, whether the reason is visible **in the code** the
scanner can reach or only **in prose**. A `prose` refusal that gets migrated is a limit of static
analysis and is reported as such. A `code` refusal that gets migrated is a gap in this guard.

`paymesh-gateway` produced two of the second kind, and both were migrated against an explicit
refusal in the first complete four-twin run:

* `PM-02 signAuthorizationRequest` — the method throws
  `IllegalStateException("MD5 is required by the legacy acquirer channel")`. The code says, in so
  many words, that the algorithm is mandated.
* `PM-08 merchantKeyDigest` — SHA-1 over an API key, stored as `merchant.api_key_digest` and
  re-derived on every request. Changing it locks out every merchant at once.

Neither fired, and the reason is the same for both: every pattern in `protocol_contract` was written
against Python idiom. `_CREDENTIAL_DIGEST` matches `md5(password)`, where the algorithm IS the
function — but Java, Go and C# separate them (`MessageDigest.getInstance("SHA-1")` on one line,
`.digest(apiKey)` on the next), so the credential is never an argument to anything named after a
hash.

The negative controls matter as much as the positives here. A guard that refuses everything is not a
guard, and the same file holds digests that must stay migratable.
"""

from __future__ import annotations

import pytest

from qubit_migrate.protocol_contract import external_contract

JAVA_ACQUIRER = (
    'MessageDigest md5Signature = MessageDigest.getInstance("MD5");\n'
    "return Hex.encode(md5Signature.digest(signingString.getBytes(StandardCharsets.UTF_8)));\n"
    "} catch (NoSuchAlgorithmException e) {\n"
    'throw new IllegalStateException("MD5 is required by the legacy acquirer channel", e);'
)

JAVA_CREDENTIAL = (
    'MessageDigest digest = MessageDigest.getInstance("SHA-1");\n'
    "return Hex.encode(digest.digest(apiKey.getBytes(StandardCharsets.UTF_8)));"
)


class TestTheCodeSaysTheAlgorithmIsRequired:
    def test_java_throw_naming_the_requirement_is_refused(self):
        verdict = external_contract("MD5", "crypto/ProviderSignatures.java", JAVA_ACQUIRER)
        assert verdict is not None, "the code states MD5 is required and it was migrated anyway"
        assert "required" in verdict.reason

    @pytest.mark.parametrize(
        "text",
        [
            '"MD5 is required by the legacy acquirer channel"',
            '"SHA-1 is mandated by the scheme specification"',
            '"this endpoint requires MD5"',
            '"the partner only accepts SHA1 signatures"',
            '"legacy channel must use RC4"',
        ],
    )
    def test_both_word_orders_and_several_phrasings(self, text):
        assert external_contract("MD5", "x/Svc.java", f"digest = hash();\nthrow new E({text});")

    @pytest.mark.parametrize(
        "text",
        [
            # Names an algorithm, but says nothing about it being required.
            '"MD5 checksum computed"',
            '"failed to compute the SHA-1 digest"',
            # States a requirement, but about something that is not an algorithm.
            '"a merchant id is required by the acquirer"',
        ],
    )
    def test_a_mere_mention_is_not_a_constraint(self, text):
        """The rule must key on the CLAIM, not on the algorithm appearing in a string.

        Half the weak-hash call sites in any codebase name their algorithm in a log line or an
        exception. Treating that as a contract would refuse nearly everything.
        """
        assert external_contract("MD5", "x/Svc.java", f'log.info({text});\nmd = digest(body);') is None


class TestCredentialDigestsOutsidePython:
    def test_java_digest_over_an_api_key_is_refused(self):
        verdict = external_contract("SHA-1", "domain/PaymentService.java", JAVA_CREDENTIAL)
        assert verdict is not None, "SHA-1 over an API key was migrated"
        assert "credential" in verdict.reason

    @pytest.mark.parametrize(
        "snippet",
        [
            "digest.digest(apiKey.getBytes(StandardCharsets.UTF_8))",
            "sha1.Sum([]byte(refreshToken))",
            "md5.Sum([]byte(clientSecret))",
            "hash.ComputeHash(passwordBytes)",
            "digest(credential)",
        ],
    )
    def test_the_c_family_calling_convention(self, snippet):
        assert external_contract("SHA-1", "x/Svc.java", snippet) is not None, snippet

    @pytest.mark.parametrize(
        "snippet",
        [
            # A digest over something that is not a credential stays migratable.
            "digest.digest(cacheKey.getBytes(StandardCharsets.UTF_8))",
            "sha1.Sum([]byte(responseBody))",
            "digest.digest(body)",
            "md5.Sum([]byte(documentId))",
        ],
    )
    def test_ordinary_digests_are_still_migratable(self, snippet):
        """`InternalDigests` in the same twin is five migratable findings.

        If this guard caught them too, the tool would refuse everything in the file and the twin's
        migrate half would be unreachable.
        """
        assert external_contract("MD5", "crypto/InternalDigests.java", snippet) is None, snippet
