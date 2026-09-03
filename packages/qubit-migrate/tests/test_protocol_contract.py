"""The guard that decides whether an algorithm is this repository's to change.

Every positive case here is a real line from `pyload/pyload` that produced a patch which passed
`applies`, `parses`, `symbols`, `compiles` and `rescan` — and broke authentication. Every negative
case is a real line the tool SHOULD migrate. The gap between the two is the whole content of this
module, and getting it wrong in either direction is expensive:

* a missed contract ships a patch that no downstream gate can catch, because `rescan` passes
  precisely *because* the algorithm changed;
* an over-eager verdict turns a migratable finding into an advisory and quietly caps the tool's
  usefulness.

Measured before this guard existed: 11 patches, two generators, all broken
(`qubit-v2/08-evaluation/RESULTS-B0-arm.md`).
"""

from __future__ import annotations

import pytest
from qubit_migrate.protocol_contract import external_contract


class TestValuesAnotherPartyDefines:
    """Real lines that produced real broken patches."""

    @pytest.mark.parametrize(
        ("label", "path", "snippet"),
        [
            (
                "Linkifier: the field name IS the algorithm",
                "src/pyload/plugins/accounts/LinkifierCom.py",
                'post = {"login": user, "md5Pass": hashlib.md5(password.encode()).hexdigest()}',
            ),
            (
                "NoPremium: same shape, different field",
                "src/pyload/plugins/accounts/NoPremiumPl.py",
                'data["hash_password"] = hashlib.sha1(hashlib.md5(password.encode()).hexdigest())',
            ),
            (
                "Rapideo: the field is generically named, the input is not",
                "src/pyload/plugins/accounts/RapideoPl.py",
                'data["pwd"] = hashlib.md5(password.encode()).hexdigest()',
            ),
            (
                "StreamCz: an API signature over a key",
                "src/pyload/plugins/downloaders/StreamCz.py",
                "api_pass = api_key + episode\n    m = hashlib.md5(api_pass.encode())",
            ),
            (
                # The real shape, not a stand-in. An earlier version of this case used
                # `hashlib.md5(x)`, which passed only because `auth.py` was then a path marker —
                # the test agreed with the rule for a reason neither of them should have relied on.
                "requests: RFC 2617 Digest requires MD5",
                "requests/auth.py",
                "class HTTPDigestAuth(AuthBase):\n"
                "    def build_digest_header(self, method, url):\n"
                '        qop = self._thread_local.chal.get("qop")\n'
                '        return hash_utf8("%s:%s:%s" % (self.username, realm, self.password))',
            ),
            (
                "GitHub webhook signature format",
                "taiga/webhooks/tasks.py",
                "mac = hmac.new(key, msg=data, digestmod=hashlib.sha1)\n"
                '"X-Hub-Signature": "sha1={}"',
            ),
            (
                "Gravatar is defined over an MD5 of the email",
                "taiga/users/gravatar.py",
                "return hashlib.md5(email.lower().encode()).hexdigest()",
            ),
        ],
    )
    def test_it_refuses_to_migrate(self, label: str, path: str, snippet: str) -> None:
        verdict = external_contract("MD5", path, snippet)
        assert verdict is not None, label
        assert verdict.reason and verdict.signal, "a refusal must say why and on what evidence"

    def test_the_advice_tells_the_operator_what_to_do_instead(self) -> None:
        """A refusal that only says no is a worse outcome than a wrong patch, because the finding
        is real and the operator still has to act on it."""
        verdict = external_contract(
            "MD5",
            "src/pyload/plugins/accounts/RapideoPl.py",
            'data["pwd"] = hashlib.md5(password.encode()).hexdigest()',
        )
        assert verdict is not None
        advice = verdict.advice("MD5")
        assert "negotiate" in advice
        assert "accept the risk" in advice
        # It must also carry the evidence, so the operator can check the call rather than trust it.
        assert verdict.signal in advice


class TestChoicesThisRepositoryOwns:
    """The other direction. Over-refusing would quietly make the tool useless."""

    @pytest.mark.parametrize(
        ("label", "path", "snippet"),
        [
            ("a cache key", "flexget/utils/tools.py", "return hashlib.md5(str(config).encode())"),
            (
                "a download filename",
                "flexget/plugins/output/download.py",
                "hashlib.md5(url.encode())",
            ),
            (
                "a request fingerprint for deduplication",
                "scrapy/utils/request.py",
                "fp = hashlib.sha1(to_bytes(canonicalize_url(request.url)))",
            ),
            (
                "an ETag over file contents",
                "app/static.py",
                "etag = hashlib.md5(file_bytes).hexdigest()",
            ),
            # NOTE: `PBKDF2HMAC(...)` was a negative case here until the KDF-parameter rule
            # landed. It moved to `TestTuningAnEstablishedKdfIsNotAOneLineEdit` because the rule's
            # own reasoning applies to it — it is an established KDF, so the only change available
            # is to its parameters, and that invalidates stored hashes. Reclassified rather than
            # deleted, so the change of mind is visible.
        ],
    )
    def test_it_leaves_them_alone(self, label: str, path: str, snippet: str) -> None:
        assert external_contract("MD5", path, snippet) is None, label


class TestTheSignalsAreDistinguishable:
    """Each rule must be reachable on its own, or a broken one hides behind another."""

    def test_path_alone_is_enough(self) -> None:
        assert external_contract("MD5", "lib/ntlm/session.py", "digest = md5(nonce)") is not None

    def test_field_name_alone_is_enough(self) -> None:
        v = external_contract("SHA-1", "app/hooks.py", 'headers["X-Hub-Signature"] = sig')
        assert v is not None

    def test_credential_input_alone_is_enough(self) -> None:
        """No protocol path, no algorithm-naming field — only the fact that a bare digest is being
        taken over a password. That is either a wire value or a stored hash, and neither survives a
        one-line algorithm swap."""
        v = external_contract("MD5", "app/util.py", "h = hashlib.md5(password.encode())")
        assert v is not None

    def test_an_empty_snippet_does_not_crash_or_refuse(self) -> None:
        """Findings from config and certificate scanners carry no snippet. Refusing everything with
        no evidence would disable the tool wherever evidence is thin."""
        assert external_contract("MD5", "app/util.py", None) is None
        assert external_contract("MD5", None, None) is None

    def test_the_pattern_compiled_correctly(self) -> None:
        """A regression guard with a specific history.

        The credential rule was first written with `\\b` word boundaries through a shell heredoc,
        which turned them into literal **backspace** characters (`\\x08`). The module imported, the
        tests that existed passed, and the rule silently matched nothing — B0 kept producing the two
        broken patches it was written to stop. Asserted structurally so a future escaping mistake
        fails loudly instead of disabling the guard.
        """
        from qubit_migrate.protocol_contract import _CREDENTIAL_DIGEST

        assert "\x08" not in _CREDENTIAL_DIGEST.pattern
        assert _CREDENTIAL_DIGEST.search("hashlib.md5(password.encode())") is not None


class TestTheGuardIsActuallyWiredIn:
    """The module can be perfect and never called.

    A mutation run that deleted the `external_contract(...)` call from `generate_patch` left every
    test above green — because they all exercise the function directly and none of them exercised
    the pipeline. A guard nothing invokes is decoration, and this is the test that says otherwise.
    """

    def test_generate_patch_calls_the_contract_check(self) -> None:
        """Asserted structurally against the orchestrator's source.

        Deliberately not a full end-to-end generation: that needs a seeded database, a repository
        on disk and a scan, and it would fail for a dozen reasons unrelated to this wiring. What
        must hold is narrow and checkable — the call exists, it happens BEFORE any generator runs,
        and its verdict routes to guided remediation rather than being computed and discarded.
        """
        from pathlib import Path

        src = Path("packages/qubit-migrate/src/qubit_migrate/orchestrator.py").read_text(
            encoding="utf-8"
        )

        assert "external_contract(" in src, "the guard is never called"
        assert "from .protocol_contract import external_contract" in src

        call = src.index("contract = external_contract(")
        # It must precede the generator dispatch, or a broken patch is written before anyone asks.
        marker = src.index("_mark_generating", call)
        assert call < marker, "the contract check must run before generation starts"

        # And its result must be acted on, not merely computed. Scoped to the enclosing block
        # rather than to a fixed number of characters — a character window silently stopped
        # covering the `raise` the first time a comment was added above it, which would have let a
        # later edit remove the enforcement without failing anything.
        window = src[call : src.index("\n    def ", call)]
        assert "raise GuidedRemediation" in window, "the verdict is computed but never enforced"
        assert "advice_text" in window, "a refusal must record advice for the operator"


class TestTuningAnEstablishedKdfIsNotAOneLineEdit:
    """The third rule, and a different failure from the two above.

    When the code already uses a recognised KDF, the only change available is to its parameters —
    and that is unsafe in both directions a KDF can be used:

    * a **stored** hash is verified by re-deriving with whatever the code says now, so changing a
      parameter invalidates every existing hash unless the parameter travels with the value;
    * a **derived** key that a remote party also computes requires both sides to agree.

    Both were measured in the pilot arm, both passed every runnable gate, and neither is caught by
    the credential or field-name rules — there is no credential in the call and nothing is posted in
    the visible snippet.
    """

    @pytest.mark.parametrize(
        ("label", "snippet"),
        [
            (
                "pyload's own password store — no iteration count is persisted alongside the hash",
                "kdf = PBKDF2HMAC(\n algorithm=hashes.SHA256(),\n length=32,\n iterations=100000,",
            ),
            (
                "Mega v2 derivation — the server supplies the salt and derives the same key",
                'elif res["v"] == 2:\n kdf = PBKDF2HMAC(\n algorithm=hashes.SHA512(),',
            ),
            (
                "a login payload derived with pbkdf2_hmac",
                'encrypted = hashlib.pbkdf2_hmac("sha256", b_password, b_password, 1000)',
            ),
            ("scrypt", "kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)"),
            ("argon2", "ph = argon2.PasswordHasher()"),
        ],
    )
    def test_it_is_guided_rather_than_patched(self, label: str, snippet: str) -> None:
        verdict = external_contract("PBKDF2", "app/accounts.py", snippet)
        assert verdict is not None, label

    def test_a_weak_kdf_is_still_migratable_in_principle(self) -> None:
        """Scoped deliberately. Replacing `md5(password)` with a real KDF is a genuine algorithm
        change, and this rule must not be what stops it — the credential rule handles that case, for
        its own reason, and the two must stay distinguishable."""
        from qubit_migrate.protocol_contract import _ESTABLISHED_KDF

        assert _ESTABLISHED_KDF.search("hashlib.md5(password.encode())") is None

    def test_symmetric_crypto_is_untouched(self) -> None:
        """The rule must not creep. An AES mode change is a different transformation with different
        risks, and refusing it here would quietly disable `code-ecb-01`."""
        assert (
            external_contract(
                "AES", "app/crypt.py", "cipher = Cipher(algorithms.AES(key), modes.CBC(iv))"
            )
            is None
        )


class TestTheIdentifierCanNameTheContract:
    """Found by the blind patch review, not by any gate.

    `flexget/utils/bittorrent.py` contains, inside `def info_hash(self)`:

        sha1_hash = hashlib.sha1()
        sha1_hash.update(encode_dictionary(self.content['info']))

    The codemod rewrote it to SHA-256. It applied, parsed, resolved symbols, compiled and rescanned
    clean — and BEP-3 *defines* the BitTorrent info-hash as the SHA-1 of the bencoded info
    dictionary, so the torrent loses its identity: tracker announces, peer handshakes and every
    dedup against a known torrent stop working.

    None of the other rules saw it. No protocol path was registered for BitTorrent, the value goes
    into no named field, nothing is a credential, and there is no KDF. What gives it away is that
    **the variable is named after the algorithm** — the same tell as `md5Pass`, one level in.
    """

    @pytest.mark.parametrize(
        "snippet",
        [
            "sha1_hash = hashlib.sha1()",
            "md5sum = hashlib.md5()",
            "sha1sum = hashlib.sha1()",
            "self.sha1_digest = hashlib.sha1()",
            'md5_hash = hashlib.new("md5")',
        ],
    )
    def test_an_algorithm_named_binding_is_a_contract(self, snippet: str) -> None:
        """Asserted on a NEUTRAL path, so the rule is proven to stand on its own rather than
        hiding behind the `bittorrent` path marker added alongside it."""
        assert external_contract("MD5", "app/neutral.py", snippet) is not None

    @pytest.mark.parametrize(
        "snippet",
        [
            "digest = hashlib.md5()",
            "hashed_name = hashlib.md5(url.encode())",
            "url_hash = hashlib.md5(config['url'].encode())",
            "fp = hashlib.sha1(to_bytes(url))",
            "return hashlib.md5(str(config).encode()).hexdigest()",
        ],
    )
    def test_a_neutrally_named_binding_stays_migratable(self, snippet: str) -> None:
        """The rule must key on the identifier naming the ALGORITHM, not on it naming a hash. Every
        one of these is a real Flexget line the tool correctly migrated."""
        assert external_contract("MD5", "app/neutral.py", snippet) is None

    def test_bittorrent_is_also_a_protocol_path(self) -> None:
        """Belt and braces, and deliberately so: the identifier rule is a heuristic, and BitTorrent
        is a named protocol whose hash is specified. Both should catch this file."""
        assert external_contract("SHA-1", "flexget/utils/bittorrent.py", "h = hashlib.sha1()")
