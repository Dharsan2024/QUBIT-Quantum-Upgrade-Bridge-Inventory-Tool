"""Is this finding's algorithm the repository's choice, or somebody else's contract?

Migrating cryptography that a remote party has specified does not harden anything — it breaks the
conversation. RFC 2617 HTTP Digest *requires* MD5; Gravatar's URL scheme is *defined* over an MD5 of
the email; a field named `md5Pass` in a request body is the service's name for the value it expects.

This module exists because the evaluation measured what happens without it. On `pyload/pyload`,
**eleven patches — seven from a deterministic codemod and three from a language model — passed
`applies`, `parses`, `symbols`, `compiles` and `rescan`, and every one broke authentication.** They
failed the same way: each rewrote crypto whose format or parameters are fixed outside the
repository. The knowledge needed to refuse them existed at the time, in
`scripts/corpus_select.py`'s corpus scorer, and never reached generation. See
`qubit-v2/08-evaluation/RESULTS-B0-arm.md`.

**The verdict is `guided`, not `skip`.** A protocol-mandated weak hash is still a real risk and the
operator still needs to know: the answer is to change the protocol, negotiate with the service, or
accept the risk deliberately — none of which is a source edit this tool can make. Advising is the
correct output; silently dropping the finding would be a different way of being wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Paths whose cryptography is protocol-mandated by construction.
#:
#: Measured, not guessed: these are the markers that correctly rejected `psf/requests` as a corpus
#: (RFC 2617 Digest MD5) and `taigaio/taiga-back` (GitHub's `X-Hub-Signature` HMAC-SHA1 and
#: Gravatar's MD5).
#:
#: **`auth.py` is deliberately NOT here**, though it was at first. It is the most common filename in
#: existence for application authentication code, and matching it wholesale refused a migration in
#: `test_m2_acceptance` whose finding is genuinely refusable — but for being a stored password hash,
#: not for its filename. A rule that reaches the right verdict by the wrong route will reach a wrong
#: verdict as soon as the route changes. `requests`' Digest code is still caught, by the credential
#: rule below, on the evidence rather than on the path.
_CONTRACT_PATHS: tuple[str, ...] = (
    "/digest",
    "digest.py",
    "/ntlm",
    "ntlm.py",
    "kerberos",
    "/sasl",
    "sasl.py",
    "webdav",
    "gravatar",
    # BitTorrent: BEP-3 defines the info-hash as the SHA-1 of the bencoded info dictionary. Change
    # it and the torrent no longer has the same identity — tracker announces, peer handshakes and
    # every dedup against a known torrent all fail. Found by the blind patch review (8.4), which
    # is the only part of the evaluation whose verdict does not come from this project's own gates.
    "bittorrent",
    "bencode",
)

#: Field and header names that EMBED the algorithm.
#:
#: The principle: when the name of the field carrying the value names the algorithm, the algorithm
#: is the remote party's contract and not this codebase's choice. `"md5Pass"` is Linkifier's name
#: for an MD5 hex digest; `X-Hub-Signature: sha1=` is GitHub's. Renaming the algorithm underneath
#: such a field changes what the other end receives.
_CONTRACT_FIELDS: tuple[str, ...] = (
    "md5pass",
    "md5_pass",
    "hash_password",
    "passwordhash",
    "x-hub-signature",
    "sha1=",
    "md5=",
    "pbkdf2_sha256$",
    "digestmod=hashlib.sha1",
    "digestmod=hashlib.md5",
    # HTTP Digest protocol tokens (RFC 2617/7616). These name the scheme itself, so their presence
    # is the strongest possible evidence that the hash is the protocol's and not the code's.
    # Matched on the SNIPPET rather than on `auth.py`, so a project that happens to keep its login
    # code in a file of that name is not refused for its filename.
    "httpdigestauth",
    "www-authenticate",
    "qop=",
    'qop="',
)

#: Service URLs whose SCHEME is defined over a particular digest.
#:
#: The same principle as `_CONTRACT_FIELDS`, one layer out: when a snippet builds a URL for a
#: service whose address format is a hash of something, the algorithm belongs to that service.
#:
#: This exists because `_CONTRACT_PATHS` already carried `gravatar` — and matched it against the
#: **file path**. That works for a project with a `gravatar.py` and fails for every project that
#: puts the same three lines in `integrations.py`, which is where an application actually puts
#: them. The knowledge was right and the place it was consulted was wrong.
#:
#: Found by the MediVault twin, which was built with the Gravatar call in `integrations.py`
#: precisely because that is where it belongs; the guard read the path, saw nothing, and cleared a
#: finding whose evidence was sitting in the snippet. See
#: `qubit-v2/08-evaluation/RESULTS-digital-twin.md`. **Guard recall on that fixture moves 4/9 → 5/9
#: as a result, and that number is therefore not an independent measurement of this rule** — the
#: same application exposed the gap and scores the fix.
_CONTRACT_URLS: tuple[tuple[str, str], ...] = (
    ("gravatar.com/avatar", "Gravatar addresses an avatar by the MD5 of the lowercased email"),
    ("libravatar.org/avatar", "Libravatar uses the same scheme as Gravatar"),
    ("www.gravatar.com", "Gravatar addresses an avatar by the MD5 of the lowercased email"),
)

#: The value is placed into an outbound request.
#:
#: A hash whose output is posted to a URL must match what the far end computes. Paired with a
#: string-literal key naming the algorithm (`_LITERAL_KEY`), this is the signature of a wire format.
_OUTBOUND = re.compile(
    r"""(?:
        \bpost\s*=|\bpost\[|\bdata\[|\bpayload\b|\bparams\s*=
        |\bapi_request\(|\brequests?\.(?:post|get)\(|\bself\.load\(
        |\burlencode\(|\bjson\.dumps\(
    )""",
    re.VERBOSE,
)

#: A dict key or keyword whose *name* mentions a hash or cipher, written as a literal.
_LITERAL_KEY = re.compile(
    r"""["'][^"']*(?:md5|sha1|sha-1|sha256|sha_256|pbkdf2|crc32|hmac)[^"']*["']\s*[:=]""",
    re.IGNORECASE,
)

#: A plain digest taken over a credential.
#:
#: This is the strongest rule here and the one with the clearest justification. When a bare hash
#: (`hashlib.md5(...)`, `sha1(...)`) is computed over something named like a credential, the result
#: is one of exactly two things, and **a blind algorithm swap is wrong in both**:
#:
#:   * a value sent to a remote party — changing the algorithm changes what they receive, and the
#:     exchange stops working; or
#:   * a password digest kept locally — changing the algorithm invalidates every stored hash unless
#:     the scheme travels with the value, which a one-line edit does not arrange.
#:
#: Both were measured on `pyload`. The wire case broke Linkifier, NoPremium, Rapideo, Twojlimit and
#: StreamCz; the storage case appeared in the pilot arm, where raising PBKDF2 iterations in
#: `user_database.py` would lock out every existing user because `_salted_password` returns
#: `salt + dk.hex()` and stores no iteration count.
#:
#: So the rule is not "this is a protocol" — it is "this needs a migration plan, not a rename", and
#: `guided` is the honest verdict for both.
_CREDENTIAL_DIGEST = re.compile(
    r"(?:md5|sha1|sha_1|sha224|sha256|sha384|sha512|new)\s*\(\s*"
    r"[\w.]*(?:password|passwd|pwd|pw|api_?pass|api_?key|apikey|secret|token|credential)",
    re.IGNORECASE,
)


#: An ALREADY-ESTABLISHED key-derivation function.
#:
#: A separate rule from the ones above, because the failure is a different one. When the code
#: already uses a recognised KDF, the only change available is to its PARAMETERS — more iterations,
#: a different hash, a different cost — and a parameter change is never a safe one-line edit:
#:
#:   * for a **stored** password hash, verification re-derives with whatever the code says now, so
#:     changing the parameter invalidates every existing hash unless the parameter travels with the
#:     value. `pyload`'s `_salted_password` returns `salt + dk.hex()` and stores no iteration count;
#:     the pilot arm's patch raising 100,000 to 600,000 would lock out every existing user.
#:   * for a **derived** key the far end also computes, both sides must agree. `MegaCoNz`'s
#:     `res["v"] == 2` branch is Mega's own derivation, with the salt supplied by Mega's server.
#:
#: Both were measured, both passed every runnable gate, and neither is caught by the rules above —
#: there is no credential in the call and nothing is posted in the visible snippet. The correct
#: output is a migration plan (rehash on next login, or negotiate with the service), which is
#: exactly what `guided` means.
#:
#: Scoped deliberately to *established* KDFs. Migrating `md5(password)` to PBKDF2 is a real
#: algorithm change and is handled by `_CREDENTIAL_DIGEST` above; this rule is only about tuning
#: something already fit for purpose.
_ESTABLISHED_KDF = re.compile(
    r"(?:PBKDF2HMAC|pbkdf2_hmac|PBKDF2|Scrypt|scrypt|Argon2|argon2|bcrypt)\s*\(",
)


#: A variable or attribute whose NAME embeds the algorithm.
#:
#: `sha1_hash = hashlib.sha1()`, `md5sum = ...`, `self.sha1_digest = ...`. The same principle as the
#: field-name rule, one level in: when the identifier holding the value names the algorithm, the
#: algorithm is part of the contract the surrounding code is written against. Renaming the algorithm
#: underneath it leaves the code lying about itself at best, and breaks a protocol at worst.
#:
#: Caught by the blind review on `flexget/utils/bittorrent.py`, where `sha1_hash = hashlib.sha1()`
#: inside `def info_hash(self)` was rewritten to SHA-256 — a change that passed every gate and
#: destroys torrent identity. None of the other three rules saw it: no protocol path at the time, no
#: named field, no credential, no KDF.
#:
#: Scoped to the identifier, not the whole snippet: `digest = hashlib.md5()` and
#: `url_hash = hashlib.md5(...)` name no algorithm and stay migratable.
_ALGORITHM_NAMED_BINDING = re.compile(
    r"(?:^|[\s.(\[])(?:[a-z_]*_)?(?:md5|sha1|sha_1|crc32)(?:_?(?:hash|sum|digest|hex))?\s*=\s*"
    r"(?:hashlib\.|hmac\.)?(?:md5|sha1|new)\s*\(",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class ContractVerdict:
    """Why this finding is somebody else's contract, in words an operator can act on."""

    reason: str
    signal: str

    def advice(self, algorithm: str) -> str:
        return (
            f"{algorithm} here is fixed by a party outside this repository — {self.reason}. "
            f"Changing it does not harden anything; it changes what the other end receives, and "
            f"the exchange stops working. Detected from: {self.signal}. "
            f"The options are to negotiate a protocol change with that party, to migrate the "
            f"protocol itself, or to accept the risk deliberately and record it. None of those is "
            f"an edit to this line."
        )


def external_contract(
    algorithm: str | None,
    file_path: str | None,
    snippet: str | None,
) -> ContractVerdict | None:
    """The finding's algorithm is fixed elsewhere, or `None` if it looks like a free choice.

    Deliberately conservative in one direction and not the other: a false `None` costs a broken
    patch that the gates will not catch, while a false verdict costs an advisory on a finding that
    could have been auto-migrated. The first is much more expensive, so borderline cases return a
    verdict.
    """
    path = (file_path or "").replace("\\", "/").lower()
    body = snippet or ""
    low = body.lower()

    for marker in _CONTRACT_PATHS:
        if marker in path:
            return ContractVerdict(
                reason=f"it lives on a protocol path (`{marker.strip('/')}`)",
                signal=f"path contains {marker!r}",
            )

    for field in _CONTRACT_FIELDS:
        if field in low:
            return ContractVerdict(
                reason=f"the value is carried in a field the remote names `{field}`",
                signal=f"snippet contains {field!r}",
            )

    for host, why in _CONTRACT_URLS:
        if host in low:
            return ContractVerdict(
                reason=f"the value is placed into a `{host}` URL, and {why}",
                signal=f"snippet contains {host!r}",
            )

    # A literal key naming a hash, in code that posts. Either alone is weak; together they are the
    # shape of a wire format.
    key = _LITERAL_KEY.search(body)
    if key and _OUTBOUND.search(body):
        return ContractVerdict(
            reason="the value is written into an outbound request under a key that names the "
            "algorithm",
            signal=f"literal key {key.group(0).strip()!r} alongside an outbound call",
        )

    named = _ALGORITHM_NAMED_BINDING.search(body)
    if named is not None:
        return ContractVerdict(
            reason="the identifier holding the value names the algorithm, so the algorithm is part "
            "of the contract the surrounding code is written against",
            signal=f"snippet contains {named.group(0).strip()!r}",
        )

    kdf = _ESTABLISHED_KDF.search(body)
    if kdf is not None:
        return ContractVerdict(
            reason="it already uses an established key-derivation function, so the only available "
            "change is to its parameters — and that invalidates stored hashes unless the "
            "parameters travel with the value, or breaks a derivation the far end also computes",
            signal=f"snippet contains {kdf.group(0).strip()!r}",
        )

    cred = _CREDENTIAL_DIGEST.search(body)
    if cred is not None:
        return ContractVerdict(
            reason="it is a plain digest over a credential, which is either a value a remote "
            "party verifies or a stored password hash — and swapping the algorithm breaks the "
            "first and invalidates the second",
            signal=f"snippet contains {cred.group(0).strip()!r}",
        )

    return None
