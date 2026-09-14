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


#: A key agreement whose other half runs somewhere else.
#:
#: The rules above all ask "who owns this FORMAT". This one asks a different question — "who holds
#: the other half of this computation" — and it is the only rule here whose answer makes the patch
#: space provably empty rather than merely risky.
#:
#: Measured on `medivault-emr`. `negotiate_referral_key` is
#:
#:     peer_public = serialization.load_pem_public_key(peer_public_pem)
#:     return private_key.exchange(ec.ECDH(), peer_public)
#:
#: and the twin's own tests state the property that makes it unpatchable:
#:
#:     negotiate_referral_key(ours, their_public) == negotiate_referral_key(theirs, our_public)
#:
#: ECDH is SYMMETRIC — both ends run the same code and get the same secret. A KEM is not: one side
#: encapsulates and the other decapsulates, and the encapsulation ciphertext has to travel between
#: them. A function that takes a peer's public key and returns only a secret has nowhere to put that
#: ciphertext, so every candidate patch either keeps ECDH (and `rescan` rejects it) or drops the
#: symmetry (and the two clinics stop agreeing). `py-ecdh-kex-01` spent three model attempts on that
#: empty space and the patch it produced passed `applies`, `parses`, `compiles` and `rescan` before
#: `tests` caught it. `guided` — "upgrade both ends together, here is the plan" — is the answer,
#: and reaching it costs no model calls at all.
#:
#: Scoped to the agreement call taking a COUNTERPARTY-NAMED input, not to key agreement in general.
#: The seal-to-self shape — generate an ephemeral key, agree with a recipient's static public key,
#: and ship the ephemeral public alongside the ciphertext — is genuinely migratable, because the
#: message that would carry a KEM ciphertext already exists in the format. That shape does not name
#: its input `peer`/`partner`/`counterparty`, because there is no live counterparty in it.
_TWO_PARTY_AGREEMENT = re.compile(
    r"""(?:
        \.\s*exchange\s*\(\s*(?:[\w.]*(?:ECDH|DH)\s*\(\s*\)\s*,\s*)?
            [\w.]*(?:peer|partner|remote|counterparty|their|other_party)
      | \.\s*(?:generate_shared_secret|compute_key|key_agreement|agree_key)\s*\(\s*
            [\w.]*(?:peer|partner|remote|counterparty|their|other_party)
      | \b(?:peer|partner|remote|counterparty|their)_\w*public\w*\s*=\s*
            [\w.]*load_(?:pem|der|ssh)_public_key
      | \b(?:ECDH|DH)_compute_key\s*\(
    )""",
    re.IGNORECASE | re.VERBOSE,
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


#: The code itself says the algorithm is required.
#:
#: The strongest possible code-level evidence, and the cheapest to check: when a source file states
#: in so many words that a weak algorithm is mandated, the algorithm is not this codebase's choice.
#: A tool that rewrites it has overruled a statement the authors wrote down precisely so that nobody
#: would.
#:
#: Measured on `paymesh-gateway` (Java), which the guard migrated against an explicit refusal:
#:
#:     throw new IllegalStateException("MD5 is required by the legacy acquirer channel", e);
#:
#: The manifest marks that finding `remote-party` with its evidence class `code` -- meaning a static
#: rule should have reached it -- and no rule here did, because every pattern above was written
#: against Python idiom and this is a Java string literal in a throw.
#:
#: Both word orders are matched: "MD5 is required by ...", and "... requires MD5".
_ALGORITHM_REQUIRED = re.compile(
    r"""["'][^"']*(?:
        (?:md5|sha-?1|des|3des|rc4|rc2|blowfish|cast5|idea)[^"']{0,40}(?:is\s+required|is\s+mandated|required\s+by|mandated\s+by|must\s+be\s+used|only\s+accepts|is\s+the\s+only)
      | (?:requires|mandates|expects|only\s+accepts|must\s+use)[^"']{0,40}
        (?:md5|sha-?1|des|3des|rc4|rc2|blowfish|cast5|idea)
    )[^"']*["']""",
    re.IGNORECASE | re.VERBOSE,
)

#: A schema VERSION TOKEN prefixed to a digest's OUTPUT -- the shape of a value that was handed
#: out and has to stay parseable by whatever holds it.
#:
#: Measured on `sentinel-idp`'s `SignSessionCookie` (SN-03), whose manifest evidence class is
#: `code` -- a static rule was supposed to reach it and none did:
#:
#:     mac := hmac.New(sha1.New, key)
#:     mac.Write([]byte(payload))
#:     return fmt.Sprintf("v1.%s", hex.EncodeToString(mac.Sum(nil)))
#:
#: A value the code stamps with its own format version is a value somebody else stores and reads
#: back: browsers hold these cookies, and re-signing them under a new algorithm invalidates every
#: live session. Before this it reached `deferred/unresolved` -- not migrated, but by accident,
#: after a generation attempt failed, rather than by a decision anyone could point at.
#:
#: **The discriminator is that the token prefixes the digest's OUTPUT.** Every migratable
#: prefixed-digest case in this corpus applies its delimiter to the hashed INPUT instead -- rate
#: limit buckets (`"%s:%d"`), cache and thumbnail keys (`"#{id}:page="`), merchant digests
#: (`String.join("|", ...)`). Each guard below earns its place against one of those:
#:
#:   * `[a-z]{1,4}\d+` -- a short marker plus digits. The four-letter cap is what keeps Go's
#:     `pbkdf2.` (five) out of it, since `pbkdf2.Key(...)` is an ordinary package reference.
#:   * the delimiter set excludes `=`, which is exactly what the `sha1=`/`md5=` wire prefixes use.
#:     Those are already `_CONTRACT_FIELDS`' business (SN-06, MV-12, IE-07, PM-01) and this rule
#:     must not double-claim them under a worse reason.
#:   * a digest-RENDERING call has to follow the literal in the same statement. Without it the
#:     rule would fire on a version token in the hashed input, which is a cache key, not a format.
#:   * the three `W/"` ETags (SN-12, IE-13, PM-12) are all expected MIGRATE and all carry no
#:     digits at all, so they never reach the digit requirement.
#:
#: Verified against every non-test source file in all four twins: exactly one match, this finding.
#: Also matches the `s1.` spelling, because the evaluation's own GitHub mirror carries a mangled
#: copy of this line -- an earlier run's patch appears to have bumped the version marker along with
#: the algorithm, which is its own kind of evidence that this value looks like a format to a model.
_VERSIONED_OUTPUT = re.compile(
    r"""["'`][a-z]{1,4}\d+[.:|\#$-]
        [^\n;]{0,80}?
        (?:hex\.encodetostring|encodetostring|hexdigest|tohexstring|
           \.sum\s*\(|b64encode|\.digest\s*\()
    """,
    re.IGNORECASE | re.VERBOSE,
)

#: A function whose NAME says its return value is an identity something else stores.
#:
#: The ownership model reads documentation, which works when a developer wrote down that a value
#: is persisted. Real repositories mostly do not: they say it in the name of the function and in
#: the shape of what it returns. Measured on scrapy, a repository with no planted findings and no
#: docstring written with this tool in mind, `documented_constraint` returned `none` for all five
#: of its persisted-digest sites -- every one of which is a value the project stores:
#:
#:   * `fingerprint` (utils/request.py) -- the dupefilter's on-disk `requests.seen` entries and the
#:     HTTP cache key. A new algorithm makes every previously-seen request look unseen.
#:   * `file_path` / `thumb_path` (pipelines/files.py, pipelines/images.py) -- the digest IS the
#:     stored filename, `full/{guid}.jpg`. Changing it orphans every file already downloaded.
#:   * `_path_safe` (pqueues.py) -- the scheduler queue's on-disk directory name.
#:
#: Restricted to the filesystem vocabulary, which is unambiguous: a digest that becomes a path,
#: directory or filename is persisted BY CONSTRUCTION, because the filesystem is what holds it.
#: No judgement about the project's intent is required, which is what makes this safe to act on
#: from a name alone.
#:
#: Two exclusions, both deliberate and both load-bearing:
#:
#:   * `key`. A cache key is the canonical MIGRATABLE case in this corpus -- recomputed from live
#:     inputs, with nothing reading it back after a restart. Including it would refuse the very
#:     findings the tool exists to fix.
#:   * `fingerprint`. Tried, and rejected on evidence. It is genuinely ambiguous: scrapy's
#:     `fingerprint()` IS persisted (the dupefilter writes it to `requests.seen`), but nothing in
#:     the function or its docstring says so -- the docstring claims only that it "uniquely
#:     identifies the resource" -- and an unqualified `fingerprint` helper is just as often a
#:     value recomputed on every call. Including it refused a bare
#:     `def fingerprint(payload): return hashlib.md5(payload).hexdigest()`, which is the textbook
#:     migratable case, and contradicted three existing tests that assert exactly that migration.
#:     Refusing on a name that carries no such guarantee trades a false migration for a missed
#:     one, and this rule is not entitled to that trade on this evidence.
#:
#: The cost is recorded rather than hidden: scrapy's `utils/request.py` fingerprint is a real
#: persisted digest this rule does NOT catch. Reaching it needs knowledge that lives in the
#: dupefilter, not in the file being judged.
_STORED_IDENTITY_NAME = re.compile(r"(?:^|_)(?:path|dir|dirname|filename)(?:_|$)", re.IGNORECASE)

#: Renders a digest to the form that gets stored. Required alongside the name, so a function
#: merely NAMED `..._path` that happens to contain unrelated cryptography is not refused for it.
_DIGEST_RENDERED = re.compile(
    r"hexdigest\s*\(|\.digest\s*\(|hex\.encodetostring|encodetostring|tohexstring|"
    r"\.sum\d*\s*\(|b64encode",
    re.IGNORECASE,
)

#: Names a definition and captures the name, across the languages in this corpus.
#:
#: One anchored alternative per family rather than one clever pattern: an earlier single-regex
#: version put `[^)]*` in front of the name to allow for a Go receiver, and that consumed the name
#: itself, so every lookup returned the last one-letter token before a bracket.
_DEFINITION_NAME = re.compile(
    # Python, Ruby, Rust, Perl: `def name(`, `fn name(`.
    r"^\s*(?:async\s+)?(?:def|fn|sub)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    # Go: `func name(` or `func (r *T) name(`.
    r"|^\s*func\s+(?:\([^)]*\)\s*)?(?P<gname>[A-Za-z_][A-Za-z0-9_]*)\s*\("
    # Java/C#/Kotlin/Swift: modifiers, a return type, then the name.
    r"|^\s*(?:(?:public|private|protected|internal|static|final|abstract|synchronized|override"
    r"|suspend|open|func)\s+)+(?:[\w<>,\[\]. ?]+\s+)?(?P<jname>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)


def enclosing_definition_name(source: str, line: int, *, window: int = 400) -> str | None:
    """The name of the definition ``line`` sits in, or None when it sits at the top level.

    Selection is by INDENTATION, not by distance: the answer is the first definition header above
    ``line`` that is indented less than ``line`` itself. A fixed lookback cannot do this job --
    scrapy's `fingerprint` opens 69 lines above the digest it computes, all of it docstring, so a
    40-line window found nothing, while a window wide enough to reach it would attribute a
    top-level statement to whatever function happened to end above it. Indentation answers both:
    a line at column 0 has no enclosing definition and returns None.
    """
    lines = source.splitlines()
    index = min(max(line - 1, 0), max(len(lines) - 1, 0))
    if not lines:
        return None
    body = lines[index]
    own_indent = len(body) - len(body.lstrip())
    if own_indent == 0:
        return None
    for i in range(index, max(index - window, -1), -1):
        candidate = lines[i]
        if not candidate.strip():
            continue
        indent = len(candidate) - len(candidate.lstrip())
        if indent >= own_indent:
            continue
        match = _DEFINITION_NAME.search(candidate)
        if match:
            return match.group("name") or match.group("gname") or match.group("jname")
        # Anything else less-indented is passed over rather than treated as a boundary. A
        # multi-line signature puts its closing `) -> bytes:` at the DEFINITION's own indent --
        # column 0 for a top-level function -- so treating the first shallower line as the end of
        # the search stopped every lookup one line short of the header it wanted.
    return None


def digest_names_stored_state(source: str, line: int) -> ContractVerdict | None:
    """Refuse when a digest is rendered inside a function whose name says it returns stored state.

    The structural counterpart to `documented_constraint`, for the ordinary case where the
    constraint was never written down in prose. Both signals are required: the name alone would
    refuse any cryptography that happens to sit in a path helper, and a rendered digest alone is
    most of the corpus.
    """
    name = enclosing_definition_name(source, line)
    if not name or not _STORED_IDENTITY_NAME.search(name):
        return None
    if not _DIGEST_RENDERED.search(required_algorithm_in_body(source, line)):
        return None
    return ContractVerdict(
        reason=(
            "this digest is rendered inside a function whose name says its result is an identity "
            "something else stores - a path, filename or fingerprint - so changing the algorithm "
            "changes a value already written down outside this file, and every record still "
            "holding the old one stops matching"
        ),
        signal=f"the enclosing definition is named '{name}'",
    )


#: A digest taken over a credential, in the C-family calling convention.
#:
#: `_CREDENTIAL_DIGEST` above matches Python's `md5(password)` shape: the algorithm IS the function.
#: Java, Go, C# and C separate the two -- `MessageDigest.getInstance("SHA-1")` on one line and
#: `.digest(apiKey.getBytes(...))` on the next -- so the credential never appears as an argument to
#: anything named after a hash, and the rule could not fire.
#:
#: Measured on `paymesh-gateway`: `merchantKeyDigest(String apiKey)` computes SHA-1 over an API key
#: stored as `merchant.api_key_digest` and re-derived on every request. Changing it locks out every
#: merchant at once. The manifest marks it `credential-digest`, evidence `code`.
#:
#: The optional cast covers Go's `sha1.Sum([]byte(token))`.
_CREDENTIAL_DIGEST_CALL = re.compile(
    r"(?:digest|hexdigest|hash|computehash|sum\d*|hashbytes)\s*\(\s*"
    r"(?:\[\]byte\(|\(byte\[\]\)|bytes\()?"
    r"[\w.]*(?:password|passwd|pwd|api_?key|apikey|secret|token|credential|privatekey)",
    re.IGNORECASE,
)


#: Language a developer uses when an algorithm's output OUTLIVES the code that produced it.
#:
#: The scanner's evidence is a +/-2 line window, which is enough to see a call and nothing about
#: what happens to its result. But the reason a digest cannot change is almost never on the call
#: line -- it is in the docstring above it, or a comment on the column that stores the value.
#:
#: Measured across the four twins: refusals whose evidence class is `prose` were 4 of the 9 false
#: migrations in the first complete run, and every one of them had the constraint written down in
#: the file, two lines above the code that was rewritten.
#:
#: **This vocabulary was written while looking at applications that also score it**, the same
#: caveat `_CONTRACT_URLS` carries: recall measured on these twins is not an independent
#: measurement of this rule. What keeps it honest is the negative vocabulary below -- the twins
#: were built so that the same primitive appears on both sides of this line.
_PERSISTED_LANGUAGE = re.compile(
    r"""(?:
        persisted | stored\s+(?:as|in|against|alongside) | written\s+to\s+the\s+(?:database|table)
      | already\s+(?:stored|issued|signed|persisted|in\s+the) | existing\s+(?:rows|records|values)
      | re-?derived | content[\s-]address
      | de-?duplicat | primary\s+key | retained\s+for
      # `resolve` alongside `match`/`agree`: a retry, a re-upload or a re-presented header must
      # RESOLVE TO the same stored row as before, which is the same "the far end still has to
      # land on this value" constraint as "must match" -- just the verb a retry/dedup/idempotency
      # docstring actually uses. Measured missing on three real refusals across two twins:
      # `inkwell-esign` template_digest ("must resolve to the existing version"), `paymesh-gateway`
      # cardToken ("must resolve to the same vault row") and idempotencyDigest ("must resolve to
      # this same row"). All three also say so explicitly elsewhere in the same docstring
      # ("PERSISTED as", "primary key"), so this widens an existing true positive rather than
      # creating a new one.
      | must\s+(?:match|agree|resolve\s+to) | both\s+ends | the\s+far\s+end
      | counterpart(?:y|ies) | third[\s-]party
      # `(?<!\bto\s)`: naming a party is a contract when that party COMPUTES or CHECKS the value
      # ("the acquirer sends sha1=", "the scheme recomputes this", "using the scheme they
      # specified") and not when the value is merely delivered to them. Once the docstring walk
      # below started reading Python docstrings, the bare clause refused `wrap_data_key` -- "for
      # transport to the partner clinic" -- whose RSA-OAEP wrap is one of the twin's expected
      # MIGRATE findings and whose tests a KEM-DEM rewrite keeps green. No refusal measured on
      # paymesh, sentinel or inkwell is phrased "to the <party>"; all six are the party acting.
      | (?<!\bto\s)the\s+(?:partner|provider|acquirer|scheme|issuer)
      | their\s+(?:system|format|software|side) | upstream\s+(?:idp|provider|service)
      | (?:cannot|must\s+not|do\s+not|never)\s+(?:change|be\s+changed|be\s+migrated)
      # A bare adjective stating the same constraint as the verb phrase above, measured on
      # `paymesh-gateway`'s cardToken: "...which is what makes the algorithm unchangeable."
      | unchangeable
      # Out-of-band distribution: the value already left the repository for good, into a channel
      # this codebase cannot re-run -- an email already sent, a link already clicked days ago.
      # Measured missing on `inkwell-esign`'s `signing_link_token` ("ALREADY IN SOMEBODY'S INBOX
      # . Links were emailed to signers days or weeks ago and are still being clicked"), the one
      # false migration whose own comment names the constraint but not in any word this list
      # already had. Checked for collisions across all four twins: `inbox` occurs nowhere else
      # near a real finding's own documentation -- its one other occurrence in this corpus is a
      # MODULE docstring in the same file, and `enclosing_documentation`'s walk (see its own
      # docstring) already keeps every real finding here from reaching that far.
      | inbox
    )""",
    re.IGNORECASE | re.VERBOSE,
)

#: Prose saying TWO PARTIES independently compute the same value.
#:
#: Split out of `_PERSISTED_LANGUAGE` because it needs the opposite treatment under the regenerable
#: veto below. "Stored in the cache" is genuinely regenerable and the veto is right to clear it.
#: "Both ends derive this" is not made regenerable by anything: how long the value lives says
#: nothing about whether the far end still computes the same one.
#:
#: Measured on `medivault-emr`, where the veto cost a correct refusal. `generate_referral_keypair`'s
#: docstring is
#:
#:     Our half of the exchange, plus the public point to send to the partner clinic.
#:     QUBIT-FIXTURE: py-ecdh-kex-01 - P-256 ephemeral key agreement.
#:
#: `the partner` matched `_PERSISTED_LANGUAGE`; `ephemeral` matched `_REGENERABLE_LANGUAGE`, the
#: veto fired first, and the finding was cleared for generation. The patch broke
#: `test_both_clinics_derive_the_same_secret` and `test_a_third_party_derives_something_else`. The
#: word `ephemeral` there describes the KEY's lifetime, which is precisely what an ephemeral ECDH is
#: for; the counterparty is unaffected by it.
#:
#: **Kept deliberately narrow, and the omissions are the interesting part.** Anything that skips the
#: veto has to be a phrase that cannot appear in prose about migratable code, and three obvious
#: candidates fail that bar on the twins themselves:
#:
#:   * `both ends` / `both sides` -- the twins' phrase for the MIGRATABLE half. "both ends of the
#:     format are the two methods below" (`InternalDigests.encryptReportBundle`), "both ends of this
#:     exchange are this same binary" (`sentinel-idp` mesh ECDH), "both ends of the format are the
#:     two methods here" (`inkwell` draft cipher). All three are expected-MIGRATE, all three say
#:     there is NO second party, and bypassing the veto refused every one of them.
#:   * `counterpart(y|ies)` -- appears in `inkwell`'s `sign_audit_record`, an expected-MIGRATE
#:     finding, inside a sentence CONTRASTING it with the signing path: "identical primitives ...
#:     and that one is verified by counterparties". The word is in the block; the counterparty is
#:     not this function's.
#:   * `the partner` / `the provider` -- a party the value is merely DELIVERED to does not own its
#:     format. `wrap_data_key`, one function below the case this rule exists for, says "for
#:     transport to the partner clinic" and is genuinely migratable: a KEM ciphertext travels inside
#:     the same wrapped blob that already goes to the partner.
#:
#: What is left is first-person mutual computation -- prose that can only be about the code it sits
#: on. Those three stay in `_PERSISTED_LANGUAGE`, vetoable, exactly as they were.
_COUNTERPARTY_LANGUAGE = re.compile(
    r"""(?:
        must\s+(?:match|agree) | the\s+(?:far|other)\s+end
      | (?:our|their)\s+(?:half|side)\s+of\s+the\s+(?:exchange|agreement|handshake|conversation)
      | derives?\s+the\s+same | agrees?\s+(?:on\s+)?the\s+same
      # A published key set every consumer has already cached -- checked here, ahead of the
      # regenerable veto, for the same reason as the phrases above: `sentinel-idp`'s
      # `IssueIDToken` (SN-04) says both "cached" and "coordinated rotation" in one docstring,
      # and `cache` is `_REGENERABLE_LANGUAGE`'s own word for this codebase's OWN local cache --
      # the opposite of what it means here, where it is describing caches this codebase does not
      # control. Reachable only after the `_MAX_BODY_SKIP` fix above, since 20 body lines sit
      # between the RSA call and this function's own header comment. Checked for collisions:
      # `coordinated rotation` is unique to this one finding across all four twins.
      | coordinated\s+rotation
      # The authors saying outright that a protocol fixes this algorithm. Checked here rather than
      # in `_PERSISTED_LANGUAGE` for the same reason as the phrases above: a mandate is not undone
      # by the value being short-lived, so the regenerable veto must not reach it. `legacyPortalToken`
      # (PM-04) is a DAILY token -- it expires within a day and is still not this codebase's to
      # change, because the reconciliation portal recomputes the same MD5 and compares.
      #
      # Measured on `paymesh-gateway`, and it is the case the fixture calls "the deliberate
      # prose-evidence case": the constraint is recorded only in the javadoc, the variable is named
      # `digest`, and nothing within five lines of the call mentions a portal. Every occurrence of
      # this phrase across all four twins -- four of them, in `integrations.py` and
      # `ProviderSignatures.java` -- is on a finding ground truth marks refuse. None is on
      # migratable code.
      | protocol[\s-]mandated
    )""",
    re.IGNORECASE | re.VERBOSE,
)

#: The counterweight, and the reason the rule above is usable at all.
#:
#: "Stored in the cache" contains "stored in". A render cache, an ETag and an autosaved draft are
#: all written somewhere and all regenerable, and migrating them is correct. Without this the rule
#: would refuse the migratable half of every twin -- `Internal.render_cache_key` sits nine lines
#: from `Documents.content_digest` and uses the same primitive.
_REGENERABLE_LANGUAGE = re.compile(
    r"""(?:
        cache | ephemeral | in[\s-]process | per[\s-]request | regenerated
      # `recomputed every request` is the plainest statement of ephemerality there is, and
      # it was in the PERSISTED list -- which flagged both twins' rate-limit buckets, the
      # most obviously regenerable values in the corpus.
      #
      # But "recomputed" is not always that: `inkwell-esign`'s `Documents.content_digest` is
      # PERSISTED as `document.content_digest` and is "recomputed every time a signed PDF is
      # verified" -- recomputed FOR COMPARISON against an already-stored value, the opposite
      # of ephemeral. Measured: this exact text matched here and vetoed the persisted verdict,
      # so `content_digest` (manifest id IE-01) was migrated in every run despite its own
      # docstring saying "Expected disposition: REFUSE" in as many words -- a false migration
      # 100% reproducible against the pristine source, not a routing flake. The negative
      # lookahead excludes the recompute-and-compare idiom (`verif` catches verify/verified/
      # verification/verifies) from the regenerable veto while leaving the rate-limit idiom
      # (`recomputed every window`, `recomputed per request`, no "verif" anywhere nearby)
      # matching exactly as before.
      | recomputed\s+(?:per|every|each|on\s+every)(?!(?:\s+\S+){0,6}\s+verif)
      | rebuilt | rate[\s-]limit
      | discarded | temporary | transient | thumbnail | draft | this\s+session
      | only\s+(?:this|consumer|reader) | nothing\s+keeps
    )""",
    re.IGNORECASE | re.VERBOSE,
)


#: An explicit, file-level statement that a value's "other half" is this same codebase.
#:
#: Deliberately narrow and deliberately NOT folded into `enclosing_documentation`'s walk -- that
#: function stops at the first line of code above a symbol specifically because an earlier version
#: that read the whole module docstring caught an unrelated word ("cache") and cleared a real
#: refusal (see its own docstring). This is a separate, second read of the file limited to one
#: narrow phrase, consulted only to SUPPRESS `_COUNTERPARTY_LANGUAGE` -- it can never manufacture a
#: refusal, so a wrong match costs one extra repair round, not a wrong verdict.
#:
#: Measured: `medivault-emr/app/services/keyexchange.py` opens "Both ends of this exchange are
#: MediVault. There is no third party whose format is fixed" -- the fact that makes
#: `generate_referral_keypair`'s own "Our half of the exchange" phrasing migratable, sitting in the
#: MODULE docstring, one function away from where `_COUNTERPARTY_LANGUAGE` fires. Grepped across all
#: four twins: this phrase occurs nowhere else, so widening it costs nothing measured here.
_NO_THIRD_PARTY = re.compile(r"no\s+third[\s-]part(?:y|ies)\b", re.IGNORECASE)


def module_declares_no_third_party(source: str) -> bool:
    """Does ``source``'s own leading module docstring say its "other half" is itself?

    Reads only the file's first triple-quoted string, independent of any particular finding's
    line -- `enclosing_documentation` intentionally cannot reach this far (see `_NO_THIRD_PARTY`).
    """
    stripped = source.lstrip()
    for quote in ('"""', "'''"):
        if stripped.startswith(quote):
            end = stripped.find(quote, 3)
            if end == -1:
                return False
            return _NO_THIRD_PARTY.search(stripped[3:end]) is not None
    return False


def documented_constraint(
    context: str | None, *, module_declares_no_third_party: bool = False
) -> ContractVerdict | None:
    """A constraint the authors wrote down in prose next to the code.

    `context` is the enclosing documentation for the finding -- a docstring, or the comment block
    above the symbol -- NOT the +/-2 line snippet, which by construction cannot contain it.

    Two branches, because the two things a constraint can say need different treatment:

    * **another party holds the other half** -- a verdict, unless the file's own module docstring
      has already said there is no other party (`module_declares_no_third_party`). Nothing about
      the value's lifetime bears on whether the far end still agrees with it.
    * **the value outlives the call** -- a verdict only when the text does NOT also say it is
      regenerable. That second half is what separates a persisted content address from a render
      cache key written with the same primitive, which is the distinction the twins were built to
      isolate and the one a snippet-level rule cannot make.

    Erring toward a verdict is deliberate and is the same trade the rest of this module makes: a
    false verdict costs an advisory on a finding that could have been auto-migrated, a missed one
    costs a broken repository that every syntactic gate passes.
    """
    if not context:
        return None
    # Checked BEFORE the veto, and deliberately not subject to it. A counterparty is a counterparty
    # whether the value it agrees on lives for a session or for a decade, so `ephemeral`,
    # `per-request` and `this session` say nothing against it -- while for a STORED value those
    # words are the whole distinction between a content address and a render-cache key.
    #
    # Measured: `medivault-emr`'s `generate_referral_keypair` documents "the public point to send to
    # the partner clinic" and "P-256 ephemeral key agreement" in the same docstring. Under one
    # combined rule the second sentence vetoed the first, the finding was generated for, and both
    # of the twin's key-agreement tests broke.
    counterparty = _COUNTERPARTY_LANGUAGE.search(context)
    if counterparty is not None and not module_declares_no_third_party:
        return ContractVerdict(
            reason="the code documents this value as one agreed with another party, and only one "
            "side of that agreement is in this repository - changing it here means the two ends "
            "stop deriving the same value, which no edit confined to this file can fix",
            signal=f"documentation says {counterparty.group(0).strip()!r}",
        )
    if _REGENERABLE_LANGUAGE.search(context):
        return None
    match = _PERSISTED_LANGUAGE.search(context)
    if match is None:
        return None
    return ContractVerdict(
        reason="the code documents this value as one that outlives the call — persisted, "
        "re-derived, or agreed with another party — so changing the algorithm changes something "
        "already written down elsewhere",
        signal=f"documentation says {match.group(0).strip()!r}",
    )


def required_algorithm_in_body(source: str, line: int, *, before: int = 6, after: int = 14) -> str:
    """The enclosing function body around `line`, for the "this algorithm is required" check only.

    The scanner's evidence is a +/-2 line window, and a constraint stated in code is very often
    just outside it — below the call rather than above.
    `ProviderSignatures.signAuthorizationRequest`
    is the measured case:

        101:   MessageDigest md5Signature = MessageDigest.getInstance("MD5");   <- the finding
        102:   return Hex.encode(md5Signature.digest(...));
        103: } catch (NoSuchAlgorithmException e) {
        104:   throw new IllegalStateException("MD5 is required by the legacy acquirer channel", e);

    The window the guard sees is 99-103. The sentence that forbids the migration is on 104, and
    `PM-02` was migrated in every run because of those two lines. Its manifest evidence class is
    `code` — a static rule was supposed to reach it.

    Deliberately used for `_ALGORITHM_REQUIRED` and nothing else. That pattern needs a string
    literal SAYING the algorithm is mandated, which is unambiguous wherever in the function it
    appears; the other patterns in this module key on proximity (a credential passed to a hash, a
    URL built beside a digest) and would start firing on unrelated neighbours if widened the same
    way.
    """
    lines = source.splitlines()
    if not 1 <= line <= len(lines):
        return ""
    return "\n".join(lines[max(0, line - 1 - before) : min(len(lines), line + after)])


def enclosing_documentation(source: str, line: int, *, window: int = 40) -> str:
    """The documentation a reader would attach to the code at ``line``.

    The contiguous block of lines above the finding, up to the first double blank line: the
    docstring or comment its author wrote for whoever reads the function next. Both shapes count —
    a `#`/`//` block ABOVE the definition, and a triple-quoted docstring INSIDE it, which is where
    Python and Ruby put the same text.

    Scanning UPWARD rather than parsing is deliberate. The constraint is written for a human reading
    the code, and every language in the corpus puts that text in the same place relative to it —
    directly above. A grammar-based version would need a different node type per language and would
    still miss the Java case, where the constraint lives in a class-level javadoc that lists every
    method rather than beside any one of them.

    The walk stops at the first line of CODE above the definition, which is what keeps the context
    the symbol's own. An earlier version simply took 40 lines and got the whole module docstring
    with it — and on `inkwell-esign` that docstring contains the sentence "A signed PDF is not a
    cache entry", whose one word `cache` vetoed a correct refusal of a persisted content address.
    Reading a neighbouring symbol's documentation is not a smaller mistake than reading none.

    ``window`` bounds the walk, so a file of solid comments cannot become one enormous context.
    """
    lines = source.splitlines()
    if not 1 <= line <= len(lines):
        return ""

    # `line` is the FINDING's line — the crypto call — not the definition's. So the walk skips the
    # signature and whatever body sits above the call before it reaches the documentation. Anchoring
    # on the definition instead was the first version, and it returned "" for almost every real
    # finding, because a call is rarely the line a symbol starts on.
    #
    # `_MAX_BODY_SKIP` bounds that skip. Without it, a long undocumented function walks all the way
    # up into the PREVIOUS symbol's comment block and reads a constraint belonging to other code.
    collected: list[str] = []
    blanks = 0
    skipped_code = 0
    crossed_definition = False
    index = line - 2
    floor = max(-1, line - 2 - window)
    while index > floor:
        text = lines[index].strip()
        if not text:
            blanks += 1
            # One blank line may sit inside a comment block; two end it.
            if blanks >= 2 and collected:
                break
            index -= 1
            continue

        # A Python or Ruby docstring is the symbol's documentation and is NOT a `#` comment, so
        # `_is_comment` cannot see it and the walk used to charge straight past it as body code.
        #
        # Measured on `medivault-emr`: this function returned "" for five of the six findings whose
        # patches broke the twin's own suite, and for the sixth — `generate_referral_keypair`, whose
        # docstring says "the public point to send to the partner clinic" — it spent the whole
        # `_MAX_BODY_SKIP` budget walking out of the function and came back with a single markdown
        # bullet from the MODULE docstring, describing a different symbol entirely. Every prose
        # refusal in a Python file was unreachable for this one reason.
        #
        # The downward scan below does not cover it: that one requires the docstring to start at or
        # just after `line`, which only holds when the finding IS the `def` line. A crypto call is
        # in the body, with the docstring above it.
        if not crossed_definition:
            block, above = _docstring_above(lines, index, floor)
            if block is not None:
                collected.extend(block)  # bottom-up, like `collected`; reversed together below
                index = above
                break  # a docstring IS the symbol's documentation; nothing above it is
        if not _is_comment(text):
            if collected:
                break  # real code above the block: it belongs to whatever came before
            if _DEFINITION.match(text):
                # Reaching the finding's OWN `def`/`func` line is not a skip past anything —
                # it is still this symbol's own body, however long. `IssueIDToken`
                # (sentinel-idp) measured this the other way: 20 body lines sit between its
                # RS256 call and its own header comment naming the JWKS constraint, and the
                # unified counter below gave up 8 lines short of ever reaching it — a
                # documented, prose refusal (SN-04) that was unreachable for exactly the
                # reason `_MAX_BODY_SKIP` exists, not despite it.
                crossed_definition = True
                index -= 1
                continue
            # Past the finding's own `def`, any docstring belongs to the PREVIOUS symbol.
            # `unwrap_data_key` in the medivault twin is undocumented and sits directly under
            # `wrap_data_key`, so without this the walk sailed past its signature and returned
            # "Wrap a per-referral data key for transport to the partner clinic" — documentation
            # about a different function. That is the same mistake `_MAX_BODY_SKIP` was added to
            # stop for comment blocks; docstrings needed their own boundary because a `#` block
            # ABOVE a definition is legitimately this symbol's and a docstring above one is not.
            # Only counted once `crossed_definition` is true: before that we are still walking
            # THIS finding's own body, which can never be misattributed to another symbol no
            # matter how long it is.
            if crossed_definition:
                skipped_code += 1
                if skipped_code > _MAX_BODY_SKIP:
                    break
            index -= 1
            continue
        blanks = 0
        collected.append(text)
        index -= 1
    collected.reverse()

    # Python and Ruby put the docstring INSIDE the definition, below the line the symbol starts on,
    # so a walk that only looks upward finds the decorator and nothing else. Measured: every
    # `medivault-emr` refusal was missed this way.
    for index in range(line, min(len(lines), line + window)):
        text = lines[index].strip()
        if not text:
            continue
        if not (text.startswith('"""') or text.startswith("'''")):
            break
        quote = text[:3]
        collected.append(text.strip(quote))
        if text.count(quote) < 2:  # multi-line docstring: read to its close
            for tail in range(index + 1, min(len(lines), index + window)):
                body = lines[tail].strip()
                collected.append(body.replace(quote, ""))
                if quote in body:
                    break
        break

    return "\n".join(collected)


#: Every comment opener in the corpus. A prefix test rather than a grammar: this reads the block
#: ABOVE a definition, which most grammars do not attach to the definition's node at all.
_COMMENT_OPENERS = ("#", "//", "*", "/*", "--", "<!--")

#: How many lines of code may sit between a finding and its documentation before the walk gives up.
#:
#: The finding is a call, so the signature and some body always sit between it and the docstring.
#: But an UNDOCUMENTED function must not borrow the previous symbol's comment block: that reads a
#: constraint written about other code and refuses a migration on it. Twelve covers the functions in
#: the corpus (the longest documented one is nine lines) without reaching past a short neighbour.
_MAX_BODY_SKIP = 12


def _is_comment(text: str) -> bool:
    return text.startswith(_COMMENT_OPENERS)


#: Triple-quote openers, including the raw/byte/format prefixes a docstring is occasionally written
#: with (`r"""` for one containing a regex is the common one).
_DOCSTRING_QUOTES = ('"""', "'''")
_STRING_PREFIXES = ("r", "b", "u", "f", "rb", "br", "fr", "rf")

#: The two halves of a signature, and the key identifier that ties them together.
#:
#: `\.verify` covers `key.verify(...)`, `public_key.verify(...)`, Go's `rsa.VerifyPKCS1v15(...)`
#: and Java's `Signature.verify(...)`; the bare `verify_`/`verifies` forms cover a method DEFINITION
#: line, which is evidence about the enclosing function just as much as a call is.
_VERIFY_SIDE = re.compile(r"\.verify\w*\s*\(|\bverify[_a-z]*\s*\(", re.IGNORECASE)
_SIGN_SIDE = re.compile(r"\.sign\w*\s*\(|\bsign[_a-z]*\s*\(", re.IGNORECASE)
#: Any identifier; the ones NAMING KEY MATERIAL are filtered out of it below. That filter is the
#: discriminator — it is what makes `signing_key`, `signingKey`, `PublicKey` and a bare `key` a
#: link between two functions while `bytes`, `digest` and `payload` are not.
#:
#: Matching the whole identifier and filtering afterwards, rather than demanding `key` inside one
#: pattern: Go writes `rsa.SignPKCS1v15(rand.Reader, key, ...)`, and a pattern that required a
#: character before `key` matched every spelling in the corpus except that one.
_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def inherited_from_signing_counterpart(source: str, line: int) -> ContractVerdict | None:
    """A verifier inherits the constraint documented on the signer it is paired with.

    **A verification cannot change algorithm independently of the signature it checks.** That is
    not a heuristic about this corpus, it is what the operation is: re-deriving a verifier under a
    new digest stops it accepting everything already signed under the old one. So when the SIGNING
    half of a pair is refused on documented evidence, the verifying half is refused for the same
    reason — and when the signing half is free, nothing propagates and the verifier stays free.

    Measured on `inkwell-esign` (IE-06), the last false migration left in that twin.
    `Signing.sign_document` carries four paragraphs about why it must not change — "every signature
    already produced was made with this algorithm pair; +verify_document+ has to keep verifying
    them, and a counterparty holding a countersigned copy verifies it with their own software" —
    and is correctly refused on it. `verify_document`, seventeen lines below, has one bare line
    ("Must keep accepting everything ever signed") that carries no vocabulary this module knows,
    so it was migrated in every run: SHA-1 swapped underneath a verifier whose whole job is to
    keep accepting SHA-1. The constraint was written down. It was written down next to the other
    half.

    Static and order-independent by construction: the sibling's DOCUMENTATION is re-read from
    source, never its task outcome, so this returns the same verdict whichever finding the queue
    happens to reach first. Reading outcomes instead would have made the answer depend on
    scheduling, which is the defect § X-B already reports rather than a fix for it.

    Deliberately one-directional. The constraint belongs to the value that was PRODUCED and handed
    out, so it is written where the producing happens; propagating the other way would let a
    verifier's silence argue about a signer it knows nothing about.
    """
    lines = source.splitlines()
    if not 1 <= line <= len(lines):
        return None

    # Which half this finding is on is decided by its OWN line, and by the definition it sits in.
    # NOT by the body window: `required_algorithm_in_body` reaches fourteen lines down and six up,
    # which on a tightly written pair reaches straight into the other half — measured on
    # `signing.rb`, where the window around `verify_document` swallows `sign_document`'s fallback
    # branch four lines above and made the verifier look like a signer.
    own_line = lines[line - 1]
    definition = ""
    # Far enough back to clear a long body. `VerifyIDToken` (sentinel-idp) measured this: its RSA
    # call sits thirteen lines into the function and the finding is recorded a line past that, so a
    # ten-line lookback missed `func VerifyIDToken` by two and the whole rule silently declined.
    # Walking UP and stopping at the first definition means a generous bound costs nothing --
    # the first one found is the enclosing one.
    for index in range(line - 2, max(-1, line - 40), -1):
        text = lines[index].strip()
        if _DEFINITION.match(text) or text.startswith(("func ", "public ", "private ", "static ")):
            definition = text
            break
    side_context = f"{own_line}\n{definition}"
    if _SIGN_SIDE.search(side_context) or not _VERIFY_SIDE.search(side_context):
        return None  # not a verifier, or is itself the signing half

    body = required_algorithm_in_body(source, line)
    keys = {
        word for m in _IDENTIFIER.finditer(body) if "key" in (word := m.group(0).lower())
    }
    if not keys:
        return None

    own_documentation = enclosing_documentation(source, line)
    for number, text in enumerate(source.splitlines(), 1):
        if not _SIGN_SIDE.search(text) or _VERIFY_SIDE.search(text):
            continue
        if not any(key in text.lower() for key in keys):
            continue
        documentation = enclosing_documentation(source, number)
        # The signer's own documentation, and not a re-reading of the verifier's: a pair written
        # tightly enough can put both inside one walk, and inheriting from yourself proves nothing.
        if not documentation or documentation == own_documentation:
            continue
        verdict = documented_constraint(
            documentation, module_declares_no_third_party=module_declares_no_third_party(source)
        )
        if verdict is not None:
            return ContractVerdict(
                reason="this verifies what another function in the same file signs with the same "
                f"key, and that one is not free to change either — {verdict.reason}. A verifier "
                "re-derived under a new algorithm stops accepting everything already signed under "
                "the old one, so the two halves move together or not at all",
                signal=f"the signing half at line {number} says {verdict.signal}",
            )
    return None


#: A definition opener in the two languages that have docstrings at all.
#:
#: Used only as a BOUNDARY for the docstring walk, never to find documentation, so it does not need
#: to cover the corpus's other seventeen languages — none of them puts documentation inside the
#: body, which is the thing this boundary exists to keep straight.
_DEFINITION = re.compile(r"(?:async\s+)?(?:def|class|module)\b")


def _docstring_above(lines: list[str], index: int, floor: int) -> tuple[list[str] | None, int]:
    """The triple-quoted documentation block whose CLOSING line is ``lines[index]``.

    Returns its text bottom-up — the order `enclosing_documentation`'s accumulator is in, so the
    single `reverse()` at the end puts everything back in reading order — together with the index
    immediately above the opening delimiter. `(None, index)` when this line does not close one.

    Walking upward means the closing delimiter is met first, which is what makes this cheap: a
    docstring is the only construct in Python or Ruby that sits between a definition and its body,
    so meeting one on the way up means the walk has arrived at the symbol's own documentation and
    can stop. No grammar, no per-language node type, and it composes with the existing `#`-comment
    walk rather than replacing it.

    A line that merely CONTAINS a triple quote is not enough: an assigned multi-line string
    (`sql = ...`) closes on its own line and looks identical from below, and a query body is not
    documentation. So the OPENER has to start its line for the block to count, and anything else
    discards it and hands the walk back unchanged.

    ``floor`` is the caller's window, applied here too: an unterminated block is not allowed to read
    the whole file just because it is quoted.
    """
    text = lines[index].strip()
    quote = next((q for q in _DOCSTRING_QUOTES if text.startswith(q)), None)
    if quote is None:
        return None, index

    # `"""One line."""` — opener and closer on the same line.
    if text.count(quote) >= 2:
        return [text.strip(quote).strip()], index - 1

    body: list[str] = []
    for above in range(index - 1, max(-1, floor), -1):
        candidate = lines[above].strip()
        if quote not in candidate:
            body.append(candidate)
            continue
        head = candidate.split(quote, 1)[0]
        if head and head.lower() not in _STRING_PREFIXES:
            # `sql = """`, not a docstring. Give back nothing rather than a query body: reading a
            # string LITERAL as documentation is the same class of mistake as reading a
            # neighbouring symbol's comment block, and the module docstring's `inkwell-esign`
            # paragraph is what that costs.
            return None, index
        body.append(candidate.split(quote, 1)[1].strip())
        return body, above - 1
    return None, index


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

    cred = _CREDENTIAL_DIGEST.search(body) or _CREDENTIAL_DIGEST_CALL.search(body)
    if cred is not None:
        return ContractVerdict(
            reason="it is a plain digest over a credential, which is either a value a remote "
            "party verifies or a stored password hash — and swapping the algorithm breaks the "
            "first and invalidates the second",
            signal=f"snippet contains {cred.group(0).strip()!r}",
        )

    # The other half of this computation runs on someone else's machine. Unlike every rule above,
    # this one is not a judgement about risk: it is a statement that no patch confined to this file
    # can be correct, because the change needs a second message on the wire that the function has
    # no way to send. See `_TWO_PARTY_AGREEMENT`.
    agreement = _TWO_PARTY_AGREEMENT.search(body)
    if agreement is not None:
        return ContractVerdict(
            reason="it is one half of a key agreement whose other half runs outside this "
            "repository — a KEM replaces the symmetric ECDH exchange with an encapsulate/"
            "decapsulate pair and a ciphertext that has to reach the peer, so both ends must be "
            "upgraded together and this function has nowhere to put that ciphertext",
            signal=f"snippet contains {agreement.group(0).strip()!r}",
        )

    required = _ALGORITHM_REQUIRED.search(body)
    if required is not None:
        return ContractVerdict(
            reason="the code states that this algorithm is required, so it is a constraint the "
            "authors recorded rather than a choice this codebase is free to make",
            signal=f"snippet contains {required.group(0).strip()!r}",
        )

    return None
