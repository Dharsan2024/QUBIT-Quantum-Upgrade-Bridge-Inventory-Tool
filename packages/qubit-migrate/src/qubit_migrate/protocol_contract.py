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
      | (?:requires|mandates|expects|only\s+accepts|must\s+use)[^"']{0,40}(?:md5|sha-?1|des|3des|rc4|rc2|blowfish|cast5|idea)
    )[^"']*["']""",
    re.IGNORECASE | re.VERBOSE,
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
      | must\s+(?:match|agree) | both\s+ends | the\s+far\s+end
      | counterpart(?:y|ies) | third[\s-]party | the\s+(?:partner|provider|acquirer|scheme|issuer)
      | their\s+(?:system|format|software|side) | upstream\s+(?:idp|provider|service)
      | (?:cannot|must\s+not|do\s+not|never)\s+(?:change|be\s+changed|be\s+migrated)
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
      | recomputed\s+(?:per|every|each|on\s+every) | rebuilt | rate[\s-]limit
      | discarded | temporary | transient | thumbnail | draft | this\s+session
      | only\s+(?:this|consumer|reader) | nothing\s+keeps
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def documented_constraint(context: str | None) -> ContractVerdict | None:
    """A constraint the authors wrote down in prose next to the code.

    `context` is the enclosing documentation for the finding -- a docstring, or the comment block
    above the symbol -- NOT the +/-2 line snippet, which by construction cannot contain it.

    Returns a verdict only when the text says the value outlives the code AND does not say it is
    regenerable. Both halves are required: the second is what separates a persisted content address
    from a render cache key written with the same primitive, which is the distinction the twins were
    built to isolate and the one a snippet-level rule cannot make.

    Erring toward a verdict is deliberate and is the same trade the rest of this module makes: a
    false verdict costs an advisory on a finding that could have been auto-migrated, a missed one
    costs a broken repository that every syntactic gate passes.
    """
    if not context:
        return None
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


def enclosing_documentation(source: str, line: int, *, window: int = 40) -> str:
    """The documentation a reader would attach to the code at ``line``.

    The contiguous block of lines above the finding, up to the first double blank line: the
    docstring or comment its author wrote for whoever reads the function next.

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
    for index in range(line - 2, max(-1, line - 2 - window), -1):
        text = lines[index].strip()
        if not text:
            blanks += 1
            # One blank line may sit inside a comment block; two end it.
            if blanks >= 2 and collected:
                break
            continue
        if not _is_comment(text):
            if collected:
                break  # real code above the block: it belongs to whatever came before
            skipped_code += 1
            if skipped_code > _MAX_BODY_SKIP:
                break
            continue
        blanks = 0
        collected.append(text)
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

    required = _ALGORITHM_REQUIRED.search(body)
    if required is not None:
        return ContractVerdict(
            reason="the code states that this algorithm is required, so it is a constraint the "
            "authors recorded rather than a choice this codebase is free to make",
            signal=f"snippet contains {required.group(0).strip()!r}",
        )

    return None
