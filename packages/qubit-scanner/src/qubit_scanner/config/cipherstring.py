# A parser for the OpenSSL cipher-string directive language (HIGH:!aNULL:!MD5, ALL:!EXPORT:!LOW,
# etc.), used by the nginx/apache/openssl config scanners to decide what cipher findings a config
# actually produces.
#
# Deliberately bounded, not a full vendored IANA suite table: this covers the alias/group tokens
# that occur in real configs and common hardening guides (ALL, and the exclusion groups below),
# not every OpenSSL alias that has ever existed. See RESUME.md "BUG 10" for the two measured
# failure modes this closes, and test_cipherstring_real_directives.py for what is pinned.

#: Groups a real `!token` exclusion names, mapped to representative suites carrying that
#: property. Previously exclusion was exact-string-match against `_CIPHER_ALIASES`' suite names
#: only, so `!aNULL`, `!MD5`, `!RC4`, `!EXPORT`, `!LOW`, `!eNULL`, `!3DES`, `!DES` — the vocabulary
#: every real hardening directive actually uses — removed nothing, because no suite is literally
#: NAMED "aNULL". Keys are looked up case-insensitively (real directives write `aNULL`, `!MD5`
#: mixed-case).
_EXCLUSION_GROUPS: dict[str, list[str]] = {
    "ANULL": ["TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"],
    "ENULL": ["TLS_RSA_WITH_NULL_SHA", "TLS_RSA_WITH_NULL_MD5"],
    "EXPORT": ["TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
    "LOW": ["TLS_RSA_WITH_IDEA_CBC_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"],
    "MD5": ["TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"],
    "RC4": [
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    ],
    "3DES": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
    "DES": ["TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
}

_CIPHER_ALIASES: dict[str, list[str]] = {
    "HIGH": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ],
    "DEFAULT": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ],
    "MEDIUM": [
        "TLS_RSA_WITH_AES_128_CBC_SHA",
    ],
}
#: `ALL` -- every suite class above, so `ALL:!aNULL` etc. describes something between "the
#: strong suites" and "every weak class OpenSSL would actually permit," instead of the single
#: fictional suite `['ALL']` this used to produce (see `_UNRECOGNISED_TOKEN_IS_A_SUITE` note
#: below). Not full IANA fidelity -- one or two representative suites per weak class, enough that
#: excluding a class has something real to remove.
_CIPHER_ALIASES["ALL"] = (
    _CIPHER_ALIASES["HIGH"]
    + _EXCLUSION_GROUPS["RC4"]
    + _EXCLUSION_GROUPS["3DES"]
    + _EXCLUSION_GROUPS["DES"]
    + _EXCLUSION_GROUPS["EXPORT"]
    + _EXCLUSION_GROUPS["ANULL"]
    + _EXCLUSION_GROUPS["ENULL"]
)


def expand_cipher_string(cipher_string: str) -> list[str]:
    """
    Expands an OpenSSL cipher string (e.g., 'HIGH:!aNULL') into a list of IANA cipher suites.
    """
    if not cipher_string:
        return []

    parts = cipher_string.split(":")
    suites: list[str] = []

    for part in parts:
        if part.startswith(("!", "-")):
            exclude = part[1:]
            exclude_key = exclude.upper()
            # A real directive excludes a GROUP ("aNULL", "MD5", "EXPORT") far more often than a
            # single literal suite name. Group membership is checked first; falling through to
            # exact-name removal keeps the literal-suite-name form working unchanged.
            if exclude_key in _EXCLUSION_GROUPS:
                drop = set(_EXCLUSION_GROUPS[exclude_key])
            elif exclude_key in _CIPHER_ALIASES:
                drop = set(_CIPHER_ALIASES[exclude_key])
            else:
                drop = {exclude}
            suites = [s for s in suites if s not in drop]
        elif part.startswith("+"):
            # Reorder (move to end)
            include = part[1:]
            include_key = include.upper()
            if include_key in _CIPHER_ALIASES:
                for s in _CIPHER_ALIASES[include_key]:
                    if s in suites:
                        suites.remove(s)
                        suites.append(s)
            elif include in suites:
                suites.remove(include)
                suites.append(include)
        else:
            part_key = part.upper()
            if part_key in _CIPHER_ALIASES:
                for s in _CIPHER_ALIASES[part_key]:
                    if s not in suites:
                        suites.append(s)
            # An unrecognised bare token used to be appended AS IF it were a literal suite name --
            # `expand_cipher_string("ALL:!aNULL")` returned `['ALL']` when "ALL" was not yet in the
            # alias table, describing one FICTIONAL cipher instead of the actually-permissive real
            # set. Only accept it as a literal suite name if it plausibly IS one -- either the
            # IANA `TLS_...` form this table's own entries use, or OpenSSL's own hyphenated
            # short-name form (`AES128-GCM-SHA256`, `DES-CBC3-SHA`, `RC4-MD5`), which real nginx/
            # apache/openssl configs use just as often and which the old code also accepted (a
            # first version of this fix required the `TLS_` form only and silently dropped every
            # OpenSSL-spelled suite in the corpus -- caught by
            # test_weak_openssl_cipher_list_is_not_reported_clean). A bare alias-shaped word with
            # no hyphen and no `TLS_` prefix (`NOTAREALALIAS`, a typo'd group name) is still
            # rejected -- that is precisely the case this guard exists for.
            elif _looks_like_suite_name(part) and part not in suites:
                suites.append(part)

    return suites


def _looks_like_suite_name(token: str) -> bool:
    """True for a token that plausibly names a real cipher suite: the IANA `TLS_...` form, or
    OpenSSL's own hyphenated short-name form. Every real OpenSSL short name is a compound of at
    least two dash-joined components (kx-enc-digest, e.g. `RC4-MD5`), which is what separates it
    from a single bare word like an unrecognised alias or a typo."""
    if token.startswith("TLS_"):
        return True
    return "-" in token and token.replace("-", "").isalnum() and token.isupper()
