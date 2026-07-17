# A simplified mock of a vendored OpenSSL cipher string parser for M2.
# In a real implementation, this would use a complete vendored IANA table.
_CIPHER_ALIASES = {
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


def expand_cipher_string(cipher_string: str) -> list[str]:
    """
    Expands an OpenSSL cipher string (e.g., 'HIGH:!aNULL') into a list of IANA cipher suites.
    """
    if not cipher_string:
        return []

    parts = cipher_string.split(":")
    suites = []

    for part in parts:
        if part.startswith("!"):
            exclude = part[1:]
            # Simple exact-match exclusion for now
            suites = [s for s in suites if s != exclude]
        elif part.startswith("-"):
            exclude = part[1:]
            suites = [s for s in suites if s != exclude]
        elif part.startswith("+"):
            # Reorder (move to end)
            include = part[1:]
            if include in _CIPHER_ALIASES:
                for s in _CIPHER_ALIASES[include]:
                    if s in suites:
                        suites.remove(s)
                        suites.append(s)
            elif include in suites:
                suites.remove(include)
                suites.append(include)
        else:
            if part in _CIPHER_ALIASES:
                for s in _CIPHER_ALIASES[part]:
                    if s not in suites:
                        suites.append(s)
            else:
                if part not in suites:
                    suites.append(part)

    return suites
