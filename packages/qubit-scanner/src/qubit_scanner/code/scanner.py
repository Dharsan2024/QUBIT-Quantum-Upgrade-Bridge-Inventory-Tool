"""``CodeScanner`` — parse a source file, run the shortlisted rules over its AST, and emit raw
``Detection`` values. Pure discovery; normalization into ``CryptoAsset`` happens in ``normalize``.
"""

from __future__ import annotations

import re
from pathlib import Path

from qubit_core import Location
from tree_sitter import Node, QueryCursor
from tree_sitter_language_pack import get_parser

from ..catalog import CompiledRule, RuleCatalog
from ..catalog.schema import Extractor, WhereFilter
from ..models import Detection
from . import resolve
from .languages import language_for, language_from_shebang

# tree-sitter reports ERROR nodes for unparseable regions; above this fraction we skip the file.
_MAX_ERROR_RATIO = 0.20

# Every grammar's spelling of "a reference to a named value", for the `string-constant` fold.
_NAME_NODE_TYPES = frozenset(
    {
        "identifier",  # python, java, go, js/ts, c, c++, rust, csharp, scala, dart, bash
        "variable_name",  # php
        "simple_identifier",  # kotlin, swift
        "constant",  # ruby
        "field_identifier",  # go struct field
        "variable",  # powershell
    }
)

# A shebang is the first line by definition; this only bounds the read on a huge binary blob.
_SHEBANG_PROBE_BYTES = 128


class CodeScanner:
    """Runs a rule catalog against source files of the languages it knows."""

    def __init__(self, catalog: RuleCatalog) -> None:
        self._catalog = catalog

    def scan_file(self, path: Path, *, repo: str | None = None) -> list[Detection]:
        language = language_for(path)
        if language is None and path.suffix == "":
            # Extensionless executables are real and common: a release script named `deploy` that
            # runs `openssl enc -des3` has no suffix and no recognisable name, so a suffix-only
            # lookup skips it entirely. Reading the file to find out costs nothing here — it is
            # about to be read anyway when the language IS known.
            language = self._language_from_shebang(path)
        if language is None or not self._catalog.for_language(language):
            return []
        try:
            source = path.read_bytes()
        except OSError:
            return []
        return self.scan_source(source, language, file_path=str(path), repo=repo)

    @staticmethod
    def _language_from_shebang(path: Path) -> str | None:
        try:
            with path.open("rb") as handle:
                head = handle.read(_SHEBANG_PROBE_BYTES)
        except OSError:
            return None
        return language_from_shebang(head)

    def scan_source(
        self,
        source: bytes,
        language: str,
        *,
        file_path: str = "<memory>",
        repo: str | None = None,
    ) -> list[Detection]:
        rules = self._catalog.for_language(language)
        if not rules:
            return []
        parser = get_parser(language)  # type: ignore[arg-type]
        tree = parser.parse(source)
        root = tree.root_node
        if _error_ratio(root) > _MAX_ERROR_RATIO:
            return []

        imports = resolve.extract_imports(root, language)
        shortlist = [r for r in rules if _import_gate(r, imports)]

        detections: list[Detection] = []
        # Rules declaring `dedupe: per-file` contribute at most one finding per algorithm per file
        # (see Rule.dedupe). Tracked per scan_source call, i.e. per file.
        collapsed: set[tuple[str, str]] = set()
        for cr in shortlist:
            for _, caps in QueryCursor(cr.query).matches(root):
                det = self._match_to_detection(
                    cr, caps, source, root, language, file_path, repo, imports
                )
                if det is None:
                    continue
                if cr.rule.dedupe == "per-file":
                    key = (det.rule_id, det.raw_algorithm)
                    if key in collapsed:
                        continue
                    collapsed.add(key)
                detections.append(det)
        return detections

    def _match_to_detection(
        self,
        cr: CompiledRule,
        caps: dict[str, list[Node]],
        source: bytes,
        root: Node,
        language: str,
        file_path: str,
        repo: str | None,
        imports: set[str] | None = None,
    ) -> Detection | None:
        rule = cr.rule
        if not all(_where_ok(w, caps) for w in rule.match.where):
            return None

        raw_algo = _extract(rule.extract["algorithm"], caps, root)
        if raw_algo is None:
            raw_algo = "UNRESOLVED"
        key_size = None
        if "key_size" in rule.extract:
            ks = _extract(rule.extract["key_size"], caps, root)
            key_size = int(ks) if ks and str(ks).isdigit() else None

        anchor = _anchor_node(caps)
        line = (anchor.start_point.row + 1) if anchor is not None else None
        snippet = _snippet(source, anchor)
        confidence = "low" if raw_algo in ("UNRESOLVED",) else rule.confidence
        context = _extract_context(anchor, imports or set())

        return Detection(
            scanner="code",
            rule_id=rule.id,
            raw_algorithm=str(raw_algo),
            key_size=key_size,
            usage_context=rule.asset.usage_context,
            asset_type=rule.asset.asset_type,
            location=Location(repo=repo, file_path=file_path, line=line),
            library_name=cr.library_name,
            evidence_snippet=snippet,
            evidence_context=context,
            confidence=confidence,
        )


# AST node types for the enclosing scope, per language (doc 01 §4.3 evidence.context).
# The enclosing function is the M2 signal that a +/-2 line snippet lacks: `store_password(user,
# pw)` around a SHA-1 call is what tells a reviewer the digest guards credentials. A grammar
# missing from these sets does not break detection, but it does strip that context from every
# finding in the language, leaving the reviewer with the call and nothing around it.
_FUNC_TYPES = {
    "function_definition",  # python, c, c++, php, scala
    "function_declaration",  # go, js, kotlin, swift, dart, rust(fn via function_item)
    "function_item",  # rust
    "method_declaration",  # java, go, csharp
    "method_definition",  # js, php
    "func_literal",  # go closures
    "arrow_function",  # js/ts
    "local_function_statement",  # csharp
    "constructor_declaration",  # java, csharp
    "method",  # ruby
    "singleton_method",  # ruby
    "function_signature",  # dart
    "function_body",  # dart — the signature is a sibling, so the body is the anchor's ancestor
    "init_declarator",  # c/c++ file-scope initialisers
    "block_function_body",  # kotlin
    "function_statement",  # powershell
    "create_function",  # sql stored procedures
}
_CLASS_TYPES = {
    "class_definition",  # python, kotlin, scala
    "class_declaration",  # java, js/ts, csharp, kotlin, php, dart, swift
    "type_declaration",  # go
    "class_specifier",  # c++
    "struct_specifier",  # c, c++
    "struct_item",  # rust
    "impl_item",  # rust — `impl Signer for X` is the meaningful scope for a crypto method
    "trait_item",  # rust
    "object_definition",  # scala
    "trait_definition",  # scala
    "interface_declaration",  # java, csharp, php, ts
    "protocol_declaration",  # swift
    "enum_declaration",  # java, csharp, swift
    "class",  # ruby
    "module",  # ruby
    "record_declaration",  # java
    "object_declaration",  # kotlin
    "extension_declaration",  # swift
    "mixin_declaration",  # dart
}


def _enclosing(node: Node, types: set[str]) -> Node | None:
    cur = node.parent
    while cur is not None:
        if cur.type in types:
            return cur
        cur = cur.parent
    return None


def _identifiers_under(node: Node, limit: int) -> list[str]:
    """Iteratively collect identifier texts beneath a node (bounded, no recursion)."""
    out: list[str] = []
    stack = [node]
    while stack and len(out) < limit:
        n = stack.pop()
        if n.type in ("identifier", "field_identifier", "type_identifier"):
            txt = resolve.node_text(n)
            if txt:
                out.append(txt)
        stack.extend(n.children)
    return out


def _extract_context(anchor: Node | None, imports: set[str]) -> dict:
    """Capture the enclosing function/class + data-flow identifiers around a crypto finding.

    This is the M2 signal that ±5-line snippets lack on real code: the sensitivity of the data
    handled by a crypto call lives in the enclosing function name, its parameters, and the class —
    e.g. ``def store_password(user, pw): ... sha1(pw)``.
    """
    ctx: dict = {
        "symbols": {"defined": [], "used": []},
        "imports": sorted(imports)[:20],
        "extra": {},
    }
    if anchor is None:
        return ctx
    defined: list[str] = []
    fn = _enclosing(anchor, _FUNC_TYPES)
    if fn is not None:
        name_node = fn.child_by_field_name("name")
        fname = resolve.node_text(name_node) if name_node is not None else None
        if fname:
            defined.append(fname)
            ctx["extra"]["enclosing_function"] = fname
        params = fn.child_by_field_name("parameters")
        if params is not None:
            defined.extend(_identifiers_under(params, 12))
    cls = _enclosing(anchor, _CLASS_TYPES)
    if cls is not None:
        cname_node = cls.child_by_field_name("name")
        cname = resolve.node_text(cname_node) if cname_node is not None else None
        if cname:
            defined.append(cname)
            ctx["extra"]["enclosing_class"] = cname
    ctx["symbols"]["defined"] = sorted(set(defined))
    ctx["symbols"]["used"] = sorted(set(_identifiers_under(anchor, 30)))
    return ctx


def _import_gate(cr: CompiledRule, imports: set[str]) -> bool:
    if not cr.detect_imports:
        return True
    return any(mod in imports for mod in cr.detect_imports)


def _where_ok(w: WhereFilter, caps: dict[str, list[Node]]) -> bool:
    nodes = caps.get(w.capture)
    if not nodes:
        return False
    text = resolve.node_text(nodes[0])
    if w.equals is not None and text != w.equals:
        return False
    if w.in_ is not None and text not in w.in_:
        return False
    return w.regex is None or re.search(w.regex, text) is not None


def _extract(ex: Extractor, caps: dict[str, list[Node]], root: Node) -> str | None:
    if ex.literal is not None:
        return ex.literal
    if ex.from_ is None:
        return None
    nodes = caps.get(ex.from_)
    if not nodes:
        return None
    node = nodes[0]
    match ex.resolve:
        case "capture-text":
            return resolve.node_text(node)
        case "string-literal":
            return resolve.string_literal_value(node)
        case "string-constant":
            val = resolve.string_literal_value(node)
            if val is not None:
                return val
            # Only "identifier" was folded, which is Python/Java/Go/JS's spelling. PHP names a
            # variable `variable_name`, Kotlin and Swift use `simple_identifier`, Ruby uses
            # `constant` for a folded constant — so `$algo = "md5"; hash($algo, ...)` resolved in
            # some languages and silently gave up in others.
            if node.type in _NAME_NODE_TYPES:
                return resolve.resolve_string_constant(resolve.node_text(node), root)
            return None
        case "int-literal":
            iv = resolve.int_literal_value(node)
            return str(iv) if iv is not None else None
        case "openssl-evp":
            # OpenSSL names its algorithm getters `EVP_<alg>` — EVP_sha1, EVP_aes_128_cbc,
            # EVP_des_ede3_cbc, EVP_chacha20_poly1305. Stripping the prefix hands the rest to the
            # canonical registry, whose separator normalization and cipher-mode stripping already
            # understand `aes_128_cbc` and `des_ede3_cbc`. One data-driven resolver therefore covers
            # every EVP cipher and digest instead of needing a rule per algorithm.
            text = resolve.node_text(node)
            return text[4:] if text.lower().startswith("evp_") else text
        case "openssl-pkey":
            # `EVP_PKEY_RSA` -> "RSA", `EVP_PKEY_ED25519` -> "ED25519".
            text = resolve.node_text(node)
            return text[9:] if text.upper().startswith("EVP_PKEY_") else text
        case "openssl-tls-method":
            # `TLSv1_1_client_method` -> "TLSv1.1"; `SSLv3_method` -> "SSLv3". The version is the
            # leading token; OpenSSL spells the minor version with an underscore.
            return _openssl_tls_version(resolve.node_text(node))
        case "openssl-legacy-fn":
            # `DES_ede3_cbc_encrypt` -> "des-ede3", `MD5_Init` -> "MD5", `RC4_set_key` -> "RC4".
            return _openssl_legacy_algorithm(resolve.node_text(node))
        case "pyca-pqc-class":
            # `MLKEM768PrivateKey` -> "ML-KEM-768", `MLDSA65PrivateKey` -> "ML-DSA-65".
            return _pyca_pqc_algorithm(resolve.node_text(node))
        case "go-tls-version":
            # `VersionTLS10` -> "TLSv1.0", `VersionSSL30` -> "SSLv3".
            return _GO_TLS_VERSIONS.get(resolve.node_text(node), resolve.node_text(node))
        case "go-ecdh-curve":
            # crypto/ecdh's `P256()` is an ECDH curve, so it must not resolve to ECDSA-P256.
            return _GO_ECDH_CURVES.get(resolve.node_text(node), resolve.node_text(node))
        case "go-mlkem-fn":
            # `GenerateKey768` -> "ML-KEM-768", `GenerateKey1024` -> "ML-KEM-1024".
            text = resolve.node_text(node)
            return "ML-KEM-1024" if "1024" in text else "ML-KEM-768"
        case "jca-signature":
            # `"SHA256withRSA"` -> "RSA": report the KEY algorithm, which is the Shor-relevant half.
            # The digest half is inventoried separately by the MessageDigest rules.
            value = resolve.string_literal_value(node) or resolve.node_text(node)
            lowered = value.lower()
            for sep in ("withencryption", "with"):
                if sep in lowered:
                    return value[lowered.rindex(sep) + len(sep) :] or value
            return value
        case "jca-transformation":
            # `"AES/GCM/NoPadding"` -> "AES": the mode and padding are not quantum-relevant.
            value = resolve.string_literal_value(node) or resolve.node_text(node)
            return value.split("/", 1)[0]
        case "go-key-package":
            # `rsa.PrivateKey` -> "RSA", `ed25519.PublicKey` -> "Ed25519". The Go package name is
            # lowercase; the registry is case-insensitive but "ed25519" must not be left to match
            # a curve alias by accident, so the mapping is explicit.
            return _GO_KEY_PACKAGES.get(resolve.node_text(node), resolve.node_text(node))
        case "noble-pqc-name":
            # @noble/post-quantum spells them `ml_kem768`, `ml_dsa65`, `slh_dsa_sha2_128f`.
            return _pqc_identifier_algorithm(resolve.node_text(node))
        case "liboqs-alg-const":
            # liboqs spells them `OQS_KEM_alg_ml_kem_768`, `OQS_SIG_alg_ml_dsa_65`.
            return _pqc_identifier_algorithm(resolve.node_text(node))
        case "dotnet-crypto-class":
            # `TripleDESCryptoServiceProvider` -> "3DES", `RijndaelManaged` -> AES,
            # `Rfc2898DeriveBytes` -> PBKDF2. .NET spells one algorithm several ways.
            return _dotnet_crypto_algorithm(resolve.node_text(node))
        case "jwa-identifier":
            # `jose.RS256`, `SignatureAlgorithm("RS256")`, `ECDH_ES` — a JOSE codebase names its
            # algorithms as identifiers and strings, not as calls into a crypto package.
            return _jwa_algorithm(resolve.node_text(node))
        case "powershell-type-literal":
            # A PowerShell script names .NET classes by their full type path, inside a type
            # literal or after New-Object: `[System.Security.Cryptography.MD5]::Create()`. Pull
            # the class name out of the path, then read it as the .NET class it is.
            return _powershell_type_algorithm(resolve.node_text(node))
        case "powershell-security-protocol":
            # `SecurityProtocol = "Tls"` / `= [Net.SecurityProtocolType]::Ssl3`.
            return _powershell_security_protocol(resolve.node_text(node))
        case "dotnet-tls-protocol":
            # `SecurityProtocolType.Tls` -> "TLSv1.0" (the bare `Tls` member IS TLS 1.0),
            # `SslProtocols.Ssl3` -> "SSLv3".
            return _DOTNET_TLS_PROTOCOLS.get(resolve.node_text(node), resolve.node_text(node))
        case "security-key-type":
            # Apple's Security framework: `kSecAttrKeyTypeRSA` -> "RSA",
            # `kSecAttrKeyTypeECSECPrimeRandom` -> "EC" (its name for a NIST prime curve).
            return _security_key_type(resolve.node_text(node))
        case "swift-tls-version":
            # `.TLSv10` -> "TLSv1.0"; `.tlsProtocol12` and `.TLSv12` both appear in real code.
            return _swift_tls_version(resolve.node_text(node))
        case "commoncrypto-alg":
            # Apple CommonCrypto: `kCCAlgorithm3DES` -> "3DES", `CC_MD5` -> "MD5".
            return _commoncrypto_algorithm(resolve.node_text(node))
        case "hmac-of-digest":
            # `hash_hmac("sha1", ...)` names the DIGEST, but the algorithm in use is HMAC-SHA1.
            # The distinction matters for the verdict: SHA-1 alone is Grover-flagged, while
            # HMAC-SHA1 is a separate registry identity with its own properties. Reporting the
            # bare digest would answer a question nobody asked.
            digest = resolve.string_literal_value(node) or resolve.node_text(node)
            return f"HMAC-{digest}" if digest else None
        case "rust-ssl-version":
            # rust-openssl spells them `SslVersion::TLS1` / `TLS1_1`; bare TLS1 is TLS 1.0.
            return _RUST_SSL_VERSIONS.get(resolve.node_text(node), resolve.node_text(node))
        case "ring-digest":
            # ring names SHA-1 `SHA1_FOR_LEGACY_USE_ONLY` — a deliberate warning in the API that
            # is also, conveniently, an unambiguous marker of exactly what needs migrating.
            text = resolve.node_text(node)
            return "SHA-1" if text.startswith("SHA1") else text
        case "cryptopp-name":
            # Crypto++ spells 3DES `DES_EDE3` and AES `Rijndael`, and keeps the broken digests in
            # a `Weak::` namespace whose name says nothing about which algorithm it is.
            return _CRYPTOPP_NAMES.get(resolve.node_text(node), resolve.node_text(node))
        case "qt-ssl-protocol":
            # `QSsl::TlsV1_0` -> "TLSv1.0"; `QSsl::SslV3` -> "SSLv3".
            return _qt_ssl_protocol(resolve.node_text(node))
        case "sql-digest-name":
            # Every dialect spells digests differently: MySQL's `SHA()` IS SHA-1, SQL Server
            # writes `SHA2_256`, and the same rule sees both a function name and a string
            # argument. One resolver so a schema does not inventory as UNKNOWN(SHA2_256).
            text = resolve.string_literal_value(node) or resolve.node_text(node)
            return _sql_digest_name(text)
        case "sql-sha2-length":
            # `SHA2(x, 256)` -> "SHA-256". MySQL accepts 224/256/384/512, and 0 meaning 256.
            length = resolve.string_literal_value(node) or resolve.node_text(node)
            return _sql_sha2_length(length)
        case "sodium-primitive":
            # libsodium names an operation, not an algorithm: `crypto_secretbox` IS
            # XSalsa20-Poly1305 and `crypto_sign` IS Ed25519. Nothing in the call text says so,
            # which is the whole point of the API — and the reason a sodium-based service used to
            # inventory as having no cryptography at all.
            return _sodium_primitive(resolve.node_text(node))
        case "php-crypto-const":
            # `OPENSSL_ALGO_SHA1` -> "SHA-1", `MCRYPT_3DES` -> "3DES",
            # `PASSWORD_BCRYPT` -> "bcrypt".
            return _php_crypto_constant(resolve.node_text(node))
        case "rust-crypto-type":
            # RustCrypto type names: `TdesEde3` -> "3DES", `Aes128Cbc` -> "AES-128".
            return _rust_crypto_type(resolve.node_text(node))
        case "shell-algorithm":
            # The whole command line, parsed as argv: `openssl enc -des3 ...` -> "3DES",
            # `ssh-keygen -t rsa -b 1024` -> "RSA", `Get-FileHash -Algorithm MD5` -> "MD5".
            return _shell_algorithm(resolve.node_text(node))
        case "shell-key-bits":
            bits = _shell_key_bits(resolve.node_text(node))
            return str(bits) if bits is not None else None
        case "pqc-identifier":
            # Any library's spelling of a PQC parameter set: `MLKem768`, `MlKem768`, `ml_kem_768`.
            return _pqc_identifier_algorithm(resolve.node_text(node))
        case "cryptojs-name":
            # crypto-js spells algorithms `TripleDES`, `HmacSHA256`, `RIPEMD160` — names the
            # registry lacks as aliases. Normalize the library-specific spellings only.
            return _CRYPTOJS_NAMES.get(resolve.node_text(node), resolve.node_text(node))
        case _:
            return resolve.node_text(node)


def _pqc_identifier_algorithm(name: str) -> str:
    """Normalize a PQC algorithm identifier from any library's spelling to the canonical name.

    Covers @noble/post-quantum (`ml_kem768`, `ml_dsa65`, `slh_dsa_sha2_128f`) and liboqs
    (`OQS_KEM_alg_ml_kem_768`, `OQS_SIG_alg_ml_dsa_65`), plus the pre-standardization names those
    libraries still ship (`kyber768`, `dilithium3`) which the registry already aliases.

    This exists because PQC APIs were detected in Go, Java and Python but NOT in JavaScript,
    TypeScript or C — so a JS service that had already migrated to ML-KEM showed zero post-quantum
    adoption, and the migration validator's stage-5 rescan could never confirm a JS/TS/C patch had
    landed on ML-KEM at all. Its `present: ML-KEM` expectation would fail on a perfectly correct
    rewrite, exactly the same way an unrecognised `sntrup761x25519-sha512` made a hardened
    sshd_config look unremediated.

    A recognised family with no parameter digits degrades to the bare family name (`ML-KEM`), which
    the registry resolves as quantum-safe — honest, since the family alone is enough to say that.
    """
    lowered = name.lower()
    digits = "".join(c for c in lowered if c.isdigit())
    # Every separator spelling in one place. liboqs' own bindings pass the HYPHENATED canonical
    # name
    # ("ML-KEM-768"), the C constants use underscores (`OQS_KEM_alg_ml_kem_768`) and @noble
    # runs them together (`ml_kem768`). Testing only the underscore form sent `ML-KEM-768` to
    # the fallback.
    squashed = lowered.replace("-", "_")

    if "ml_kem" in squashed or "mlkem" in squashed or "kyber" in squashed:
        return f"ML-KEM-{digits}" if digits in {"512", "768", "1024"} else "ML-KEM"
    if "ml_dsa" in squashed or "mldsa" in squashed or "dilithium" in squashed:
        return f"ML-DSA-{digits}" if digits in {"44", "65", "87"} else "ML-DSA"
    if "slh_dsa" in squashed or "slhdsa" in squashed or "sphincs" in squashed:
        # SLH-DSA parameter sets carry a hash and a size (`sha2_128f`); the registry tracks the
        # family, so the parameter set stays in the evidence rather than the algorithm identity.
        return "SLH-DSA"
    # Not a recognised PQC identifier. In real liboqs code the argument is often a VARIABLE —
    # `OQS_SIG_new(oqs_name)` — and returning its name produced findings labelled
    # `UNKNOWN(oqs_name)`, which reports the scanner's own local variable as an algorithm.
    # Measured on open-quantum-safe/oqs-provider. The algorithm is selected at runtime, which is
    # what RUNTIME-SELECTED means, and the identifier is deliberately excluded from that judgement
    # only when it plainly is not an algorithm name.
    # liboqs spells its constants `OQS_KEM_alg_...` / `OQS_SIG_alg_...`, so `_alg_` is what
    # separates a real algorithm constant from a local variable holding one. Keeping the raw name
    # for the former leaves an unmapped liboqs algorithm visible; a bare `oqs_name` is not an
    # algorithm at all.
    if "_alg_" in squashed:
        return name
    return "UNRESOLVED"


def _openssl_tls_version(fn_name: str) -> str:
    """Map an OpenSSL version-specific method name to a canonical protocol version."""
    head = fn_name.split("_method")[0]
    parts = head.split("_")  # ["TLSv1", "1", "client"] / ["SSLv3"] / ["TLSv1", "client"]
    version = parts[0]
    if len(parts) > 1 and parts[1].isdigit():
        version = f"{version}.{parts[1]}"
    elif version.lower().startswith("tlsv1"):
        version = "TLSv1.0"  # bare TLSv1_method is TLS 1.0
    return version


# Legacy one-shot OpenSSL entry points -> the algorithm they implement. `DES_ede3_*` must be checked
# before the plain `DES_` prefix, otherwise 3DES would be misreported as single DES.
_OPENSSL_LEGACY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("des_ede3", "des-ede3"),
    ("des_", "DES"),
    ("rc4", "RC4"),
    ("rc2", "RC2"),
    ("md5_", "MD5"),
    ("md4_", "MD4"),
    ("sha1_", "SHA-1"),
)


def _openssl_legacy_algorithm(fn_name: str) -> str:
    lowered = fn_name.lower()
    for prefix, algorithm in _OPENSSL_LEGACY_PREFIXES:
        if lowered.startswith(prefix):
            return algorithm
    return fn_name


# Go's crypto/tls version constants -> canonical protocol names.
_GO_TLS_VERSIONS: dict[str, str] = {
    "VersionSSL30": "SSLv3",
    "VersionTLS10": "TLSv1.0",
    "VersionTLS11": "TLSv1.1",
    "VersionTLS12": "TLSv1.2",
    "VersionTLS13": "TLSv1.3",
}

# crypto/ecdh curve constructors. Distinct from crypto/elliptic's identically-named P256(), which is
# an ECDSA curve — mapping these to ECDSA-* would mislabel a key agreement as a signature algorithm.
_GO_ECDH_CURVES: dict[str, str] = {
    "P256": "ECDH-P256",
    "P384": "ECDH-P384",
    "P521": "ECDH-P521",
    "X25519": "X25519",
}

# crypto-js's library-specific spellings -> canonical registry names. Only names the registry
# cannot already resolve are listed (MD5/SHA256/AES resolve directly and are absent on purpose).
_CRYPTOJS_NAMES: dict[str, str] = {
    "TripleDES": "3DES",
    "RIPEMD160": "RIPEMD-160",
    "HmacMD5": "HMAC",
    "HmacSHA1": "HMAC",
    "HmacSHA256": "HMAC",
    "SHA3": "SHA3-256",
    # crypto-js's Rabbit stream cipher has no NIST/registry identity; report it verbatim so it
    # surfaces as UNKNOWN(Rabbit) rather than being silently mapped onto an unrelated algorithm.
    "Rabbit": "Rabbit",
    "RabbitLegacy": "Rabbit",
}

# Go crypto package name -> canonical algorithm family, for key-material type references.
_GO_KEY_PACKAGES: dict[str, str] = {
    "rsa": "RSA",
    "ecdsa": "ECDSA",
    "ed25519": "Ed25519",
    "dsa": "DSA",
}

_PYCA_PQC_RE = re.compile(r"^(ML(?:KEM|DSA))(\d+)", re.IGNORECASE)


def _pyca_pqc_algorithm(class_name: str) -> str:
    """`MLKEM768PrivateKey` -> "ML-KEM-768"; `MLDSA65PublicKey` -> "ML-DSA-65".

    pyca/cryptography (>=48) spells its PQC classes without separators, which would not match the
    canonical registry's hyphenated names.
    """
    m = _PYCA_PQC_RE.match(class_name)
    if m is None:
        return class_name
    family = "ML-KEM" if m.group(1).upper() == "MLKEM" else "ML-DSA"
    return f"{family}-{m.group(2)}"


# ── .NET ────────────────────────────────────────────────────────────────────────────────────────

# Suffixes .NET attaches to the same algorithm depending on the implementation backing it.
# `MD5`, `MD5CryptoServiceProvider` and `MD5Cng` are one algorithm with three class names.
_DOTNET_IMPL_SUFFIXES = ("CryptoServiceProvider", "Managed", "Cng", "OpenSsl", "Implementation")

# Class-name stems that are not the algorithm's registry spelling.
_DOTNET_CLASS_ALIASES: dict[str, str] = {
    "TripleDES": "3DES",
    # "Rijndael" is deliberately absent: the canonical registry aliases it onto bare AES, so
    # letting the stem through keeps one answer instead of two that could drift apart.
    "ECDsa": "ECDSA",
    "ECDiffieHellman": "ECDH",
    "Rfc2898DeriveBytes": "PBKDF2",  # the class name never says PBKDF2; the RFC number does
    "PasswordDeriveBytes": "PBKDF1",
    "RNGCryptoServiceProvider": "CSPRNG",
    # AEAD modes of AES. .NET gives each its own class; the registry knows the mode-qualified name,
    # which is what a rule's `present: AES` expectation is satisfied by either way.
    "AesGcm": "AES-GCM",
    "AesCcm": "AES-CCM",
    "DES": "DES",
    "RC2": "RC2",
}


def _dotnet_crypto_algorithm(class_name: str) -> str:
    """`TripleDESCryptoServiceProvider` -> "3DES"; `SHA1Managed` -> "SHA1"; `RSACng` -> "RSA"."""
    stem = class_name
    for suffix in _DOTNET_IMPL_SUFFIXES:
        if stem.endswith(suffix) and len(stem) > len(suffix):
            stem = stem[: -len(suffix)]
            break
    return _DOTNET_CLASS_ALIASES.get(stem, stem)


# SecurityProtocolType / SslProtocols members. The bare `Tls` member is TLS 1.0 — a fact worth
# spelling out, because `SecurityProtocol = SecurityProtocolType.Tls` reads like "use TLS" while
# actually pinning the one version every modern profile forbids.
_DOTNET_TLS_PROTOCOLS: dict[str, str] = {
    "Tls": "TLSv1.0",
    "Tls11": "TLSv1.1",
    "Tls12": "TLSv1.2",
    "Tls13": "TLSv1.3",
    "Ssl2": "SSLv2",
    "Ssl3": "SSLv3",
    "Default": "TLSv1.0",  # SecurityProtocolType.Default is SSL3 | TLS1.0
}


# .NET class names a PowerShell script can name, longest first so `MD5CryptoServiceProvider` is
# preferred over the bare `MD5` substring it contains -- and so `SHA1` never wins inside `SHA1...`
# variants or `HMACSHA1` inside `HMACSHA1`.
#
# The strong classes are here for the same reason the PQC rules exist: a migration is confirmed by
# DETECTING its target, so a language that can be scanned for 3DES but not for AES can never be
# shown to have been migrated. Measured on `Provision.ps1`, whose 3DES -> AES-GCM rewrite was
# refused with "Expected one of ['AES'] present, but not found".
_POWERSHELL_TYPE_NAMES: tuple[str, ...] = (
    "TripleDESCryptoServiceProvider",
    "RSACryptoServiceProvider",
    "AesCryptoServiceProvider",
    "DESCryptoServiceProvider",
    "MD5CryptoServiceProvider",
    "SHA1CryptoServiceProvider",
    "SHA256CryptoServiceProvider",
    "RC2CryptoServiceProvider",
    "Rfc2898DeriveBytes",
    "ChaCha20Poly1305",
    "RijndaelManaged",
    "SHA256Managed",
    "SHA1Managed",
    "AesManaged",
    "HMACSHA256",
    "HMACSHA384",
    "HMACSHA512",
    "HMACSHA1",
    "HMACMD5",
    "TripleDES",
    "AesGcm",
    "AesCcm",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA1",
    "Aes",
    "MD5",
    "MD4",
)


# JWA identifiers as a Go or Java CONSTANT spells them, mapped to the spelling the algorithm
# registry uses. The wire format is hyphenated ("RSA-OAEP"), while an identifier cannot contain a
# hyphen, so every library writes the same algorithm two ways. Only the ones that actually differ
# are listed; `RS256` and `ES256` are identical in both forms, and `RSA1_5` really is spelled with
# an underscore in RFC 7518 §4.1.
# https://www.iana.org/assignments/jose/jose.xhtml — RFC 7518 §3.1, §4.1, §5.1
_JWA_CONSTANT_ALIASES: dict[str, str] = {
    "RSA_OAEP": "RSA-OAEP",
    "RSA_OAEP_256": "RSA-OAEP-256",
    "ECDH_ES": "ECDH-ES",
    "ECDH_ES_A128KW": "ECDH-ES+A128KW",
    "ECDH_ES_A192KW": "ECDH-ES+A192KW",
    "ECDH_ES_A256KW": "ECDH-ES+A256KW",
    "A128CBC_HS256": "A128CBC-HS256",
    "A192CBC_HS384": "A192CBC-HS384",
    "A256CBC_HS512": "A256CBC-HS512",
    "PBES2_HS256_A128KW": "PBES2-HS256+A128KW",
    "PBES2_HS384_A192KW": "PBES2-HS384+A192KW",
    "PBES2_HS512_A256KW": "PBES2-HS512+A256KW",
}


def _jwa_algorithm(text: str) -> str | None:
    """A JWA identifier in either spelling, normalised to the registry's.

    `jose.RS256` and `KeyAlgorithm("RSA-OAEP")` name the same kind of thing, and both are how a
    JOSE codebase actually selects an algorithm. Returning the identifier is enough: the registry
    resolves RS256 to a Shor-vulnerable RSA signature and A256GCM to AES-256 on its own.
    """
    token = text.strip().strip("\"'")
    if not token:
        return None
    # A selector like `jose.RS256` arrives whole when the query captures the expression.
    token = token.rsplit(".", 1)[-1]
    return _JWA_CONSTANT_ALIASES.get(token, token)


def _powershell_type_algorithm(text: str) -> str | None:
    for name in _POWERSHELL_TYPE_NAMES:
        if name.lower() in text.lower():
            # Recover the source spelling so the .NET suffix stripper sees the real class name.
            start = text.lower().index(name.lower())
            return _dotnet_crypto_algorithm(text[start : start + len(name)])
    return None


def _powershell_security_protocol(text: str) -> str | None:
    """The protocol version a `SecurityProtocol = ...` assignment selects.

    Checked most-specific first: a bare `Tls` is TLS 1.0, but `Tls12` also contains "Tls", so
    testing in declaration order would report every modern setting as the broken one.
    """
    lowered = text.lower()
    for token, version in (
        ("tls13", "TLSv1.3"),
        ("tls12", "TLSv1.2"),
        ("tls11", "TLSv1.1"),
        ("ssl3", "SSLv3"),
        ("ssl2", "SSLv2"),
        ("tls", "TLSv1.0"),
    ):
        if token in lowered:
            return version
    return None


# ── Apple CommonCrypto ──────────────────────────────────────────────────────────────────────────


def _commoncrypto_algorithm(name: str) -> str:
    """`kCCAlgorithm3DES` -> "3DES"; `CC_MD5` -> "MD5"; `kCCAlgorithmAES128` -> "AES128"."""
    for prefix in ("kCCAlgorithm", "kCCHmacAlg", "CC_"):
        if name.startswith(prefix):
            stem = name[len(prefix) :]
            # CommonCrypto spells CAST-128 as plain `CAST`; the registry knows it as CAST5.
            return {"CAST": "CAST5", "TripleDES": "3DES"}.get(stem, stem)
    return name


# ── Apple Security framework / Swift ────────────────────────────────────────────────────────────

_SECURITY_KEY_TYPES: dict[str, str] = {
    "kSecAttrKeyTypeRSA": "RSA",
    "kSecAttrKeyTypeDSA": "DSA",
    "kSecAttrKeyTypeEC": "EC",
    # Apple's name for a NIST prime curve key; the curve itself comes from the key size attribute.
    "kSecAttrKeyTypeECSECPrimeRandom": "EC",
    "kSecAttrKeyTypeAES": "AES",
    "kSecAttrKeyTypeDES": "DES",
    "kSecAttrKeyType3DES": "3DES",
    "kSecAttrKeyTypeRC4": "RC4",
    "kSecAttrKeyTypeRC2": "RC2",
}


def _security_key_type(name: str) -> str:
    return _SECURITY_KEY_TYPES.get(name, name)


def _swift_tls_version(name: str) -> str:
    """`.TLSv10` / `.tlsProtocol10` -> "TLSv1.0"; `.sslv3` -> "SSLv3"."""
    stem = name.lstrip(".").lower()
    for prefix, label in (("tlsprotocol", "TLSv"), ("tlsv", "TLSv"), ("sslv", "SSLv")):
        if stem.startswith(prefix):
            digits = stem[len(prefix) :]
            if label == "SSLv":
                return f"SSLv{digits}"
            # `TLSv10` is major 1, minor 0; `TLSv1` on its own is TLS 1.0.
            if len(digits) >= 2:
                return f"TLSv{digits[0]}.{digits[1]}"
            return f"TLSv{digits}.0"
    return name


# ── PHP ─────────────────────────────────────────────────────────────────────────────────────────

# PHP's password_hash() algorithm constants. PASSWORD_DEFAULT is bcrypt as of PHP 8.x; naming it
# bcrypt rather than leaving it unresolved is the honest reading, and both are quantum-safe.
_PHP_PASSWORD_CONSTANTS: dict[str, str] = {
    "PASSWORD_BCRYPT": "bcrypt",
    "PASSWORD_DEFAULT": "bcrypt",
    "PASSWORD_ARGON2I": "argon2i",
    "PASSWORD_ARGON2ID": "argon2id",
}


# libsodium operation prefix -> the primitive it is defined as. Longest prefix first, because
# `crypto_aead_xchacha20poly1305` also starts with `crypto_aead`.
_SODIUM_PRIMITIVES: tuple[tuple[str, str], ...] = (
    ("crypto_aead_xchacha20poly1305", "XChaCha20"),
    ("crypto_aead_chacha20poly1305", "ChaCha20"),
    ("crypto_aead_aes256gcm", "AES-256"),
    ("crypto_secretstream_xchacha20poly1305", "XChaCha20"),
    ("crypto_secretbox", "XSalsa20"),  # XSalsa20-Poly1305
    ("crypto_stream_xchacha20", "XChaCha20"),
    ("crypto_stream", "XSalsa20"),
    ("crypto_sign", "Ed25519"),
    ("crypto_box", "X25519"),  # X25519 key agreement + XSalsa20-Poly1305
    ("crypto_kx", "X25519"),
    ("crypto_scalarmult", "X25519"),
    # crypto_auth is HMAC-SHA-512-256. It reports as bare HMAC rather than a sized name because
    # the registry aliases "HMAC-SHA512" onto the JOSE algorithm HS512, and labelling a libsodium
    # call with a JWS algorithm identifier in a CBOM would be wrong. The digest stays in evidence.
    ("crypto_auth", "HMAC"),
    ("crypto_generichash", "BLAKE2b"),
    ("crypto_pwhash_scryptsalsa208sha256", "scrypt"),
    ("crypto_pwhash", "argon2id"),
    ("crypto_shorthash", "SipHash"),
)


def _sodium_primitive(fn_name: str) -> str:
    lowered = fn_name.lower()
    if lowered.startswith("sodium_"):
        lowered = lowered[len("sodium_") :]
    for prefix, algorithm in _SODIUM_PRIMITIVES:
        if lowered.startswith(prefix):
            return algorithm
    return fn_name


def _php_crypto_constant(name: str) -> str:
    """`OPENSSL_ALGO_SHA1` -> "SHA1"; `MCRYPT_3DES` -> "3DES"; `md5_file` -> "md5"."""
    if name in _PHP_PASSWORD_CONSTANTS:
        return _PHP_PASSWORD_CONSTANTS[name]
    # PHP ships a `_file` twin of every digest function (`md5_file`, `sha1_file`). They are the
    # same algorithm applied to a path, and hashing a file with MD5 is exactly the integrity
    # check most worth inventorying.
    if name.endswith("_file"):
        return name[: -len("_file")]
    for prefix in ("OPENSSL_ALGO_", "OPENSSL_CIPHER_", "MCRYPT_", "OPENSSL_KEYTYPE_"):
        if name.startswith(prefix):
            stem = name[len(prefix) :]
            return {"TRIPLEDES": "3DES", "RIJNDAEL_128": "AES-128", "ARCFOUR": "RC4"}.get(
                stem, stem
            )
    return name


# ── RustCrypto ──────────────────────────────────────────────────────────────────────────────────

# RustCrypto type names that are not the algorithm's registry spelling. The cipher crates encode
# the mode in the type (`Aes128Cbc`, `DesEcb`), which the registry's mode-stripping does not know
# how to read because there is no separator to strip.
_RUST_TYPE_ALIASES: dict[str, str] = {
    "TdesEde3": "3DES",
    "TdesEde2": "3DES",
    "TdesEee3": "3DES",
    "DesX": "DES",
    "RsaPrivateKey": "RSA",
    "RsaPublicKey": "RSA",
    "SigningKey": "UNRESOLVED",  # ed25519_dalek/ecdsa both use it; the crate decides, not the type
}

# Cipher-mode suffixes RustCrypto appends to a cipher type name.
_RUST_MODE_SUFFIXES = ("Cbc", "Ecb", "Ctr", "Gcm", "Ofb", "Cfb", "Xts", "Ccm", "Siv")


def _rust_crypto_type(type_name: str) -> str:
    if type_name in _RUST_TYPE_ALIASES:
        return _RUST_TYPE_ALIASES[type_name]
    stem = type_name
    for suffix in _RUST_MODE_SUFFIXES:
        if stem.endswith(suffix) and len(stem) > len(suffix):
            stem = stem[: -len(suffix)]
            break
    return _RUST_TYPE_ALIASES.get(stem, stem)


# rust-openssl protocol constants. `SslVersion::TLS1` is TLS 1.0, not "TLS".
_RUST_SSL_VERSIONS: dict[str, str] = {
    "SSL3": "SSLv3",
    "TLS1": "TLSv1.0",
    "TLS1_1": "TLSv1.1",
    "TLS1_2": "TLSv1.2",
    "TLS1_3": "TLSv1.3",
}


# ── C++ ─────────────────────────────────────────────────────────────────────────────────────────

# Crypto++ class names that are not the algorithm's registry spelling.
_CRYPTOPP_NAMES: dict[str, str] = {
    "DES_EDE3": "3DES",
    "DES_EDE2": "3DES",
    "ARC4": "RC4",
    "CAST128": "CAST5",
    "Rijndael": "AES",
    "ElGamal": "ElGamal",
}


def _qt_ssl_protocol(name: str) -> str:
    """`TlsV1_0` -> "TLSv1.0"; `SslV3` -> "SSLv3"; `TlsV1_2OrLater` -> "TLSv1.2"."""
    stem = name.split("OrLater")[0]
    if stem.startswith("SslV"):
        return f"SSLv{stem[len('SslV') :]}"
    if stem.startswith("TlsV"):
        return "TLSv" + stem[len("TlsV") :].replace("_", ".")
    return name


# ── SQL ─────────────────────────────────────────────────────────────────────────────────────────

# Dialect-specific digest spellings. MySQL's `SHA()` is documented as a synonym for `SHA1()`, and
# SQL Server's HASHBYTES takes `SHA2_256`/`SHA2_512` where every other dialect writes SHA-256.
_SQL_DIGEST_NAMES: dict[str, str] = {
    "md2": "MD2",
    "md4": "MD4",
    "md5": "MD5",
    "sha": "SHA-1",
    "sha1": "SHA-1",
    "sha2_256": "SHA-256",
    "sha2_512": "SHA-512",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "crc32": "CRC32",
}


def _sql_digest_name(text: str) -> str:
    return _SQL_DIGEST_NAMES.get(text.strip().strip("'" + chr(34)).lower(), text)


def _sql_sha2_length(text: str) -> str:
    digits = "".join(c for c in text if c.isdigit())
    # MySQL documents 0 as equivalent to 256.
    if digits in ("", "0"):
        return "SHA-256"
    return f"SHA-{digits}" if digits in ("224", "256", "384", "512") else text


# ── Shell and PowerShell command lines ──────────────────────────────────────────────────────────
#
# Shell scripts are the fifth most-used language in the Stack Overflow 2025 survey (48.7%), and
# the crypto in them is not an API call — it is an argv token. `openssl enc -des3` and
# `ssh-keygen -t rsa -b 1024` carry the whole decision in flags, so these rules capture the entire
# command node and read it as argv rather than trying to express argument position in a
# tree-sitter query. Positional queries were the alternative and they are brittle: any reordering
# of `-in`/`-out` around the algorithm flag breaks them, and reordering is free in a shell.

# Flags whose FOLLOWING token names the algorithm.
_SHELL_ALGORITHM_VALUE_FLAGS = frozenset(
    {
        "-t",  # ssh-keygen -t rsa
        "-md",  # openssl req -md sha1
        "-macalg",
        "-sigalg",
        "-keyalg",  # keytool -genkeypair -keyalg RSA
        "-digestalg",  # jarsigner -digestalg SHA1
        "-digest",
        "--digest-algo",  # gpg
        "--cipher-algo",  # gpg
        "--personal-cipher-preferences",
        "--secure-protocol",  # wget --secure-protocol=TLSv1 (also handled as key=value below)
        "-newkey",  # openssl req -newkey rsa:2048
        "-algorithm",  # openssl genpkey -algorithm RSA / PowerShell -Algorithm MD5
        "-keyalgorithm",  # PowerShell New-SelfSignedCertificate
        "-hashalgorithm",
        "-provider",
    }
)

# Bare subcommands that name an algorithm by themselves.
_SHELL_SUBCOMMAND_ALGORITHMS: dict[str, str] = {
    "genrsa": "RSA",
    "gendsa": "DSA",
    "dsaparam": "DSA",
    "ecparam": "ECDSA",
    "dhparam": "DH",
    "gendh": "DH",
    "md5sum": "MD5",
    "sha1sum": "SHA-1",
    "sha256sum": "SHA-256",
    "sha512sum": "SHA-512",
}

# Dash-prefixed tokens that name an algorithm or protocol version directly. Kept as an explicit
# set rather than "anything the registry resolves" so that `-in`, `-out` and `-des` -style
# filenames cannot be mistaken for algorithms.
_SHELL_FLAG_ALGORITHMS = frozenset(
    {
        # digests
        "md2",
        "md4",
        "md5",
        "sha",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3-256",
        "sha3-512",
        "ripemd160",
        "blake2b512",
        "sm3",
        "whirlpool",
        # ciphers
        "des",
        "des3",
        "des-ede3-cbc",
        "des-cbc",
        "rc2",
        "rc4",
        "rc5",
        "idea",
        "cast",
        "cast5",
        "bf",
        "blowfish",
        "seed",
        "sm4",
        "aes128",
        "aes192",
        "aes256",
        "aes-128-cbc",
        "aes-192-cbc",
        "aes-256-cbc",
        "aes-128-gcm",
        "aes-256-gcm",
        "aes-128-ecb",
        "aes-256-ecb",
        "camellia128",
        "camellia256",
        "chacha20",
        "chacha20-poly1305",
        # protocol versions
        "ssl2",
        "ssl3",
        "sslv2",
        "sslv3",
        "tls1",
        "tls1_1",
        "tls1_2",
        "tls1_3",
        "tlsv1",
        "tlsv1.0",
        "tlsv1.1",
        "tlsv1.2",
        "tlsv1.3",
    }
)

# Key-size flags whose following token is a bit count.
_SHELL_BITS_VALUE_FLAGS = frozenset({"-b", "-bits", "-keylength", "-keysize", "-newkey"})

# Subcommands whose following bare number is a bit count: `openssl genrsa 1024`.
_SHELL_BITS_SUBCOMMANDS = frozenset({"genrsa", "gendsa", "dhparam", "dsaparam"})


def _shell_tokens(command_text: str) -> list[str]:
    """Split a command line into argv-ish tokens, expanding `--flag=value` into two tokens.

    Whitespace splitting also handles the backslash line-continuations long openssl invocations
    are usually wrapped with; the stray trailing backslash becomes its own token and matches
    nothing.
    """
    tokens: list[str] = []
    for raw in command_text.split():
        token = raw.strip("'" + chr(34))
        if token.startswith("-") and "=" in token:
            flag, _, value = token.partition("=")
            tokens.extend([flag, value])
        else:
            tokens.append(token)
    return tokens


def _shell_algorithm(command_text: str) -> str | None:
    """The algorithm a shell/PowerShell command line selects, or None."""
    tokens = _shell_tokens(command_text)
    for index, token in enumerate(tokens):
        lowered = token.lower()
        if lowered in _SHELL_ALGORITHM_VALUE_FLAGS and index + 1 < len(tokens):
            value = tokens[index + 1]
            # `-newkey rsa:2048` names the algorithm before the colon.
            return value.split(":", 1)[0] if ":" in value else value
        if lowered in _SHELL_SUBCOMMAND_ALGORITHMS:
            return _SHELL_SUBCOMMAND_ALGORITHMS[lowered]
        if lowered.startswith("-") and lowered.lstrip("-") in _SHELL_FLAG_ALGORITHMS:
            return lowered.lstrip("-")
    return None


def _shell_key_bits(command_text: str) -> int | None:
    """The key size a shell/PowerShell command line requests, or None."""
    tokens = _shell_tokens(command_text)
    for index, token in enumerate(tokens):
        lowered = token.lower()
        if lowered in _SHELL_BITS_VALUE_FLAGS and index + 1 < len(tokens):
            value = tokens[index + 1]
            candidate = value.split(":", 1)[1] if ":" in value else value
            if candidate.isdigit():
                return int(candidate)
        if lowered in _SHELL_BITS_SUBCOMMANDS:
            for following in tokens[index + 1 :]:
                if following.isdigit():
                    return int(following)
    return None


def _anchor_node(caps: dict[str, list[Node]]) -> Node | None:
    # prefer an explicit @call/@anchor capture; else the earliest captured node
    for key in ("call", "anchor"):
        if caps.get(key):
            return caps[key][0]
    all_nodes = [n for nodes in caps.values() for n in nodes]
    return min(all_nodes, key=lambda n: n.start_byte) if all_nodes else None


def _snippet(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    text = source.decode("utf-8", "replace")
    lines = text.splitlines()
    row = node.start_point.row
    lo, hi = max(0, row - 2), min(len(lines), row + 3)  # ±2 lines around the finding
    return "\n".join(lines[lo:hi])


def _error_ratio(root: Node) -> float:
    total = 0
    errors = 0
    stack = [root]
    while stack:
        n = stack.pop()
        total += 1
        if n.is_error or n.type == "ERROR":
            errors += 1
        stack.extend(n.children)
    return errors / total if total else 0.0


__all__ = ["CodeScanner"]
