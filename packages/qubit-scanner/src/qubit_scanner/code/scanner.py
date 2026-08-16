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
from .languages import language_for

# tree-sitter reports ERROR nodes for unparseable regions; above this fraction we skip the file.
_MAX_ERROR_RATIO = 0.20


class CodeScanner:
    """Runs a rule catalog against source files of the languages it knows."""

    def __init__(self, catalog: RuleCatalog) -> None:
        self._catalog = catalog

    def scan_file(self, path: Path, *, repo: str | None = None) -> list[Detection]:
        language = language_for(path)
        if language is None or not self._catalog.for_language(language):
            return []
        try:
            source = path.read_bytes()
        except OSError:
            return []
        return self.scan_source(source, language, file_path=str(path), repo=repo)

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
_FUNC_TYPES = {
    "function_definition",  # python
    "function_declaration",  # go / js
    "method_declaration",  # java / go
    "method_definition",  # js
    "func_literal",  # go closures
    "arrow_function",  # js
}
_CLASS_TYPES = {"class_definition", "class_declaration", "type_declaration"}


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
            if node.type == "identifier":
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

    if "ml_kem" in lowered or "mlkem" in lowered or "kyber" in lowered:
        return f"ML-KEM-{digits}" if digits in {"512", "768", "1024"} else "ML-KEM"
    if "ml_dsa" in lowered or "mldsa" in lowered or "dilithium" in lowered:
        return f"ML-DSA-{digits}" if digits in {"44", "65", "87"} else "ML-DSA"
    if "slh_dsa" in lowered or "slhdsa" in lowered or "sphincs" in lowered:
        # SLH-DSA parameter sets carry a hash and a size (`sha2_128f`); the registry tracks the
        # family, so the parameter set stays in the evidence rather than the algorithm identity.
        return "SLH-DSA"
    return name


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
