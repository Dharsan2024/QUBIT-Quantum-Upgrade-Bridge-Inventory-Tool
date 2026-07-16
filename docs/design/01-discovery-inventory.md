# QUBIT Subsystem Design 01 — Discovery & Inventory Engine

**Packages:** `qubit-scanner` (all discovery), `qubit-core` (registry, canonical algorithm registry, CBOM layer)
**Status:** Design v1 — conforms to `00-architecture-frame.md` (v1, binding)
**Authors:** QUBIT team (Dharsan L, Akshay Kumar S)
**Frame deviations:** none material (see §11.3 for clarifications: AGPL tooling kept out-of-process; in-house CBOM serializer instead of relying on `cyclonedx-python-lib` crypto-property models; public package facades as sanctioned interfaces).

---

## 1. Purpose & Requirements

### 1.1 Purpose

The Discovery & Inventory Engine is the input stage of QUBIT. It finds every cryptographic asset an organization has — in source code, in server/daemon configuration, on the wire, and in certificate/key stores — normalizes each finding into the shared `CryptoAsset` schema, deduplicates across scans and scanners, persists them in the Asset Registry (DB), and exports/imports the inventory as a CycloneDX v1.7 CBOM. Everything downstream (risk engine, migration orchestrator, dashboard) consumes only what this subsystem produces.

Design north star: **detection rules are data, not code.** A new "detect RSA key generation in Go" rule must be a YAML file plus embedded test snippets — zero Python changes.

### 1.2 Functional requirements

| ID | Requirement |
|----|-------------|
| FR-1 | Scan source trees in Python, Java, C/C++, Go, JavaScript (Node) via tree-sitter AST parsing; detect crypto API usage per a per-language/per-library rule catalog (Python `cryptography`/`pycryptodome`/`ssl`/`hashlib`, Java JCA/JCE/BouncyCastle, OpenSSL C API, Go `crypto/*` + `golang.org/x/crypto`, Node `crypto`/`tls`). **M2 baseline: Python, Java, Go; C/C++ and JavaScript rule packs are M3/stretch (§9, §10).** |
| FR-2 | Handle the semantic gap: case/alias normalization (`"des"` vs `"DES"` vs `"DES/ECB/PKCS5Padding"`), algorithm names built from local string constants, transformation-string parsing (`Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")`), with confidence levels; optionally escalate unresolved cases to the local Ollama LLM. |
| FR-3 | Scan configuration files: nginx, Apache httpd, `sshd_config`, Java keystore references (`javax.net.ssl.keyStore`, Spring `server.ssl.*`) — M2 baseline; `openssl.cnf` and Postfix `main.cf`/`master.cf` are M3/stretch (§9). Extract protocol versions, cipher strings, cert/key file references. |
| FR-4 | Active network scan: full TLS handshake enumeration against `host:port` targets — supported protocol versions, cipher suites (per version), key-exchange groups (classical + PQC hybrid, e.g. X25519MLKEM768), certificate chain retrieval and parsing. |
| FR-5 | Passive network scan: parse pcap/pcapng files, reassemble TLS handshakes, extract negotiated versions/cipher suites/groups/certificates per observed flow. **M3/stretch — pre-descoped from the M2 baseline (§9, §10).** |
| FR-6 | Certificate & key material scan: PEM/DER X.509 certs, CSRs, private/public keys, PKCS#12, JKS keystores (M2 baseline; JCEKS/BKS/UBER via the optional `pyjks` extra, M3/stretch — §3) — algorithm, key size, curve, validity, signature algorithm, fingerprints. Private-key bytes are never persisted: only fingerprints/metadata survive normalization (§6.5). |
| FR-7 | Normalize all findings into `CryptoAsset` (frame §"Shared CryptoAsset schema"), write to the registry with deterministic dedup and last-seen tracking; rescans converge (no duplicate rows). |
| FR-8 | Export the registry as a CycloneDX v1.7 CBOM (JSON) validating against the official schema; import an external v1.6/v1.7 CBOM into the registry. |
| FR-9 | Expose the above via `qubit scan …` CLI, an importable Python API, and REST endpoints under `qubit-api`. |
| FR-10 | Every finding carries evidence (code snippet + file:line, config directive, handshake transcript summary, cert fingerprint) sufficient for the dashboard's drill-down and the paper's case studies. |

### 1.3 Non-functional requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | Code scan throughput ≥ 2,000 files/min on a laptop (tree-sitter is incremental/fast; rules compiled once). 100 kLoC repo in < 60 s. |
| NFR-2 | Fully offline: no telemetry, no cloud calls; LLM assist uses local Ollama only, and is opt-in. |
| NFR-3 | All hard dependencies permissive or weak-copyleft file-scoped (MIT/BSD/Apache-2.0/MPL-2.0) — no GPL/AGPL hard deps; AGPL tools (sslyze, nmap) only as optional out-of-process adapters, never imported or bundled. |
| NFR-4 | Deterministic output: same input tree/pcap → identical asset set *modulo timestamps, with LLM-assist off* (stable IDs, sorted CBOM); `qubit cbom export --reproducible` pins the CBOM `metadata.timestamp` for byte-identical artifacts in paper experiments. |
| NFR-5 | Safe scanning: never sends application data to targets; rate-limited, bounded timeouts, explicit target allowlist file for network scans; refuses to scan public CIDRs without `--i-own-this`. |
| NFR-6 | ≥ 70% pytest coverage on `qubit-scanner` and the `qubit-core` registry/CBOM modules (frame CI gate). |
| NFR-7 | Rule catalog is hot-loadable: `--rules-dir` override; rules validated (`qubit rules lint`) against a JSON Schema; a bad rule fails loudly at load, not silently at scan. |
| NFR-8 | Memory-bounded: streaming file iteration, per-file size cap (default 2 MB, configurable), pcap streams capped at 64 KB of reassembled handshake bytes per flow. |

### 1.4 Explicit non-goals

- Whole-program interprocedural dataflow (CogniCrypt-class analysis). We do intra-file, single-assignment constant resolution + optional LLM assist; the paper positions this honestly against CrySL/CryptoGuard.
- Binary/firmware scanning, JVM bytecode scanning, live memory scanning.
- Decrypting captured traffic (we only read handshake plaintext).
- Vulnerability detection beyond crypto identification (misuse *detection* is rule-tagged, but exploitability analysis belongs to `qubit-risk`).

---

## 2. Component Breakdown

```
packages/qubit-scanner/src/qubit_scanner/
  catalog/            # rule catalog loader, JSON Schema, compiled rule model
    loader.py         #   RuleCatalog.load(dirs) -> RuleCatalog
    schema.py         #   pydantic models for qubit-rule/v1
    rules/            #   built-in YAML rules (shipped as package data)
      python/  java/  c/  go/  javascript/  config/
  code/               # (a) source-code scanner
    scanner.py        #   CodeScanner: walk, parse, query, resolve, emit Detection
    languages.py      #   language registry: extension map -> tree-sitter grammar
    resolve.py        #   string-constant folding, import tracking, alias normalization
    llm_assist.py     #   optional Ollama disambiguation for UNRESOLVED captures
  config/             # (b) config scanner
    nginx.py apache.py sshd.py opensslcnf.py postfix.py javaprops.py
    cipherstring.py   #   OpenSSL cipher-string expansion ("HIGH:!aNULL" -> suites)
  network/            # (c) network scanner
    active.py         #   TlsEnumerator (asyncio)
    clienthello.py    #   raw TLS ClientHello builder + ServerHello/Alert parser
    passive.py        #   PcapAnalyzer: dpkt + minimal TCP reassembly
    tlsparse.py       #   shared TLS record/handshake parser (used by active+passive)
    registry_tables/  #   vendored IANA cipher-suite & group CSVs
  certs/              # (d) certificate & key scanner
    scanner.py        #   CertScanner: PEM/DER/PKCS12/JKS sniffing + parsing
  normalize/          # (e) normalization + dedup
    normalizer.py     #   Detection -> CryptoAsset
    fingerprint.py    #   deterministic asset fingerprints
  api.py              # public Python API facade
  orchestrate.py      # ScanJob: fan-out scanners, collect, ingest

packages/qubit-core/src/qubit_core/
  models/asset.py     # CryptoAsset pydantic + SQLAlchemy models (frame-owned)
  algorithms.py       # canonical algorithm registry (names, aliases, quantum properties)
  registry.py         # AssetRegistry: upsert/dedup/query (DB source of truth)
  cbom/               # (f) CycloneDX v1.7 CBOM export/import
    export.py import_.py mapping.py
    schema/bom-1.7.schema.json   # vendored official schema for validation
```

| Component | Responsibility | Owner package |
|---|---|---|
| Rule Catalog | Load/validate/compile YAML rules into executable tree-sitter queries + extractors | qubit-scanner |
| Code Scanner | File walking, language detection, AST parse, rule query execution, semantic resolution | qubit-scanner |
| Config Scanner | Per-format parsers → directives → crypto meaning (incl. cipher-string expansion) | qubit-scanner |
| Active TLS Enumerator | Version/cipher/group/cert enumeration via crafted handshakes | qubit-scanner |
| Passive Pcap Analyzer | Handshake extraction from captures | qubit-scanner |
| Cert/Key Scanner | X.509 / PKCS#12 / JKS parsing | qubit-scanner |
| Normalizer + Fingerprinter | Detections → canonical `CryptoAsset`s with stable identity | qubit-scanner |
| Canonical Algorithm Registry | Single source of truth for algorithm names, aliases, key sizes, `quantum_vulnerable` mapping | qubit-core |
| Asset Registry | Upsert/dedup, last-seen, query API over DB | qubit-core |
| CBOM Layer | CycloneDX v1.7 export/import + schema validation | qubit-core |
| Scan Orchestrator | One `ScanJob` = N scanners + ingestion + summary; invoked by CLI and REST | qubit-scanner |

Dependency direction: `qubit-scanner` → `qubit-core` only (frame rule: communication via qubit-core models, DB, REST — no cross-package private imports).

---

## 3. Exact Tech Stack

All pip-installable; versions current as of July 2026 (verified). Pin with `~=` in `pyproject.toml`.

| Library | Version | License | Used for |
|---|---|---|---|
| `tree-sitter` (py-tree-sitter) | 0.26.x | MIT | AST parsing core; prebuilt wheels, no compiler needed |
| `tree-sitter-language-pack` | 1.12.x | MIT (bundles only permissively-licensed grammars) | Precompiled grammars for Python, Java, C, C++, Go, JavaScript (+300 more free) |
| `cryptography` (pyca) | ≥ 45, latest stable | Apache-2.0/BSD dual | X.509, PKCS#12, key parsing, fingerprints |
| *(vendored)* `jks_reader.py` | in-repo (~200 LoC) | MIT (ours) | JKS cert-entry parsing over `hashlib` + `cryptography` (documented SHA-1 keystore format); PKCS#12 handled by pyca. **`pyjks` is NOT a hard dep** — it depends on the abandoned `twofish` C extension (sdist-only, no wheels ⇒ fails without MSVC on Windows 11) and hasn't released since 2020; it survives only as the optional extra `qubit-scanner[jceks]` for JCEKS/BKS/UBER (M3/stretch) |
| `crossplane` | 0.5.x | Apache-2.0 | nginx config → JSON AST (NGINX Inc's own parser) |
| `dpkt` | 1.9.x | BSD-3 | pcap/pcapng framing + IP/TCP decoding (we do TLS parsing ourselves) |
| `PyYAML` | 6.x | MIT | Rule catalog files |
| `jsonschema` | 4.x | MIT | CBOM validation against vendored CycloneDX 1.7 schema |
| `cyclonedx-python-lib` | 11.11.x | Apache-2.0 | CBOM interop utilities / serialization plumbing where its models suffice (see §11.3) |
| `pydantic` | 2.x | MIT | All data models (frame) |
| `SQLAlchemy` + `alembic` | 2.x / 1.x | MIT | Registry persistence (frame) |
| `typer` + `rich` | latest | MIT | CLI + terminal output (frame) |
| `httpx` | 0.28.x | BSD-3 | Scanner→API ingestion in server mode |
| `pathspec` | 0.12.x | MPL-2.0 (file-scoped, dependency-safe) | `.gitignore`-style ignore handling |

**Runtime notes:**
- The stdlib `ssl` groups API (`SSLContext.set_groups()` / `get_groups()` / `SSLSocket.group()`, CPython gh-136306) lands in **Python 3.15** (final expected Oct 2026) — *not* 3.14 (the issue was filed after 3.14's feature freeze) — and `SSLSocket.group()` additionally requires OpenSSL ≥ 3.2. Plan: Docker image starts on `python:3.14-slim` (OpenSSL 3.5 ⇒ hybrid X25519MLKEM768 negotiates silently by default) and moves to `python:3.15-slim` at M2 once 3.15.0 ships; all group-API usage is feature-gated via `hasattr(ssl.SSLSocket, "group")`. Until then — and on the frame's minimum 3.12 — the **negotiated-group verification primitive is Probe B's plaintext ServerHello `key_share` parse (§6.3)** plus `openssl s_client -groups X25519MLKEM768` inside the bridge container; "report the negotiated group from a stdlib handshake" is a nice-to-have fast path, never a demo dependency.
- **Explicitly excluded as hard deps:** `sslyze` 6.3.x (AGPL-3.0 — optional subprocess adapter only, `qubit scan net --engine sslyze`, parsing its `--json_out`); `scapy` (GPL-2.0); `nmap` (invoked as external binary only if present, for host discovery convenience).
- Grammar pinning: `tree-sitter-language-pack` pins grammar revisions per release; we record the pack version in every scan's metadata for reproducibility.

---

## 4. Data Models / Schemas

### 4.1 CryptoAsset (frame-owned, qubit-core) — SQLAlchemy + Pydantic

Conforms exactly to the frame schema; scanner populates everything except `sensitivity`, `shelf_life_years`, `risk`, `migration` (risk/migrate engines own those, they stay `null`/default here).

```python
# qubit_core/models/asset.py
class Location(BaseModel):
    host: str | None = None; service: str | None = None
    repo: str | None = None; file_path: str | None = None; line: int | None = None

class ProtocolDetail(BaseModel):
    protocol: Literal["tls","ssh","ipsec","smtp","other"]
    version: str                      # "TLSv1.2", "TLSv1.3"
    cipher_suites: list[str] = []     # IANA names
    groups: list[str] = []            # "x25519", "X25519MLKEM768", ...
    extensions: dict[str, Any] = {}   # sig_algs, alpn — evidence-grade extras

class QuantumVulnerability(BaseModel):
    vulnerable: bool
    attack: Literal["shor","grover","none"]

class CryptoAsset(BaseModel):
    id: UUID                                  # uuid5(NAMESPACE_QUBIT, fingerprint) — stable
    fingerprint: str                          # §6.5; UNIQUE index in DB
    source_scanner: Literal["code","config","network","cert","key"]
    location: Location
    asset_type: Literal["algorithm-use","protocol","certificate","key","library"]
    algorithm: str                            # canonical, e.g. "RSA-2048", "ECDSA-P256", "AES-128-CBC", "SHA-1"
    key_size: int | None
    protocol_detail: ProtocolDetail | None
    library: LibraryRef | None                # {name, version|null}
    usage_context: Literal["tls","kex","signature","encryption-at-rest",
                           "token","hash","password","unknown"]
    sensitivity: str = "unknown"              # risk engine writes
    shelf_life_years: float | None = None     # risk engine writes
    quantum_vulnerable: QuantumVulnerability  # from canonical registry (§4.2)
    evidence: Evidence                        # §4.3
    discovered_at: datetime
    last_seen_at: datetime                    # additive column, see §11.3
    stale: bool = False                       # additive: set when a full rescan of the same
                                              # target set no longer observes this asset (§6.5);
                                              # consumed by dashboard "remediated/removed" view
    scan_id: UUID                             # provenance (ScanJob row)
    rule_id: str | None                       # which catalog rule fired (code/config)
    confidence: Literal["high","medium","low"]# additive column
    risk: RiskAnnotation | None = None
    migration: MigrationAnnotation | None = None
```

`fingerprint`, `last_seen_at`, `scan_id`, `rule_id`, `confidence` are additive provenance fields (frame schema is a minimum, not a ceiling; flagged in §11.3).

### 4.2 Canonical algorithm registry (qubit-core/algorithms.py)

Data file `algorithms.yaml` shipped in qubit-core; one entry per canonical algorithm:

```yaml
- canonical: RSA-2048
  family: RSA
  kind: asymmetric            # asymmetric | symmetric | hash | kdf | mac | pqc-kem | pqc-sig
  key_size: 2048
  aliases: [rsa2048, "RSA/2048", "rsa-2048"]
  cyclonedx_name: "RSA-2048"          # CycloneDX Cryptography Registry pattern instance
  oid: "1.2.840.113549.1.1.1"
  quantum_vulnerable: {vulnerable: true, attack: shor}
  classical_security_level: 112
  nist_quantum_security_level: 0
- canonical: ML-KEM-768
  family: ML-KEM
  kind: pqc-kem
  aliases: [Kyber768, kyber-768, mlkem768, X25519MLKEM768/pq-part]
  oid: "2.16.840.1.101.3.4.4.2"
  quantum_vulnerable: {vulnerable: false, attack: none}
  nist_quantum_security_level: 3
```

API: `resolve(name_or_alias, key_size=None) -> CanonicalAlgorithm | None` (case-insensitive, strips separators, applies key size to parameterize families: `("rsa", 4096) -> RSA-4096`). Rules never encode quantum properties — the registry is the single source of truth (rules only name algorithms).

### 4.3 Detection (scanner-internal, pre-normalization)

```python
class Detection(BaseModel):
    scanner: str                 # "code" | "config" | ...
    rule_id: str | None
    raw_algorithm: str           # exactly as seen: "des", "RSA/ECB/PKCS1Padding"
    key_size_expr: str | None    # raw evidence for key size, e.g. "2048", "keyBits"
    key_size: int | None
    usage_context: str
    location: Location
    library: LibraryRef | None
    protocol_detail: ProtocolDetail | None
    evidence: Evidence           # {snippet, snippet_sha256, context: dict}
    confidence: Literal["high","medium","low"]
```

**Evidence contract (producer guarantees to downstream consumers):**
- `evidence.snippet` for code assets = **±5 lines around the finding** (post-redaction, §6.5). qubit-risk's sensitivity classifier tokenizes identifiers/comments from this snippet itself — the scanner does NOT extract enclosing-function names or REST-endpoint mappings (agreed contract with 02-risk-engine).
- At **M2** the code scanner additionally populates `evidence.context.symbols = {defined: [...], used: [...]}` and `evidence.context.imports = [...]` per file (cheap byproduct of the ImportTable + query captures) — consumed by qubit-migrate's dependency-edge heuristic #1 (agreed contract with 03-migration-orchestrator; that heuristic is M2 there, gated on this landing).

### 4.4 Rule catalog format — `qubit-rule/v1` (the "rules are data" contract)

One YAML file per (language, library). JSON Schema in `catalog/schema.py`; linted in CI.

```yaml
# catalog/rules/java/jca.yaml
schema: qubit-rule/v1
language: java
library: { name: "JCA", detect_imports: ["javax.crypto", "java.security"] }
rules:
  - id: JAVA-JCA-CIPHER-001
    title: Cipher.getInstance transformation string
    match:
      query: |
        (method_invocation
          object: (identifier) @obj
          name: (identifier) @meth
          arguments: (argument_list (_) @arg0))
      where:
        - { capture: obj,  equals: "Cipher" }        # import-qualified check applied too
        - { capture: meth, equals: "getInstance" }
    extract:
      algorithm: { from: arg0, resolve: string-constant, transform: java-transformation }
      # java-transformation: "AES/CBC/PKCS5Padding" -> algorithm AES-CBC (+ mode, padding in evidence)
    asset: { asset_type: algorithm-use, usage_context: unknown }   # rules only state what they can
                                        # see; the normalizer refines `unknown` from the resolved
                                        # algorithm's kind (asymmetric cipher -> kex, symmetric ->
                                        # encryption-at-rest). `qubit rules lint` validates every
                                        # usage_context against the frame enum.
    confidence: high
    examples:
      positive:
        - 'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");'
        - |
          String algo = "RSA";
          Cipher c = Cipher.getInstance(algo);          # exercises constant resolution
      negative:
        - 'Cipher c = someFactory.getInstance();'

  - id: JAVA-JCA-KEYGEN-002
    title: KeyPairGenerator with key size
    match:
      query: |
        (method_invocation
          object: (identifier) @obj name: (identifier) @meth
          arguments: (argument_list (_) @arg0))
      where:
        - { capture: obj, equals: "KeyPairGenerator" }
        - { capture: meth, equals: "getInstance" }
    extract:
      algorithm: { from: arg0, resolve: string-constant }
      key_size:  { from_sibling_call: "initialize", arg: 0, resolve: int-constant }
    asset: { asset_type: algorithm-use, usage_context: signature }
    confidence: high
    examples:
      positive:
        - |
          KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
          g.initialize(2048);
```

Rule fields:

- `match.query`: a verbatim tree-sitter S-expression query for that grammar. Compiled once at catalog load (`tree_sitter.Query`).
- `match.where`: cheap post-filters on captures — `equals`, `in`, `regex`, `resolves_import` (capture's identifier must trace to one of the listed module paths via the file's import table).
- `extract.*.resolve`: one of `literal` (capture is the value), `string-constant` (fold literals; follow single local assignment; f-string/concat of literals), `int-constant`, `none`. Resolution failure ⇒ `raw_algorithm="UNRESOLVED"`, `confidence=low`, optional LLM assist (§6.2).
- `extract.*.transform`: named parser — `java-transformation`, `openssl-cipherstring`, `hashlib-name`, `identity`.
- `extract.key_size.from_sibling_call`: search the enclosing scope for a call on the same receiver variable (handles the `getInstance` + `initialize(2048)` split).
- `examples.positive/negative`: **every rule ships its own test fixtures**; `qubit rules test` compiles them into pytest cases automatically (§8.2).

Config-scanner rules use the same envelope with `match.directive` instead of `match.query`:

```yaml
# catalog/rules/config/nginx.yaml
schema: qubit-rule/v1
language: nginx
rules:
  - id: CFG-NGINX-PROTO-001
    match: { directive: ssl_protocols }
    extract: { protocol_versions: { from: args, transform: tls-version-list } }
    asset: { asset_type: protocol, usage_context: tls }
  - id: CFG-NGINX-CIPHERS-001
    match: { directive: ssl_ciphers }
    extract: { cipher_suites: { from: args, transform: openssl-cipherstring } }
    asset: { asset_type: protocol, usage_context: tls }
  - id: CFG-NGINX-CERT-001
    match: { directive: ssl_certificate }
    extract: { cert_path: { from: args } }        # chains into cert scanner (§6.4)
    asset: { asset_type: certificate, usage_context: tls }
```

Initial catalog (M1+M2 target ≈ 120 rules): Python `cryptography` (14), `pycryptodome` (12), `ssl`/`hashlib`/`hmac` (10); Java JCA/JCE (16), BouncyCastle (8); C OpenSSL EVP + legacy (18); Go `crypto/*` (16), `x/crypto` (6); Node `crypto`/`tls` (12); configs (~12).

### 4.5 ScanJob

```python
class ScanJob(BaseModel):
    id: UUID; created_at: datetime
    targets: list[str]                        # paths, host:port specs, pcap files
    scanners: list[str]                       # subset of code/config/network/cert
    status: Literal["pending","running","done","failed","partial"]
    stats: dict            # files_scanned, parse_failures, assets_new, assets_seen, duration_s
    tool_versions: dict    # qubit-scanner, tree-sitter-language-pack, rule catalog hash
```

---

## 5. Public Interfaces

### 5.1 CLI (Typer, in qubit-cli, thin wrapper over qubit_scanner.api)

```
qubit scan <TARGET> [--out cbom.json]      # auto-dispatch: dir->code+config+certs, host[:port]->net,
                                           # *.pcap->passive   (frame req. #1)
qubit scan code  PATH [--lang py,java] [--rules-dir DIR] [--llm-assist] [--jobs N]
qubit scan config PATH [--format nginx|apache|sshd|opensslcnf|postfix|auto]
qubit scan net   HOST[:PORT] [--ports 443,8443,...] [--cidr] [--no-pqc-probe]
                 [--engine builtin|sslyze] [--rate 20/s] [--i-own-this]
qubit scan pcap  FILE.pcap
qubit scan certs PATH [--password-file F]  # for encrypted PKCS12/JKS
qubit scan ... [--json] [--no-db]          # --no-db: emit results to stdout/file WITHOUT ingesting
                                           # to the registry — the contract qubit-migrate's
                                           # stage-5 sandbox re-scan depends on
qubit cbom export [--scan-id ID] [--out cbom.json] [--spec 1.7]
                  [--with-evidence]        # evidence omitted by default (redaction, §6.5)
                  [--reproducible]         # pin metadata.timestamp for byte-identical output (NFR-4)
qubit cbom import FILE.json
qubit rules list|lint|test [--rules-dir DIR]
qubit assets ls [--algorithm RSA*] [--scanner code] [--json]
```

Exit codes: 0 ok, 1 fatal, 2 completed-with-errors (partial), 3 no assets found. `--json` on every command for scripting.

### 5.2 Python API (`qubit_scanner.api`)

```python
def scan_paths(paths: list[Path], *, scanners: set[str] = {"code","config","cert"},
               catalog: RuleCatalog | None = None, llm_assist: bool = False,
               progress: Callable[[ScanProgress], None] | None = None) -> ScanResult

async def scan_network(targets: list[TargetSpec], *, ports: list[int] = [443],
                       probe_pqc: bool = True, rate_limit: float = 20.0) -> ScanResult

def scan_pcap(path: Path) -> ScanResult

def ingest(result: ScanResult, registry: AssetRegistry) -> IngestStats
    # registry from qubit_core; or IngestClient(base_url) to POST via REST in server mode

class ScanResult(BaseModel):
    job: ScanJob
    detections: list[Detection]
    assets: list[CryptoAsset]        # normalized, deduped within the result
    errors: list[ScanError]
```

Lower-level (for tests and the paper's ablation experiments): `CodeScanner(catalog).scan_file(path) -> list[Detection]`, `TlsEnumerator().enumerate(host, port) -> TlsEndpointReport`, `CbomExporter(registry).export(scan_id=None) -> dict`.

### 5.3 REST endpoints — **defined by doc 05's normative registry, not here**

The scanner is a producer; the HTTP surface that exposes its output is owned by **05-platform-api-dashboard §5.1** (the single normative REST registry). The relevant endpoints there are `POST /api/v1/projects/{pid}/scans` (202 + job, SSE progress — *not* WebSocket), `GET /api/v1/scans/{sid}/assets`, `POST /api/v1/scans/{sid}/assets/batch` (bulk ingest, used by the bridge `--push` path), `GET /api/v1/scans/{sid}/cbom`, `POST /api/v1/projects/{pid}/cbom/import`, and `GET /api/v1/registry/algorithms`. This subsystem only defines the *Python* contract (§5.2) that doc 05's service layer calls; it consumes no REST itself.

---

## 6. Key Algorithms & Flows

### 6.1 Code scan pipeline

```
walk(root, ignore=.gitignore+defaults, size_cap)          # pathspec
  -> detect language by extension (+ shebang fallback)
  -> parse file with tree-sitter grammar (language pack)
  -> build ImportTable (per-language import/require/include extraction)
  -> shortlist rules: only rules whose library.detect_imports intersect ImportTable
     (C: OpenSSL rules gated on '#include <openssl/...>')
  -> for rule in shortlist: run compiled query; for each match:
       apply where-filters -> run extractors -> Detection
  -> resolver pass (6.2) on UNRESOLVED detections
  -> normalize (6.5) -> CryptoAsset[]
```

Parallelism: `ProcessPoolExecutor` over files (`--jobs`, default `os.cpu_count()`); each worker owns its parsers (tree-sitter objects are not picklable — construct per worker via initializer).

### 6.2 Semantic gap resolution (the CrySL-gap answer, scoped for undergrads)

```
resolve_string_constant(node, scope):
  1. node is string literal            -> return folded value           (conf: high)
  2. node is concat/f-string of literals -> fold                        (conf: high)
  3. node is identifier:
       find assignments to it in enclosing function, then module scope
       if exactly one assignment and RHS resolves by (1)/(2) -> value   (conf: medium)
  4. else -> UNRESOLVED
       if --llm-assist: prompt local Ollama with the enclosing function
       source + question "what algorithm string reaches this call?";
       accept answer only if it resolves in the canonical registry     (conf: low, evidence
       tagged llm_assisted: true)
  5. else emit Detection(raw_algorithm="UNRESOLVED", confidence=low)
```

Alias normalization then runs in the canonical registry: lowercase, strip `-_/ `, alias table, transformation-string parsing (`java-transformation` splits `ALG/MODE/PAD`; `hashlib-name` maps `md5`→`MD5`; `openssl-cipherstring` expands via vendored IANA table + OpenSSL cipher-string grammar subset: `:`-separated tokens, `!`/`-`/`+` operators, keyword groups `HIGH/MEDIUM/DEFAULT/aNULL/...` resolved against the vendored table). This is exactly the `"des"` vs `"DES"` case from the literature — handled by data, not code.

### 6.3 Active TLS enumeration (builtin engine)

Two probes layered; together they produce one `protocol` asset per endpoint, **one `algorithm-use` asset per distinct negotiated-relevant algorithm** (key-exchange group, signature algorithm, cipher — see §6.5), plus one `certificate` asset per chain element.

**Probe A — stdlib full handshakes** (cert chain, default negotiation): `ssl.create_default_context()` with verification off, capture negotiated version/cipher/ALPN; `getpeercert(binary_form=True)` + `SSLSocket.get_verified_chain()`/`get_unverified_chain()` (3.13+) → cert scanner. On Python 3.15+/OpenSSL ≥ 3.2 (feature-gated via `hasattr(ssl.SSLSocket, "group")`): `SSLSocket.group()` records the actually-negotiated group (e.g. `X25519MLKEM768`) as a fast path; Probe B is the canonical group-verification source (§3 runtime notes).

**Probe B — raw ClientHello enumeration** (`clienthello.py`, no OpenSSL dependency, works everywhere, and probes suites/groups the local stack doesn't implement). **Scope guard:** `clienthello.py` is time-boxed to 2 person-weeks; enumeration loops cover **TLS 1.3 and 1.2 only** — TLS 1.0/1.1 presence is detected via the `supported_versions` extension and downgrade/`protocol_version` alerts, never enumerated suite-by-suite. Demo phase-4 verification depends only on the single-group PQC probe + packet capture below, never on full enumeration:

```
for version in [TLS1.3, TLS1.2]:
    offered = all_suites_for(version)             # vendored IANA table
    while offered:
        send ClientHello(version, offered, groups=ALL_GROUPS, sni=host)
        resp = parse ServerHello | Alert | timeout
        if Alert(handshake_failure|protocol_version) or timeout: break
        accepted.add(resp.cipher_suite); offered.remove(resp.cipher_suite)
        # TLS1.3: also read key_share / HelloRetryRequest selected_group

# PQC group probing (TLS 1.3): offer exactly one candidate group per hello,
# with an empty key_share for it -> server that supports it answers
# HelloRetryRequest(selected_group=candidate); else alert/other group.
for g in [0x11EC X25519MLKEM768, 0x11EB SecP256r1MLKEM768,
          0x11ED SecP384r1MLKEM1024, 0x6399 X25519Kyber768Draft00(legacy)]:
    probe(g) -> supported_groups
```

Concurrency: asyncio, per-host semaphore, global token-bucket rate limiter, 5 s connect / 5 s read timeouts, ≤ 3 retries with jitter. Output `TlsEndpointReport {host, port, versions:{v:[suites]}, groups[], cert_chain[], sni_used, timing}`.

### 6.4 Passive pcap analysis

```
dpkt.pcap/pcapng reader -> for each packet: ethernet/ip/tcp decode
flow key = (src, sport, dst, dport); per-flow ordered byte accumulator
  (in-order-only reassembly; out-of-order handshake segments beyond a 64-entry
   hold-back buffer are dropped and counted as a stat — good enough for hellos)
feed accumulator to tlsparse.RecordReader (shared with active scanner):
  ClientHello  -> offered versions/suites/groups (evidence only, confidence=medium)
  ServerHello  -> negotiated version/suite/group  -> protocol asset (confidence=high)
  Certificate  (TLS<=1.2 plaintext) -> cert assets
stop parsing a flow after ChangeCipherSpec / first app-data record or 64 KB
```

Note recorded in evidence when TLS 1.3 hides the cert chain (encrypted extensions) — the report distinguishes "negotiated" from "offered".

### 6.5 Normalization, fingerprinting, dedup

```
normalize(det: Detection) -> CryptoAsset:
  canon = algorithms.resolve(det.raw_algorithm, det.key_size)
  algorithm = canon.canonical if canon else f"UNKNOWN({det.raw_algorithm})"
  quantum_vulnerable = canon.quantum_vulnerable if canon else {vulnerable: unknown->false, attack: none}
  redact(det.evidence)                       # see "Evidence redaction" below
  # ALL path components are normalized to POSIX form BEFORE hashing
  # (PurePosixPath.as_posix(), casefold on Windows) — identical fingerprints
  # from Windows dev machines and the Linux Docker runtime.
  fingerprint = sha256(canonical_json({
      scanner: det.scanner,
      # identity fields per scanner type:
      code:    (repo_rel_posix_path, rule_id, algorithm, line_bucket)  # line_bucket = line//10:
                                                                       # survives small edits, ADR-noted tradeoff;
                                                                       # demo-lab fixtures are curated (and fixture-linted)
                                                                       # so no two identical (rule, algorithm) findings
                                                                       # share a bucket
      config:  (posix_file_path, directive, algorithm)
      network-protocol:  (host, port, protocol_version)   # one protocol asset per endpoint+version;
                                                          # its `algorithm` field = the protocol version string
      network-algorithm: (host, port, algorithm)          # one algorithm-use asset per distinct
                                                          # negotiated-relevant algorithm (kex group /
                                                          # sig alg / cipher) — carries its own
                                                          # quantum_vulnerable verdict; cross-referenced
                                                          # from the protocol asset via bom-refs (§6.6)
      cert:    (cert_sha256_fingerprint,)         # same cert on disk & wire -> same asset, locations merged
      key:     (public_key_sha256 | posix_file_path)
      import:  (source_bom_serial, bom_ref)       # imported CBOMs lack scanner identity fields —
                                                  # dedicated arm prevents collapsing them into one row
  }))[:32]
  id = uuid5(QUBIT_NS, fingerprint)

AssetRegistry.upsert(asset):
  ON CONFLICT(fingerprint) DO UPDATE
     last_seen_at=now, scan_id=new, evidence=new,
     locations: cert/network assets merge location lists
  -> returns (created|refreshed)
```

**Evidence redaction (security-critical, runs inside the normalizer for every asset):** key *bytes* never survive normalization — key/cert assets carry fingerprints and metadata only; PEM private-key blocks (`-----BEGIN … PRIVATE KEY-----`) and high-entropy string literals are scrubbed from code snippets before persistence; keystore passwords are used transiently and never written to DB, logs, or evidence. CBOM export omits evidence by default — `qubit cbom export --with-evidence` is the explicit opt-in. A CI test asserts no PEM private-key block ever appears in the DB file or any exported CBOM produced from the fixture corpus (which includes planted keys).

Rescan convergence (NFR + frame demo phase "re-scan proves remediation"): assets not seen in a full rescan of the same target set get `migration.status` untouched but are flagged `stale=true` (declared in §4.1; dashboard shows remediated/removed).

The network split into protocol + algorithm-use assets keeps the schema honest: an endpoint offering both `X25519` and `X25519MLKEM768` yields two algorithm assets with *different* `quantum_vulnerable` verdicts, instead of one endpoint asset with an undefined verdict — and gives the risk engine per-algorithm granularity, as the frame's "risk engine annotates each asset" requires.

### 6.6 CBOM export (CycloneDX v1.7)

Mapping (`qubit_core/cbom/mapping.py`):

| CryptoAsset | CycloneDX 1.7 |
|---|---|
| asset_type=algorithm-use | `component{type:"cryptographic-asset"}` + `cryptoProperties{assetType:"algorithm", algorithmProperties:{primitive, parameterSetIdentifier, curve?, executionEnvironment:"software-plain-ram", cryptoFunctions[], classicalSecurityLevel, nistQuantumSecurityLevel}}`, `bom-ref = urn:qubit:asset:{id}` |
| asset_type=protocol | `cryptoProperties{assetType:"protocol", protocolProperties:{type:"tls", version, cipherSuites:[{name, algorithms:[bom-refs], identifiers:[IANA hex]}]}}` — the `algorithms` bom-refs point at the per-endpoint `algorithm-use` assets emitted by §6.5's `network-algorithm` arm, so no dangling refs |
| asset_type=certificate | `certificateProperties{subjectName, issuerName, notValidBefore, notValidAfter, signatureAlgorithmRef, subjectPublicKeyRef, certificateFormat:"X.509"}` |
| asset_type=key | `relatedCryptoMaterialProperties{type:"private-key"…, size, state:"active", securedBy:{mechanism:"Software"}}` |
| location/evidence | `component.evidence.occurrences[{location, line}]` + `properties[{name:"qubit:evidence", value:...}]` |
| algorithm names | CycloneDX Cryptography Registry patterns, e.g. `RSA-PKCS1-1.5-SHA-256-2048` when padding/digest known, else family-size form; OID emitted in `cryptoProperties.oid` |

Export = deterministic ordering (sort by bom-ref) → serialize → `jsonschema.validate` against vendored `bom-1.7.schema.json` → write. Import = validate (accept 1.6 and 1.7) → inverse mapping → detections → normal ingest path (dedup applies), unknown algorithm names preserved as `UNKNOWN(...)` with a warning list returned.

---

## 7. Failure Modes & Handling

| # | Failure | Handling |
|---|---|---|
| 1 | Unparseable/binary/minified source file (tree-sitter ERROR nodes > 20% of tree) | Skip file, record `ScanError{file, reason}`, count in stats; scan continues (never abort a job for one file) |
| 2 | Grammar/pack version drift changes node names, queries silently match nothing | CI canary: `qubit rules test` runs every rule's positive examples on every dependency bump; a rule with 0 positive matches fails CI |
| 3 | Huge repo / node_modules / vendored trees | Default ignore set (`node_modules, vendor, .git, dist, *.min.js`), `.gitignore` respected, 2 MB file cap, `--max-files` guard with warning |
| 4 | String constant not resolvable (dynamic algorithm choice) | Emit `UNRESOLVED` low-confidence asset (visible, honest) rather than dropping; optional LLM assist; counted separately in paper metrics |
| 5 | LLM assist hallucinates an algorithm | Answer accepted only if it resolves in canonical registry AND the literal appears in the provided context window; always tagged `llm_assisted` |
| 6 | Network target down / filtered / RST | Per-endpoint timeout, mark endpoint `unreachable` in ScanJob stats, no asset emitted |
| 7 | Server tolerates only small ClientHellos or breaks on unknown groups (middlebox intolerance) | Retry once with minimal hello (single suite batch, no PQC groups); record `intolerant_middlebox: true` |
| 8 | Scanning unauthorized hosts | Non-RFC1918 targets require `--i-own-this` + entry in `~/.qubit/allowed_targets`; refusal is default; rate limiting always on |
| 9 | Encrypted PKCS12/JKS without password | Try empty + `changeit`; else emit `certificate/key` asset with `algorithm=UNKNOWN(encrypted-store)`, evidence "password required" |
| 10 | Malformed pcap / truncated flows / TLS 1.3 encrypted certs | Per-flow error isolation; distinguish "offered" vs "negotiated"; encrypted cert chains simply produce no cert asset (noted in evidence) |
| 11 | DB write conflict (two scans concurrently) | Upsert is idempotent by fingerprint; SQLite WAL mode; batch inserts of 500 with retry-on-locked |
| 12 | CBOM import of hostile/garbage JSON | Schema validation first; size cap 50 MB; unknown fields ignored; import never executes strings (no eval anywhere) |
| 13 | Rule file syntax/schema error | Catalog load fails fast with file+line diagnostics (`qubit rules lint` = same code path); scan never starts with a broken catalog |
| 14 | Windows/macOS path & encoding issues | All paths `pathlib`, files read as bytes for tree-sitter (it takes bytes), evidence decoded UTF-8/replace; fingerprint paths normalized to POSIX + casefolded (§6.5) so Windows-host CLI and Linux-container scans converge |
| 15 | Sensitive material (private keys, passwords, secrets) captured in evidence | Redaction pass in the normalizer (§6.5): fingerprints/metadata only for key material, PEM blocks + high-entropy literals scrubbed from snippets, passwords never persisted; CBOM evidence export is opt-in (`--with-evidence`); CI test asserts no PEM private-key block in DB or exported CBOM |

---

## 8. Testing Strategy

### 8.1 Layers

1. **Unit:** resolver (constant folding cases per language), cipher-string expansion vs known OpenSSL outputs, fingerprint stability, canonical registry resolution, CBOM mapping round-trip (export→import→identical asset set).
2. **Rule tests (auto-generated):** every rule's embedded `examples.positive/negative` become pytest parametrized cases: positive must yield ≥ 1 Detection with expected algorithm; negative must yield 0. This is also the fixture-authoring workflow: writing a rule *is* writing its tests.
3. **Integration — code:** `demo-lab/` apps (frame-owned deliberately-vulnerable apps: `vulnapp-python` + `vulnapp-java` in M1, per the shared demo-lab SPEC) each carry a `ground_truth.yaml` (list of expected assets: file, line, algorithm). One tiered target table (single source of truth for §9 acceptance): **literals-only subset P/R = 1.0** (fixtures curated + fixture-linted so no two identical findings share a line bucket); **full ground truth ≥ 0.9 at M1, ≥ 0.85 at M2** (incl. alias/string-constant cases).
4. **Integration — network:** `tests/compose/tls-matrix.yaml` spins containers: (a) nginx TLS1.2-only RSA suites, (b) nginx TLS1.3 default, (c) `openssl s_server` built on `debian:trixie` (ships OpenSSL 3.5 — there is no official `openssl:3.5` Docker Hub image) with `-groups X25519MLKEM768`, (d) old openssl 1.1.1 image with 3DES enabled. Assertions on exact suites/groups discovered. Runs in CI via services; skipped gracefully when Docker absent (`-m network`).
5. **Integration — pcap:** golden pcaps checked into `tests/fixtures/pcaps/`, *generated once* by a script (`tests/fixtures/make_pcaps.sh`: tshark capture of scripted `openssl s_client` handshakes against the tls-matrix containers) and committed — CI never needs capture privileges. Regeneration is documented, not automatic.
6. **Benchmark (M3, feeds the paper):** run code scanner on CryptoAPI-Bench (Java crypto-misuse benchmark) + a hand-built corpus (~150 labeled snippets across Python/Java/Go baseline — extended to 5 languages only if the stretch rule packs land — incl. alias/string-built cases from MASC-style mutations); report precision/recall vs CogniCrypt baseline numbers from literature. Corpus lives in `demo-lab/benchmark-corpus/` with `labels.csv`.
7. **Property tests:** `hypothesis` on ClientHello parser (random truncation never crashes; parse(serialize(x)) == x).

### 8.2 Fixture construction summary

- Rule snippets: embedded in rule YAML (authored with the rule).
- Ground-truth repos: demo-lab apps annotated by hand once, reviewed by both students (inter-annotator check — paper method detail).
- Network: docker compose matrix with pinned images = reproducible "known server".
- Pcaps: scripted generation, committed binaries (~small), regeneration script versioned.
- Keystores/certs: `tests/fixtures/make_material.py` generates self-signed RSA-1024/2048/4096, ECDSA-P256, Ed25519 certs and packs JKS (via keytool in a temurin container, once, committed) + PKCS12 (via `cryptography`).

CI: ruff + mypy + pytest (unit + rule tests always; network/pcap marked, run in the docker-enabled job) — frame's ≥ 70% coverage gate applies to `qubit_scanner` and `qubit_core.registry/cbom/algorithms`.

---

## 9. Milestones (frame cadence) — effort in person-weeks (pw), 2 students

Effort is drawn from the **portfolio-reconciled capacity budget in 06-engineering-plan (≈44 pw total across ALL subsystems)**; this subsystem's allocation is **9 pw baseline** (M1 3.5 + M2 4 + M3 1.5), the largest single share because every other subsystem consumes its output. The M2 baseline was pre-descoped (FR-1/FR-3/FR-5/FR-6): passive pcap, JS + C/C++ rule packs, JCEKS/BKS, and openssl.cnf/postfix are **M3/stretch, not baseline** — cut-lines 2–4 of §10 applied up front so the other five subsystems' M2 slices are actually resourced.

### M1 — walking skeleton (by First Review, ~Sep 2026) — **3.5 pw**

Scope: rule catalog loader + JSON Schema + `qubit rules lint/test`; code scanner for **Python + Java** (~40 rules: cryptography, pycryptodome, hashlib/ssl, JCA); literal + alias resolution (no constant-folding yet); normalizer + fingerprint dedup + redaction + AssetRegistry upsert; minimal CBOM export (algorithm assets only, schema-valid 1.7); `qubit scan <path>` end-to-end.

Acceptance criteria:
- `qubit scan demo-lab/vulnapp-python && qubit cbom export` produces a CBOM that validates against the official 1.7 schema; demo-lab ground truth: P/R = 1.0 on the literals-only subset, ≥ 0.9 full (tiered table, §8.1).
- Running the same scan twice yields 0 new rows (dedup proof).
- CI green with rule-example tests auto-generated; ≥ 40 rules merged.
- Registry rows visible on the M1 dashboard page via `GET /api/v1/assets`.

### M2 — feature complete baseline (end Phase 1, ~Nov 2026) — **4 pw**

Scope: **Go** grammar + rules (catalog ≈ 90 across Python/Java/Go); constant-folding resolver + `java-transformation`/`hashlib-name` transforms + optional Ollama assist; config scanner (nginx via crossplane, apache, sshd, Java keystore refs) + `openssl-cipherstring` expansion; active TLS enumerator (probe A + B incl. PQC group probing, TLS 1.3/1.2 only) + tls-matrix compose tests; cert/key scanner (PEM/DER/PKCS12 + vendored JKS reader); **PQC-API detection rules** (pyca `mlkem`/`mldsa`, BouncyCastle `"ML-KEM"`/`"ML-DSA"`) so qubit-migrate's stage-5 re-scan can assert `present: ML-KEM`; `evidence.context.symbols/imports` (§4.3 contract); CBOM import; `POST /scans` + SSE progress (via qubit-api's normative contract); cross-scanner cert correlation; `--no-db` scan mode.

Acceptance criteria:
- Python, Java, Go demo-lab ground truths at the §8.1 tiered targets (full ≥ 0.85 incl. alias + string-constant cases).
- Active scan of tls-matrix reports exact expected suites, and detects `X25519MLKEM768` on the OpenSSL 3.5 container via Probe B (the frame's demo phase-4 verification primitive).
- CBOM export→import round-trip is lossless on the registry.
- One command (`qubit scan demo-lab/ && qubit scan localhost:8443`) populates everything the risk engine needs.

### M3 — hardened product + paper experiments (Jan–Mar 2027) — **1.5 pw baseline + stretch**

Baseline scope: performance pass (NFR-1 measured & reported), Windows/Linux smoke matrix, packaging polish (`pip install qubit-scanner` standalone works), benchmark evaluation (CryptoAPI-Bench Java corpus + hand-built corpus, ablation: rules-only vs rules+resolver vs rules+resolver+LLM — a core paper table), docs (rule-authoring guide), property hardening of parsers.
Stretch (only if schedule allows, in cut-line-reverse order): JS + C/C++ rule packs, passive pcap analyzer, JCEKS/BKS via `[jceks]` extra, openssl.cnf/postfix configs, sslyze adapter.

Acceptance criteria:
- Benchmark table complete with reproduction script (`make eval`); scanner section of paper drafted.
- 100 kLoC scan < 60 s demonstrated in CI perf job.
- Zero crashes across corpus + 10k-iteration hypothesis runs; coverage ≥ 70%.

**Subsystem total: 9 pw baseline** of the team's ~44 pw reconciled capacity (06-engineering-plan owns the portfolio table).

---

## 10. Risks & Mitigations + Cut-lines

| Risk | L×I | Mitigation |
|---|---|---|
| Tree-sitter query semantics differ per grammar (Java `method_invocation` vs Go `call_expression`) → rule authoring slower than planned | M×M | Rules are per-language anyway; write 3 "template rules" per language first; rule-example tests catch grammar drift |
| C/C++ macro obfuscation defeats AST rules (OpenSSL code is macro-heavy) | H×M | Scope C rules to EVP + common legacy calls; document limitation honestly in paper (it strengthens the LLM-assist narrative) |
| PQC group probing behaves inconsistently against middleboxes/CDNs | M×M | Demo targets are our own containers; middlebox intolerance handled (§7.7) and reported, not fatal |
| `cyclonedx-python-lib` crypto-property model coverage for 1.7 lags | M×L | In-house serializer is primary (§11.3); official JSON Schema validation is the compatibility contract |
| Passive TLS 1.3 hides certs → committee expects "certs from pcap" | M×L | Demo pcap uses a TLS1.2 leg for cert extraction; UI copy distinguishes offered/negotiated/encrypted |
| Scope explosion (5 languages × N libraries) | H×H | Rule count is elastic by design — the engine doesn't change; cut libraries, not features (below) |
| Two-person bus factor / uneven skills | M×H | Rule authoring is the parallelizable, low-risk task; one student owns engine code, both write rules |

**Cut-lines (drop in this order under time pressure — product story preserved at every line):**

1. LLM assist in scanner (`--llm-assist`) — the migration engine still shows LLM novelty; scanner falls back to honest `UNRESOLVED` assets.
2. Passive pcap analyzer — demo phase 1 uses Wireshark manually anyway; active scanner still proves network discovery + phase-4 verification.
3. JCEKS/BKS/UBER keystores (keep JKS + PKCS#12) and Postfix/openssl.cnf config formats (keep nginx + sshd + apache).
4. JavaScript and C/C++ code rules to post-M2 (keep Python + Java + Go) — demo lab is Python/Java; paper benchmark (CryptoAPI-Bench) is Java.
5. CBOM **import** (keep export — export is the compliance story and demo phase 2).
6. CIDR sweep + sslyze adapter (keep single-host active enumeration).

**Never cut:** code scanner (Py+Java) + rule catalog, registry dedup, CBOM 1.7 export, active TLS enumeration with PQC group detection — these four are demo phases 2 and 4 and the paper's evaluation spine.

---

## 11. Appendices

### 11.1 Example end-to-end trace (developer orientation)

```
$ qubit scan demo-lab/spring-app
[code] 214 files, 3 skipped (minified)  ->  17 detections
  JAVA-JCA-CIPHER-001  src/main/java/Pay.java:88  "RSA/ECB/PKCS1Padding" -> RSA (kex)
  JAVA-JCA-KEYGEN-002  src/main/java/Pay.java:91  RSA + initialize(2048) -> RSA-2048
[config] application.properties: server.ssl.key-store=classpath:keystore.jks
[cert]   keystore.jks: RSA-2048 cert CN=pay.demo, SHA1withRSA signature
registry: 12 new, 5 refreshed        cbom: docs/cbom-2026-09-14.json (valid, spec 1.7)
```

### 11.2 Vendored data files (all in-repo, versioned)

- IANA TLS Cipher Suites CSV + IANA Supported Groups CSV (public registry data) → generated Python tables (`make regen-tables`).
- OpenSSL cipher-string keyword→suite map (extracted once from `openssl ciphers -V` across 1.1.1/3.0/3.5 in containers; committed).
- CycloneDX `bom-1.7.schema.json` (Apache-2.0) for validation.
- `algorithms.yaml` canonical registry (~90 entries at M2).

### 11.3 Frame deviations & clarifications

1. **No deviation, clarification:** frame's `CryptoAsset` is treated as the minimum contract; we add provenance fields (`fingerprint`, `last_seen_at`, `scan_id`, `rule_id`, `confidence`) as additive columns in qubit-core. All frame fields keep exact names/semantics.
2. **No deviation, license note:** sslyze (AGPL) and nmap are optional external processes invoked by adapters, never dependencies — keeps the MIT license clean (frame binding).
3. **No deviation, implementation choice:** CBOM serialization is an in-house mapping validated against the official CycloneDX 1.7 JSON Schema; `cyclonedx-python-lib` (Apache-2.0, v11.11+) is used where its models already cover our needs, but the schema file — not the library — is the compatibility contract, because third-party crypto-property model coverage historically lags spec releases.
4. **Python version:** package supports 3.12+ (frame); the shipped Docker image uses `python:3.14-slim` (OpenSSL 3.5 ⇒ hybrid groups negotiate by default), moving to `python:3.15-slim` at M2 for the stdlib `ssl` groups API (`SSLContext.set_groups`, `SSLSocket.group` — a Python 3.15 feature, gated via `hasattr`; see §3 runtime notes). Within frame bounds either way.
5. **Sanctioned facades:** the frame's "no cross-package private imports" rule is read as: each package's public facade (`qubit_scanner.api`, `qubit_core.registry`, …) IS a sanctioned interface — `qubit-cli` imports facades directly for offline one-command scans. Enforced in CI with an import-linter contract (facade modules allowed, everything else forbidden).
