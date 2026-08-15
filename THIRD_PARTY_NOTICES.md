# Third-Party Notices

QUBIT (MIT license, this repository) is developed independently. This file lists external
projects whose publicly-documented schemas, data, or specification details informed specific
files in this repository — required attribution per those projects' own licenses (Apache
License 2.0, §4(b)/(c)). No source code from any project listed here is vendored, copied, or
redistributed; only publicly-documented identifiers, JSON/YAML schema shapes, and algorithm
classifications were used as design references. Full evaluation of these and other reference
repositories: [docs/design/07-ecosystem-factcheck.md §11](docs/design/07-ecosystem-factcheck.md#11-external-reference-repos-evaluated-for-integration-2026-08-local-snapshot).

## csnp/cryptodeps

- **Project:** <https://github.com/csnp/cryptodeps>
- **License:** Apache License 2.0
- **Copyright:** Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
- **Used in:** `packages/qubit-scanner/src/qubit_scanner/deps/crypto_library_map.yaml` — the
  general shape of a "package → known crypto algorithms" curated dataset (package name,
  ecosystem, per-algorithm entries) is adapted from cryptodeps' `data/crypto-database.json`
  schema. QUBIT's version is independently curated (a small, hand-verified subset, not derived
  from or copied out of the upstream dataset) and deliberately schema-differs: entries name
  QUBIT's own canonical algorithm registry identifiers (`qubit_core.algorithms`) and quantum
  vulnerability is resolved through that registry at normalization time, rather than being
  duplicated as a `quantumRisk`/`severity` classification in the data file itself, per QUBIT's
  own "the registry is the single source of truth" design principle
  (`docs/design/01-discovery-inventory.md` §4.2).
- **Used in:** `packages/qubit-scanner/src/qubit_scanner/deps/manifest.py` — the general approach
  (one parser function per ecosystem: `go.mod`, `package.json`, `requirements.txt`/
  `pyproject.toml`, `pom.xml`) mirrors cryptodeps' `internal/manifest/*.go` structure; the
  implementation itself is native Python (stdlib `json`/`tomllib`/`xml.etree`), not a port or
  translation of the Go source.
- **Test fixtures:** `packages/qubit-scanner/tests/test_deps_scanner.py`'s manifest fixtures were
  authored independently but shaped to exercise the same package names (`jsonwebtoken`,
  `bcrypt`, `cryptography`, `PyJWT`, `bcprov-jdk18on`, `jjwt-api`) as cryptodeps' own
  `testdata/fixtures/{npm,python,maven}-project/` test data, used here only as validation
  ground truth during development, not copied into the repository.

## csnp/tls-analyzer

- **Project:** <https://github.com/csnp/tls-analyzer>
- **License:** MIT License
- **Used in:** `packages/qubit-risk/src/qubit_risk/params/cnsa2_milestones.yaml` — the CNSA 2.0
  milestone table (names, deadlines, weights, per-milestone requirements) and the
  approved/transitional/deprecated algorithm classification tables are ported from
  `internal/analyzer/cnsa2.go`'s `CNSA2Milestones`/`CNSA2Approved*`/`CNSA2Transitional`/
  `CNSA2Deprecated` tables, with algorithm names translated to QUBIT's own canonical registry
  identifiers. `packages/qubit-risk/src/qubit_risk/cnsa2.py`'s evaluator logic is an independent
  reimplementation generalized from a single-endpoint scan result to QUBIT's asset-inventory
  model — it is not a line-by-line port of `analyzeMilestone`/`calculateTimelineScore`.

## golang-jwt/jwt and go-jose/go-jose

- **Projects:** <https://github.com/golang-jwt/jwt> (MIT), <https://github.com/go-jose/go-jose>
  (Apache License 2.0, no NOTICE-file obligation — none exists upstream)
- **Used in:** `packages/qubit-core/src/qubit_core/algorithms.py`'s JOSE/JWT canonical algorithm
  entries (`RS256`/`PS256`/`ES256`/`HS256`/`EdDSA` families) and
  `packages/qubit-scanner/src/qubit_scanner/catalog/rules/{go,javascript,typescript}/jwt.yaml`'s
  detection rules — these two independent real-world JWT/JOSE implementations were used to
  cross-verify the RFC 7518 algorithm identifier set and, for the Go rule pack, the exact
  `jwt.NewWithClaims(jwt.SigningMethodRS256, ...)` API shape. No code from either project is
  used; only publicly-documented algorithm name strings and API signatures.

## open-quantum-safe/oqs-provider

- **Project:** <https://github.com/open-quantum-safe/oqs-provider>
- **License:** MIT License
- **Used in:** `docs/design/07-ecosystem-factcheck.md` §2 — cited only, to cross-check
  `packages/qubit-bridge/src/qubit_bridge/registry.py`'s hybrid-TLS-group codepoints
  (`X25519MLKEM768`/`SecP256r1MLKEM768`/`SecP384r1MLKEM1024`) against oqs-provider's
  `ALGORITHMS.md`, and to confirm its documented self-disabling behavior on OpenSSL >= 3.5. Not
  a dependency; QUBIT's hybrid bridge deliberately uses native OpenSSL 3.5+ instead (see that
  doc for the full rationale).
