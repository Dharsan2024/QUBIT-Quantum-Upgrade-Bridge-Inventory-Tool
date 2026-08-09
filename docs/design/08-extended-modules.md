# 08 — Extended Modules: Literature-Survey Coverage & Additive Feature Designs

**Subsystem:** cross-cutting (touches `qubit-migrate`, `qubit-api`, `qubit-core`, `dashboard/`)
**Status:** Design v1 — additive to the binding frame (`00-architecture-frame.md`); the `CryptoAsset`
schema stays FROZEN, every design below is additive (new params files, new read models, new endpoints,
new dashboard surfaces — no changes to the binding schema or the normative decisions of docs 00–07).
**Authors:** QUBIT team (Dharsan L, Akshay Kumar S)
**Date:** 2026-08-09

This document folds the **literature survey** (16 papers → 12 thematic modules M1–M12, plus the
feature-comparison and gap tables) into the QUBIT design. It does two things:

1. **§1 — Coverage map.** For every survey module M1–M12, state what QUBIT *already* delivers and in
   which package, so the survey's positioning of QUBIT as the *unified* PQC-migration platform is
   grounded in shipped code, not aspiration.
2. **§2 — Additive designs (E1–E5).** For the handful of features the survey implies but QUBIT has not
   yet *surfaced*, give an implementable additive design (purpose, data/params, API endpoint in the
   doc-05 registry style, dashboard surface, and — crucially — how it reuses code that already exists).

**§3** records the one module deliberately scoped out (M11, hardware PQC library implementation) and why.

> This is a **design/tracking** document. Building E1–E5 is future work tracked by
> [BUILD_PLAN.md](../BUILD_PLAN.md) (its "Literature-grounded module coverage" table and the M3/M4
> scope). Nothing here is implemented yet; where a design says "reuse X", X is verified to exist in the
> repo today (paths are real).

---

## 1. Literature-survey → QUBIT module map

The survey groups the field into twelve capability areas. QUBIT already satisfies the large majority of
them; the "Status" column is honest — `built` means shipped + tested, `partial` means the capability
exists but is not fully surfaced/hardened, `new` means it is designed here (E1–E5) and not yet built.

| # | Survey module (capability) | QUBIT status | Where it lives (verified path) |
|---|---|---|---|
| M1 | **Cryptographic discovery / inventory** (source, config, network, cert/key) | **built** | `packages/qubit-scanner/` (code AST via tree-sitter, config, active TLS enumeration, cert/key) |
| M2 | **CBOM generation** (machine-readable crypto bill of materials) | **built** | `packages/qubit-core/.../cbom/export.py` — CycloneDX 1.7 |
| M3 | **Quantum-risk quantification** (when is crypto breakable) | **built** | `packages/qubit-risk/.../timeline/` — Monte-Carlo CRQC surface-code timeline + survey-blend |
| M4 | **HNDL / data-shelf-life risk model** (harvest-now-decrypt-later) | **built** | `packages/qubit-risk/.../hndl.py` — closed-form P_HNDL + `HndlBayesNet` (pgmpy) |
| M5 | **Migration dependency analysis** (what must migrate before what) | **partial** → **E3** | `packages/qubit-migrate/.../graph/{builder,order}.py` exists; **not surfaced** via API/UI |
| M6 | **Governance & operational workflow** (approval, ownership, CI/CD) | **partial** → **E4** | migrate review/approve endpoints + the new CI workflow exist; no governance layer |
| M7 | **Crypto agility** (policy for hybrid-vs-pure, which PQC to adopt) | **partial** → **E2** | replacement mapping exists in the registry + rule `pqc_target`; no explicit agility *policy* |
| M8 | **Automated remediation / code transformation** (patch generation) | **built** | `packages/qubit-migrate/.../transform/` — Ollama LLM + deterministic template codemods |
| M9 | **Patch validation / safety gating** (a bad patch can never merge) | **built** | `packages/qubit-migrate/.../transform/validate.py` + docker sandbox — 5-stage pipeline |
| M10 | **Hybrid PQC deployment / runtime proof** (prove the migration on the wire) | **built** | `packages/qubit-bridge/` — X25519MLKEM768 probe/verify against the demo-lab bridge |
| M11 | **PQC library implementation on constrained/embedded (ARM) targets** | **out of scope** (§3) | — (hardware impl; not a software-migration-platform concern) |
| M12 | **Prioritization / risk-ranked scheduling** (do the worst first) | **built** | `packages/qubit-migrate/.../queue/{effort,priority}.py` — risk÷effort WSJF over the ready frontier |
| — | **Algorithm recommendation surfaced per-asset** (survey feature-table cell) | **partial** → **E1** | data in rule `target`/`pqc_target`/`semantic_note` + `MigrationAnnotation.recommendation`; not exposed as its own read model |

**Reading of the map:** eight of twelve modules (M1–M4, M8–M10, M12) are shipped and tested today. Three
(M5, M6, M7) exist as internal capability but are **not surfaced** — the survey's feature table would
mark them absent because a user cannot *see* or *drive* them from the product surface. E1–E5 close exactly
that surfacing gap; none of them require new research, and all of them reuse code that already exists.

---

## 2. Additive designs (E1–E5)

Common rules for all five (frame-conformant):

- **Frozen-schema-safe.** No change to `CryptoAsset` or to doc-05 §4.1's binding models. New knowledge
  lives in **versioned params files** (`packages/qubit-*/…/params/*.yaml`, hashed into
  `RiskRun.params` / migration engine-version records for reproducibility, per frame N8) and in
  **additive read models** returned by new endpoints.
- **Registry-conformant.** Every new endpoint is proposed for doc-05 §5.1 (the single normative REST
  registry). Cross-references are added to docs 03 and 05; this doc does not define competing shapes.
- **Reuse-first.** Each design names the existing function it wraps. The point of E1–E5 is *exposure*,
  not reinvention.

### E1 — Algorithm Recommendation (per-asset PQC target + rationale + library)

**Survey ref:** feature-comparison table cell "recommends a concrete PQC target per asset" (papers on
crypto-agility & migration tooling). **Why it's a gap:** QUBIT already *decides* a target internally
(the migration rule's `target`/`pqc_target` + `MigrationAnnotation.recommendation`, e.g.
`"RSA-2048 kex → ML-KEM-768 (hybrid X25519+ML-KEM-768)"`), but there is no first-class, explainable
**recommendation read model** a user can query per asset without opening a migration item.

**Design (additive):**
- **Read model** (returned by the API; not a DB table — a projection):
  ```
  AssetRecommendation:
    asset_id: UUID
    current: {algorithm, key_size, usage_context, quantum_vulnerable, attack}
    target:  {algorithm, mode: "pure"|"hybrid", parameter_set}   # e.g. ML-KEM-768, hybrid
    library: {name, min_version}                                 # from the KB (E5): pyca cryptography>=49, BC>=1.79
    rationale: str                                               # human sentence + FIPS ref
    source: "rule"|"kb"|"agility-policy"                         # provenance of the pick (E2/E5)
    confidence: float                                            # rule-match confidence
  ```
- **Endpoint (proposed for doc-05 §5.1):** `GET /assets/{aid}/recommendation` → `AssetRecommendation`
  (🔑ro). Pure read; assembled from the migration rule that matches the asset's canonical algorithm +
  `usage_context`, enriched by the migration KB (E5) and the agility policy (E2).
- **Reuse:** the rule-matching already done by `qubit_migrate.transform.rules` (canonical algorithm +
  `usage_context` → rule); `MigrationAnnotation.recommendation` for the human string; the algorithm
  registry (`qubit_core.registry`) for the canonical PQC replacement.
- **Dashboard surface:** a **Recommendation** cell/badge in the Inventory drawer (doc-05 §6.7 page 2)
  and on the Migration detail header — "→ ML-KEM-768 (hybrid) · pyca cryptography≥49" with a tooltip
  carrying the rationale. No new page.

### E2 — Crypto Agility Engine (agility policy: hybrid-vs-pure, which PQC to adopt)

**Survey ref:** M7 (crypto-agility papers). **Why it's a gap:** the *replacement mapping* exists, but
the **policy** — "adopt hybrid X25519MLKEM768 for KEX during the transition; pure ML-DSA-65 for new
signatures; category-3 parameter sets by default" — is implicit in scattered rule fields, not a single
inspectable, versioned artifact. Crypto agility as the survey means it is *the ability to state and
change that policy*, which QUBIT cannot currently express as data.

**Design (additive):**
- **Versioned params file** `packages/qubit-migrate/src/qubit_migrate/params/agility_policy.yaml`:
  ```yaml
  version: "2026.08"
  defaults:
    kex:        {mode: hybrid, target: ML-KEM-768,  hybrid_group: X25519MLKEM768, category: 3}
    signature:  {mode: pure,   target: ML-DSA-65,   category: 3}
    encryption_at_rest: {target: AES-256, note: "Grover → double symmetric key size"}
  overrides:                     # context/sensitivity-scoped exceptions
    - match: {usage_context: token, sensitivity: credentials}
      set:   {mode: pure, target: ML-DSA-65}
  ```
- **Resolver (pure function, deterministic):**
  `resolve_target(asset, policy) -> {mode, target, parameter_set, hybrid_group, rationale}`.
  It is the single authority E1 calls to decide the target when a specific rule does not pin one.
- **Reuse:** feeds E1's `target`/`library` fields; the registry stays the source of canonical names.
  The policy file's hash is recorded in the migration engine-version record (reproducibility, N8).
- **API/UI:** read-only `GET /meta/agility-policy` (🔑ro) so the dashboard Settings page can display the
  active policy version + table. Editing the policy is a params-file change (git-reviewed), **not** a
  runtime mutation endpoint — keeps it reproducible and auditable. **Never-cut** (small, high-leverage).

### E3 — Dependency Graph, surfaced (viz + API)

**Survey ref:** M5 (dependency-analysis papers). **Why it's a gap:** `build_dependency_graph` and
`migration_order` already run inside the planner
(`packages/qubit-migrate/src/qubit_migrate/graph/{builder,order}.py`, verified present) to compute the
dependency-safe `order_index`, but the graph itself is **internal-only** — the user sees a flat ordered
queue, never the structure that produced it. The survey treats the *visible* dependency graph as a
first-class capability.

**Design (additive):**
- **Endpoint (proposed for doc-05 §5.1):** `GET /plans/{plan_id}/graph` (🔑ro) →
  ```
  { nodes: [{id, asset_id, algorithm, usage_context, risk_score, unit_id, order_index}],
    edges: [{source, target, kind, confidence}],   # kind: keygen-before-use | shared-cert | lib-upgrade | encrypt_decrypt_pair | ...
    units: [{unit_id, members: [node_id], is_cycle}] }
  ```
  A pure read — serialize the already-built `nx.DiGraph` + SCC condensation (an `export.py` in `graph/`
  is the natural home, matching the doc-03 component list which already lists `graph/export.py` as
  "JSON / DOT / dashboard payloads").
- **Reuse:** `graph.builder.build_dependency_graph`, `graph.order` (SCC condensation + topo order + ready
  frontier) — no new graph logic, only a serializer.
- **Dashboard surface:** a **Dependency Graph** tab on the Migration queue page — a directed-graph view
  (nodes colored by risk, edges labeled by kind, cycles boxed as migration units). Clicking a node opens
  that asset's migration detail. This is **cut-line-eligible** (the JSON endpoint is cheap and
  paper-relevant even if the interactive viz is deferred).

### E4 — Governance & Operational Workflow (approval gates, ownership, CI/CD validation)

**Survey ref:** M6 (governance/operationalization paper). **Why it's a gap:** QUBIT has *technical*
review (generate → approve/reject → apply → verify, doc-03 state machine) and now a **CI/CD validation
hook** (the `.github/workflows/ci.yml` added in M3 that runs ruff+mypy+pytest+dashboard build), but no
**governance layer**: no notion of an approver identity/role, a required sign-off before apply, or a
policy gate ("assets with sensitivity∈{phi,financial} require two approvals"). The survey positions
governance as what makes a migration *operable in an organization*, not just technically correct.

**Design (additive, layered over the existing FSM — no FSM rewrite):**
- **Additive migration-event metadata** (doc 03 owns the migration tables; this is additive columns/JSON
  on `MigrationEvent`, not a schema break): `actor` (token name from `ApiToken`), `role`, and a
  `governance` blob on approve/apply events.
- **Policy gate** `params/governance_policy.yaml` (versioned):
  ```yaml
  version: "2026.08"
  gates:
    - match: {sensitivity: [phi, financial]}
      require: {approvals: 2, apply_scope: rw}
    - match: {default: true}
      require: {approvals: 1}
  ```
  Evaluated in the existing `apply` guardrail path (doc-05 §6.5) — *before* the write — as an additional
  precondition alongside `allow_apply` + `X-Qubit-Confirm`. A failed gate returns `409 governance_gate`
  with the unmet requirement.
- **Endpoint additions (proposed):** the existing `/migrations/{mid}/approve` records the actor; a new
  `GET /migrations/{mid}/governance` (🔑ro) returns the gate state ("1 of 2 approvals; blocked on
  second sign-off"). **Document** the CI/CD hook (already shipped) here as the automated-validation half
  of governance.
- **Dashboard surface:** an approvals strip on the Migration detail page (who approved, what's still
  required) + a red "blocked by governance policy" state on Apply. **Cut-line-eligible** below single-
  approval (the single-approval + actor-logging core is cheap; multi-approval + role policy can defer).

### E5 — Migration Knowledge Base (vuln-algo → PQC target + library + guidance)

**Survey ref:** M2/M11-survey (migration-guidance papers). **Why it's a gap:** the mapping "this weak
algorithm → this PQC target → this library ≥ this version → this guidance note" exists today only as
prose scattered across rule `semantic_note` fields. It is neither consolidated nor independently
queryable, so it can't power E1/E2 cleanly or be cited as a coverage artifact.

**Design (additive):**
- **Versioned params file** `packages/qubit-migrate/src/qubit_migrate/params/migration_kb.yaml`:
  ```yaml
  version: "2026.08"
  entries:
    - vuln: {family: RSA, usage_context: kex}
      target: {algorithm: ML-KEM-768, mode: hybrid, hybrid_group: X25519MLKEM768, category: 3, fips: FIPS-203}
      library: {python: {name: cryptography, min_version: "49"}, java: {name: bouncycastle, min_version: "1.79"}}
      guidance: "KEX is HNDL-exposed; adopt hybrid during transition. Do not inject liboqs-python into target repos (offline-sandbox break)."
    - vuln: {family: ECDSA, usage_context: signature}
      target: {algorithm: ML-DSA-65, mode: pure, category: 3, fips: FIPS-204}
      library: {python: {name: cryptography, min_version: "49"}, java: {name: bouncycastle, min_version: "1.84"}}
      guidance: "No mainstream JOSE lib registers an ML-DSA alg in 2026 — patch the signing primitive, not the JOSE layer."
  ```
  (Entries are the single source; the migration rule pack's `semantic_note` becomes a *reference* to a KB
  entry rather than duplicating prose — a later refactor, not a rule-pack rewrite.)
- **Reuse / consumers:** E1 (`library`, `rationale`), E2 (agility resolver reads KB defaults), and the
  rule pack (dedup its notes against the KB). The KB file hash goes into the engine-version record (N8).
- **API/UI:** `GET /meta/migration-kb` (🔑ro) so the dashboard can render a "PQC migration reference"
  table (Settings or a docs panel). **Never-cut** — it is the substrate E1/E2 stand on, and it doubles
  as a citable artifact for the paper's coverage claim.

**Dependency order among E1–E5 (for implementation sequencing):** **E5 (KB)** and **E2 (agility policy)**
are the substrate → **E1 (recommendation)** consumes both → **E3 (graph)** and **E4 (governance)** are
independent of E1/E2/E5 and can land in any order. BUILD_PLAN folds E5+E2+E1 into M3 (never-cut) and
E3+E4 into M3/M4 as cut-line-eligible.

---

## 3. Explicit non-goal — M11 (PQC library implementation on ARM/embedded)

The survey's module M11 covers **implementing** PQC primitives on constrained/embedded (e.g. ARM
Cortex-M) hardware — cycle counts, stack usage, side-channel-hardened assembly. **QUBIT does not do
this, by design:**

- QUBIT is a **software-migration platform**: it *discovers* crypto, *quantifies* HNDL risk,
  *recommends + generates + validates* migrations, and *proves* the hybrid deployment on the wire. It
  consumes vetted PQC implementations (native OpenSSL 3.5 for the bridge; pyca `cryptography`≥49 /
  BouncyCastle≥1.79 in generated patches) — it does not author primitive implementations.
- Embedded PQC implementation is a **hardware / cryptographic-engineering** discipline with its own
  toolchain and threat model (constant-time, fault-injection). Claiming it would be exactly the kind of
  unverifiable stretch the project's honesty discipline forbids.

We therefore record M11 as an **acknowledged, deliberate non-goal**, cite the standard reference
implementations QUBIT *targets* (so a reader knows where the implemented primitives come from), and note
it as clearly-scoped future work for a different kind of project — not a QUBIT gap.

---

## 4. Cross-references

- The binding schema and normative decisions these designs respect: [00-architecture-frame](00-architecture-frame.md).
- Dependency graph internals reused by E3, and the migration state machine E4 layers over:
  [03-migration-orchestrator](03-migration-orchestrator.md) (see its "M3+ extension" subsections).
- The normative REST registry the E1/E3/E4 endpoints are proposed into, and the dashboard pages E1–E4
  surface on: [05-platform-api-dashboard](05-platform-api-dashboard.md) (see its "Extended-module
  endpoints (M3+)" additions).
- Tracking + acceptance + cut-lines for building E1–E5: [BUILD_PLAN.md](../BUILD_PLAN.md).
- Where the project stands overall (completion, production-readiness, improvements):
  [PROJECT_STATUS_REPORT.md](../project-status/PROJECT_STATUS_REPORT.md).
