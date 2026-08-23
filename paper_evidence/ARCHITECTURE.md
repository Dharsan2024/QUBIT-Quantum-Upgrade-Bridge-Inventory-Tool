QUBIT is a native Windows desktop application over a local HTTP engine. Nothing
it does requires a network service the user did not name: discovery, risk, transformation and
verification all run on the machine, against a local model, writing to one SQLite file. That is
a structural property rather than a policy — the engine binds to `127.0.0.1`, and the shell
bundles the dashboard instead of serving it.

## Layers

**Interface.** A Tauri 2 shell hosts the React dashboard; `qubit-cli` offers the same operations
without a window, for scripting and for reproducing a run from a shell.

**Service.** `qubit-api` is a FastAPI application bound to loopback, with bearer-token
authentication and rate limiting. It is the only writer the interface layer talks to.

**Engine.** Four packages, none of which knows about the others except through the inventory:

* `qubit-scanner` — 6 independent discovery sources (AST, configuration,
  live TLS, certificates, dependency manifests, HashiCorp Vault), driven by a data-only rule
  catalog: **268 rules compiled into 307 language bindings across
  19 tree-sitter grammars**, plus a package→algorithm map covering
  **903 packages**.
* `qubit-risk` — CRQC Monte-Carlo, Mosca inequality, CNSA 2.0 milestone evaluation.
* `qubit-migrate` — plan, patch, and a validation gate that must pass before a patch is offered.
* `qubit-bridge` — hybrid TLS handshake verification.

**Foundation.** `qubit-core` owns the frozen `CryptoAsset` schema, the canonical registry of
**150 algorithms**, the database, CycloneDX 1.7 CBOM export, and report rendering.
Every other package depends on it and it depends on none of them at run time.

## The one edge that looks like a cycle

`qubit-core/alembic/env.py` imports the migration models so a single Alembic `target_metadata` sees
all 12 tables. It is an import for schema registration, not a runtime dependency, and
F02 draws it dotted for that reason. The 171 runtime edges point strictly
downward.

## Rules are data, not code

The detection catalog is YAML validated against a `qubit-rule/v1` schema, not Python. A new rule is
a file, and every rule ships its own positive and negative fixtures which run as tests. This is why
the rule set can be counted, versioned and audited — and why the counts above are read from the
catalog at build time rather than typed into this document.

## Storage

One SQLite database in WAL mode, 12 tables (F05). The inventory is the single source of
truth: risk and migration annotate the same `assets` row rather than keeping a second copy, so a
finding cannot be current in one view and stale in another.
