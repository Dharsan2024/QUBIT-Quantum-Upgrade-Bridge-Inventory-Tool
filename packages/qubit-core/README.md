# qubit-core

Shared foundation for QUBIT: the binding `CryptoAsset` schema, the canonical algorithm registry,
deterministic asset fingerprinting, evidence redaction, and the SQLAlchemy database layer.

Every other QUBIT package depends on this one. The `CryptoAsset` schema defined here is **frozen** —
changes are additive only (see `docs/design/00-architecture-frame.md`).
