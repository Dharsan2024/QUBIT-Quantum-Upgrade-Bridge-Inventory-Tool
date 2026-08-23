# T12_site_collapse — Overlapping-rule reconciliation (qubit_scanner.code.scanner::_one_per_site)

One call is one cryptographic fact however many rules recognise it. The catalog deliberately overlaps — a generic `Signature.getInstance(<alg>)` rule for coverage and a specific ML-DSA rule that carries the migration example — and before this both reached the inventory, inflating every count taken over it. Specificity is the number of `where` constraints; ties break on confidence and then rule id, so the inventory does not depend on catalog iteration order. Comparison is on the **resolved** algorithm, so `Dilithium3` and `ML-DSA-65` collapse together.

| case | rule A constraints | A confidence | rule B constraints | B confidence | kept |
|---|---|---|---|---|---|
| generic vs PQC-specific, same name | 2 | high | 3 | high | the specific rule |
| generic vs PQC-specific, alias name | 2 | high | 3 | high | the specific rule |
| same specificity, different confidence | 3 | medium | 3 | high | the higher confidence |
| identical on both | 3 | high | 3 | high | the lower rule id (deterministic) |
| more constrained but lower confidence | 2 | high | 4 | low | the more constrained rule |
