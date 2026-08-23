# Construct mapping — QUBIT against CryptoAPI-Bench

**Written before any score was computed. Not revised afterwards.**

CryptoAPI-Bench (Afrose et al., SecDev 2019; MIT) is a benchmark for cryptographic **misuse**
detection. QUBIT is a cryptographic **inventory** tool aimed at post-quantum migration. Those are
not the same construct, and scoring one against the other without saying how is the kind of
comparison this project exists to avoid. This document fixes the mapping in advance.

## Why use it at all

Every hand label in this study's corpus evaluation was produced by a language model or by the one
annotator who supervised it. That is the single largest threat to the evaluation's validity.
CryptoAPI-Bench's ground truth was produced by other people, published, and peer-reviewed, and it
is the same benchmark CryptoGuard and CogniCrypt report against — so a number computed here is
both independent of this project and comparable to prior work.

## The predicate

A benchmark row says `vulnerable = true|false` for a named file. QUBIT does not emit a
"vulnerable" verdict per file; it emits assets, each carrying `quantum_vulnerable.vulnerable`
from the canonical algorithm registry.

**The mapping is:** QUBIT is scored positive on a case if it reports at least one asset in that
case's file(s) whose registry entry is `vulnerable = True`. Negative otherwise.

* **true positive** — benchmark says vulnerable, QUBIT reports a vulnerable asset
* **false negative** — benchmark says vulnerable, QUBIT reports nothing vulnerable
* **false positive** — benchmark says secure, QUBIT reports a vulnerable asset
* **true negative** — benchmark says secure, QUBIT reports nothing vulnerable

Line numbers are recorded but **not** required to match. The benchmark's line column was partly
destroyed by Excel (see `convert.py`), the misuse frequently spans several lines, and 20 cases span
two files. Requiring a line match would measure the spreadsheet, not the detector. Line agreement is
reported separately as a secondary figure.

## Categories, fixed in advance

### A — In scope, strict. QUBIT is expected to get these right.

Weak-algorithm identity, which is exactly what an inventory tool is for:

| benchmark type | QUBIT's route |
|---|---|
| `MD5 used`, `SHA1 used` | `JAVA-JCA-MESSAGEDIGEST-BROKEN` |
| `MD4 used`, `MD2 used` | in the registry; **see the known gap below** |
| `DES used` | `JAVA-JCA-CIPHER-DES` |
| `RC4 used`, `Blowfish used`, `RC2 used`, `IDEA used` | `JAVA-JCA-CIPHER-LEGACY-STREAM` |
| `HmacMD5`, `HmacSHA1` | `JAVA-JCA-MAC` |

Their `...Corrected` counterparts use AES and SHA-256, which the registry marks not vulnerable, so
a correct tool is silent on them. Those cases are the precision half of the benchmark.

### B — In scope, but the two constructs provably differ. Reported separately, never pooled.

| benchmark type | why |
|---|---|
| `RSA keysize 1024 bits` | The benchmark's secure counterpart is RSA-2048. QUBIT marks **both** quantum-vulnerable, because Shor breaks RSA at any modulus size. QUBIT is *right* by its own construct and *wrong* by the benchmark's. |

This is a definitional disagreement, not a detector error, and pooling it into one precision figure
would hide the most interesting thing the comparison shows. Scored and reported on its own.

### C — Out of scope, declared in advance. Counted as neither hit nor miss.

QUBIT does not model these, by design, and a benchmark row testing them says nothing about
inventory quality:

| benchmark type | why out of scope |
|---|---|
| `Usage of ECB` | A cipher **mode**. QUBIT resolves `AES/ECB/PKCS5Padding` to the algorithm AES; mode weakness is not an inventory property. |
| `Constant Seed`, `Usage of Random Method from Library` | PRNG seeding quality, not an algorithm identity. |
| `PBE iteration < 1000` | A parameter threshold. QUBIT detects PBKDF2, not whether its iteration count is adequate. |
| `HTTP` | Absence of cryptography, not presence of it. |
| `Dummy Certificate`, `Dummy Verifier`, `Socket Hostname w/o verification` | TLS trust-validation logic, not cryptographic inventory. |
| `Credential in String`, `Static/Constant Key`/`Password`/`IV`/`Salt` | Handled by QUBIT's **secrets** pass rather than its code pass. Scored as a **separate** secondary experiment, because pooling a secrets result into a crypto-detection precision would repeat exactly the error this project already caught once. |

Reporting the out-of-scope share honestly is part of the result: a tool that covers 12 of 28
benchmark categories should say so rather than quietly scoring only the ones it wins.

## A coverage gap, recorded before scoring

Reading `java/jca.yaml` while writing this document — **not** from any score — shows
`JAVA-JCA-MESSAGEDIGEST-BROKEN` matching `^"(MD5|SHA-?1)"$`. `MD4` and `MD2` are in the canonical
registry and are marked vulnerable, but no Java rule matches them, so the 12 `MD4 used` / `MD2 used`
cases cannot be detected.

It is recorded here, before the first score, so that the baseline is honest. The plan is: score,
publish the baseline, fix the rule, re-score, and publish both figures as a before/after. A fix
applied before the baseline exists would be fitting to the test set.

## Known defects in the benchmark itself

Reported because a reader deserves to know the ground truth is not perfect either:

* **18 of 182 rows had their line numbers converted to dates by Excel** (`9,12` → `2019-09-12`).
  Repaired in `convert.py`, flagged per row as `line_repaired`.
* **12 rows omit the `.java` extension** — all of them `...Corrected`, i.e. the entire secure half.
* **20 rows name two files in one cell**, separated by a newline; the misuse spans both.
* **2 rows name a file that is not in the repository** (`CredentialInStringBBCase2.java`,
  `PredictableSeedsABPMCase2.java`). Excluded, and counted in the report.

## What this experiment cannot show

CryptoAPI-Bench is Java-only, synthetic, and built around classical misuse. A good score here is
evidence about QUBIT's Java rules on small, purpose-built files. It is **not** evidence about the
other 18 grammars, about real repositories, or about post-quantum readiness — the 26-repository
corpus is what speaks to those, and the two results are reported side by side rather than merged.
