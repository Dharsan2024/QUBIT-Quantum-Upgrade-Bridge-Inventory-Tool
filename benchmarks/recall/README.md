# Detection recall, measured against an independent detector

QUBIT's central claim is an inventory: *here is the cryptography in your codebase.* A test suite
written by the same person who wrote the rules cannot check that claim. A rule that fails to match
something also fails to notice it should have, and its fixtures are written from the same
understanding that produced the gap.

That is not hypothetical. Every detection gap found in this project so far surfaced **by accident**,
from the migration side, when a patch was rejected for a reason that turned out to be the scanner's
fault:

| Gap | How it was found | Consequence |
|---|---|---|
| `SWIFT-CRYPTOKIT-STRONG`'s title advertises `AES.GCM.seal`; its query cannot match it | a Swift migration produced correct CryptoKit and was rejected for "no AES present" | every CryptoKit AEAD call invisible |
| Both Swift CryptoKit rules blind to `try!` | widening the rule above | every force-tried crypto call invisible — idiomatic Swift |
| Every strong .NET class (`Aes`, `AesGcm`, `SHA256`) unmatched in PowerShell | a PowerShell 3DES→AES migration could not be confirmed | no PowerShell cipher migration verifiable |

None was caught by a test. So this harness asks a detector QUBIT did not write.

## Method

**Oracle.** [`pqaudit`](https://github.com/PQCWorld/pqaudit) (PQCWorld, MIT) ships
`rules/crypto-patterns.yaml`: 28 rules and 178 regular expressions naming the cryptographic APIs an
independent team decided were worth detecting. `oracle.py` applies those patterns, unmodified, to
real third-party source. Patterns that will not compile under Python's `re` are dropped rather than
rewritten — a pattern reinterpreted by QUBIT's author is no longer independent evidence.

**Corpus.** Real, third-party projects, each pinned to an upstream commit. They are not vendored
into this repository; clone them into `git help/` to reproduce.

| Repository | Commit | Why |
|---|---|---|
| [go-jose/go-jose](https://github.com/go-jose/go-jose) | `8d4e64d` | JOSE/JWT, dense in algorithm identifiers |
| [golang-jwt/jwt](https://github.com/golang-jwt/jwt) | `1a11d37` | the other major Go JWT library |
| [hashicorp/vault](https://github.com/hashicorp/vault) | `744b611b` | large real system, ~4 700 source files |
| [open-quantum-safe/oqs-provider](https://github.com/open-quantum-safe/oqs-provider) | `7e70df2` | C, and post-quantum rather than classical |
| [csnp/cryptoscan](https://github.com/csnp/cryptoscan) | `11f0e46` | ships deliberate multi-language crypto samples |
| [PQCWorld/pqaudit](https://github.com/PQCWorld/pqaudit) | `5e389b2` | **the oracle**, not scanned |

**Unit of comparison.** Per `(file, algorithm family)` — the claim an inventory actually makes:
*this file uses ECDSA.* Twelve QUBIT rules carry `dedupe: per-file`, deliberately, because an
inventory that lists the same `*ecdsa.PrivateKey` twenty times is a worse inventory, not a more
complete one. The first run of this harness compared line by line against a regex that fires on
every line, scored **9.5%**, and measured nothing but that design decision. Line-level agreement is
still printed, labelled for what it is.

Families are coarse (`RSA-2048` and `RSA` compare equal, `ECDSA`/`ECDH`/`Ed25519` all fold to `EC`)
because the question is whether QUBIT saw the cryptography at all, not whether the two tools agree
on parameters.

## What the numbers do and do not mean

Recall here is **against this oracle's vocabulary**, not against all cryptography. Neither tool is
treated as correct:

- **Both** — two independently written detectors agreeing is the strongest available evidence that
  something is really there.
- **Oracle only** — QUBIT's candidate misses. *Candidates*, because a regex over source text cannot
  tell a call from a string. Adjudicating go-jose's misses by hand: a benchmark named
  `BenchmarkEncryptAES256_CBCHMAC_64k` matched as ECDSA (`ES256` inside `AES256`), a base64
  certificate blob matched as 3DES, and the string `"Should reject AES-128 with 32-byte key"` inside
  a test assertion. Those are the oracle's false positives, not QUBIT's misses.
- **QUBIT only** — sometimes its parser reaching where a line-level pattern cannot (a digest named
  through a variable, `HashAlgorithm.Create(algo)`), sometimes vocabulary the oracle lacks, and
  sometimes QUBIT's own false positives. Printed, not assumed.

## Result on go-jose, and the gaps it found

Each row is a real defect this harness surfaced, then fixed.

| | recall | oracle-only (misses) |
|---|---|---|
| before | 52.6% | 27 |
| + `ecdsa.GenerateKey` detected | 59.6% | 23 |
| + JWA algorithm identifiers detected | **78.9%** | **12** |

1. **`ecdsa.GenerateKey` was matched by nothing** — the standard way to create an ECDSA key in Go.
   `GO-CRYPTO-DSA-GENERATEKEY` even carries it as its *negative* example, so the rule pack documented
   that ecdsa is not dsa and then never added the rule that catches ecdsa.
2. **`crypto.SHA256` and its siblings were unmatched.** Go names a hash twice — the package that
   implements it and the `crypto.Hash` constant that selects it. Real code selects far more often
   than it imports: `NewConcatKDF(crypto.SHA256, …)`, `priv.Thumbprint(crypto.SHA256)`. A file
   choosing SHA-1 for a signature read as having no hash at all.
3. **JWA algorithm identifiers were unmatched** — 17 of the 23 misses remaining at step 2. QUBIT's
   JWT rules matched exactly one call shape from one library, so `jose.RS256`,
   `[]SignatureAlgorithm{RS256, ES256}` and `KeyAlgorithm("RSA-OAEP")` — the way go-jose itself
   names algorithms — all fell through. The registry already knew the whole vocabulary and rated it
   correctly; only the detection was missing.

## Running it

```bash
uv run python benchmarks/recall/run.py "git help/go-jose" --name go-jose
uv run python benchmarks/recall/run.py "git help/vault" --name vault --json vault.json
```

`--show N` prints N disagreements per side for adjudication; `--json` writes every disagreement so
the adjudication can be redone or checked by someone else.

## Attribution

`oracle.py` reads pqaudit's `rules/crypto-patterns.yaml` at run time. Nothing from pqaudit is
vendored, modified or redistributed here. pqaudit is MIT licensed, © PQCWorld.
