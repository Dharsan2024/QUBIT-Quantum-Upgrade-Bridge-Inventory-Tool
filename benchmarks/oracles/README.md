# Four detectors, and an estimate of what all four missed

`benchmarks/recall/` asks: *how much of one oracle's output did QUBIT reproduce?* That question has
a ceiling built into it — it can never see anything the oracle also missed, and both tools missing
the same thing looks identical to neither tool being wrong.

This harness asks the question underneath it:

> Given several independently written detectors, how much cryptography did **none** of them find?

## The detectors

| name | kind | selection | provenance |
|---|---|---|---|
| `qubit` | tree-sitter AST | its own rule pack | this repository, via the public CLI |
| `pqaudit` | 178 regexes | whole pattern file | PQCWorld/pqaudit @ `5e389b2` (MIT) |
| `semgrep` | AST + dataflow | **semgrep's own CWE metadata** | `semgrep/semgrep`, registry packs (LGPL-2.1) |
| `cryptoscan` | pattern tables | whole tool | csnp/cryptoscan @ `11f0e46` (MIT) |

QUBIT is deliberately *not* privileged in the code. It is a `Detector` like the others, and
`population.py` cannot tell which of its inputs is the tool under test. Anything else invites
treating "QUBIT found it" as ground truth, which is the assumption this whole directory exists to
avoid making.

Two choices are worth stating because they are where an evaluation gets quietly rigged:

**Semgrep's rules are selected by semgrep, not by us.** Filtering with a keyword regex over rule IDs
would put QUBIT's author back in charge of deciding what counts as cryptography. The filter is
`metadata.cwe ∈ {326, 327, 328, 347, 916}`. CWE-319 (cleartext transmission) and CWE-330/338 (weak
PRNG) are excluded on the record: both are real findings, neither says which algorithm is in use.

**cryptoscan's `crypto-samples/` are not used as corpus.** They are a detector's own pattern tables
rendered as source files. Scoring QUBIT against them measures agreement with a word list; it
returned 22.3% in an earlier run and the number meant nothing.

## Two corrections that changed the answer

Both were found by running the thing and reading the output, and both moved the result *against*
QUBIT. They are recorded because the corrected numbers are only trustworthy if the uncorrected ones
are visible.

**1. Lines are the wrong unit.** Twelve QUBIT rules carry `dedupe: per-file` deliberately: an
inventory that lists the same `*ecdsa.PrivateKey` twenty times is a worse inventory. Compared
line-by-line against a regex that fires on every line, QUBIT scored **9.5%** and the benchmark had
measured a design decision. The unit is now `(file, algorithm family)`.

**2. A bigger vocabulary is not better detection.** On go-jose, 109 of QUBIT's findings are the
family `JSON WEB TOKEN`, which neither cryptoscan nor pqaudit has any word for. Every one landed in
"found by QUBIT alone", inflated the estimated population, and depressed everyone else's recall:

| | all families | shared vocabulary |
|---|---|---|
| QUBIT sites | 144 | 75 |
| QUBIT-only sites | 91 | 22 |
| agreement with cryptoscan | 27.8% | 51.9% |
| agreement with pqaudit | 28.8% | 52.3% |

The default restricts comparison to families **≥2 detectors can name**. `--all-families` reproduces
the flattering version. Most of QUBIT's apparent lead was vocabulary, and publishing the 144 would
have been the same error as the cryptoscan-samples corpus, pointing the other way.

## The finding: detectors cannot tell a use from a mention

Running four detectors over crypto *tooling* — the codebases most likely to be audited during a PQC
migration — produced a result that no recall number would have shown.

On `tls-analyzer`, QUBIT reports 9 sites and cryptoscan reports 112. Reading the difference:

```go
pkg/types/policy.go:194        BannedAlgorithms: []string{"3DES", "RC4", "MD5", "SHA1"},
internal/analyzer/cnsa2.go:75  "RC4":  "Immediately",
internal/scanner/grade.go:352  if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5") {
```

A ban list. A remediation-deadline table. A weak-signature check. **A project that bans RC4 is
reported as using RC4** — the finding is not merely wrong, it is inverted. Publishing "QUBIT recall
8%" from that comparison would have published a number known to be false.

`adjudicate.py` classifies each detector's exclusive findings by whether the algorithm name appears
anywhere outside quotes on its line. Findings **no other detector reported**:

| corpus | detector | exclusive | code | mention-only |
|---|---|---:|---:|---:|
| tls-analyzer | cryptoscan | 171 | 39 | **132 (77%)** |
| tls-analyzer | pqaudit | 69 | 14 | **55 (80%)** |
| tls-analyzer | qubit | 5 | 5 | 0 |
| cryptodeps | cryptoscan | 406 | 46 | **359 (88%)** |
| cryptodeps | pqaudit | 133 | 32 | **101 (76%)** |
| cryptodeps | qubit | 76 | 3 | **73 (96%)** |
| go-jose | qubit | 252 | 249 | 0 |
| go-jose | pqaudit | 26 | 21 | 5 |

Two things this says, and the second is the one worth having.

**On a real crypto library, QUBIT's advantage is real.** 249 of its 252 exclusive findings on
go-jose are code.

**On crypto tooling, QUBIT was committing the same error.** 73 of 76 exclusive findings on
cryptodeps were mentions, *all* of them from `GO-JWA-WIRE-NAME` — a rule added in the same session
that built this harness, matching any `"RS256"` string anywhere in a Go file. An AST detector that
matches a bare string literal has thrown away the only advantage it has. The benchmark caught it in
its first run against a corpus the rule's author had not thought about.

Fixed by spending the AST advantage instead of asserting it: the string must now be a **call
argument**, a constraint no regex can express. Measured cost — go-jose 45 → 37 detections,
cryptodeps 114 → 2, golang-jwt/jwt 31 → 1. That last one was a real recall loss (golang-jwt defines
its algorithms in composite literals), recovered on precise evidence by a new
`GO-JWA-SIGNING-METHOD` rule: a ban list contains `"RS256"`, never `jwt.SigningMethodRS256`.

`adjudicate.py` itself had the same class of bug and it is worth recording, because it is the reason
to distrust a screening heuristic that has not been checked by hand. It classified on the detector's
`text` field, which adapters truncate to 160 characters — so a long line's closing quote went
missing and `Description: "RSA key is less than 2048 bits…"` scored as *code*. A mention counted as
a use, in the direction that flattered the pattern detectors. It now reads the real line from disk.

## Result on go-jose

Shared vocabulary (AES, EC, HMAC, PBKDF2, RSA, SHA, SHA-1); 75 QUBIT sites, 48 cryptoscan, 56
pqaudit, 2 semgrep.

| method | population | missed by all | QUBIT recall (upper bound) |
|---|---|---|---|
| Chapman, vs cryptoscan | 85.6 [81.0, 91.5] | 4.6 | 87.6% [82.0, 92.6] |
| Chapman, vs pqaudit | 93.2 [86.0, 100.6] | 7.2 | 80.5% [74.5, 87.2] |
| log-linear, 4-source, independent | 93.5 [91.8, 96.9] | 3.5 | 80.2% [77.4, 81.7] |
| log-linear, 4-source, correlated | 96.0 [93.0, 102.2] | 6.0 | 78.1% [73.4, 80.7] |

Four methods converging on 78–88% is worth more than any one of them.

## How to read the numbers

Every figure is a **floor on the population** and therefore a **ceiling on recall**. Detectors are
positively correlated — they are all written from public documentation of the same libraries — which
inflates the overlap, deflates the estimated population, and inflates recall.

`population.py` measures how badly, rather than asserting it. Simulating 1 000 sites split into an
easy half and a hard half, against a *known* true N:

    2-source Chapman ................ 593
    3-source, independence .......... 630
    3-source, one interaction ....... 640
    3-source, two interactions ...... 653

Every estimator lands far low. Modelling the correlation moves the right way without closing the
gap. So the claim is deliberately narrow: **recall measured against a union of detectors is
optimistic, and this is a lower bound on by how much.** `test_population.py` fails if this module
ever starts claiming more.

## Running it

```bash
docker pull semgrep/semgrep                                    # digest pinned in semgrep_oracle.py
docker build -t qubit-bench-cryptoscan:11f0e46 "git help/cryptoscan"

uv run python benchmarks/oracles/run_multi.py "git help/go-jose" --name go-jose
uv run python benchmarks/oracles/run_multi.py "git help/vault"   --name vault --json vault.json
uv run pytest benchmarks/oracles/test_population.py -q
```

An unavailable detector is reported as unavailable and never as having found nothing — zero
findings and zero capability look the same in a table and mean opposite things.

Semgrep runs with `--metrics=off`. This harness is a development tool and ships in no release, but
a benchmark that posted match counts to a vendor while measuring an offline guarantee would be a
poor joke.
