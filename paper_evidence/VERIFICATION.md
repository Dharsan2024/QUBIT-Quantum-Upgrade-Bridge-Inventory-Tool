# Verification

## Test suites, by kind

| suite | files | cases | what it can catch |
|---|---|---|---|
| Python unit + integration | 77 | 640 | logic, schema, FSM transitions, API contract, scanner rules, codemod output, and every regression pinned after a real defect |
| Benchmark / oracle | 4 | 84 | changes to detector agreement, the screening classifier, and the capture-recapture estimator |
| Browser end-to-end (Playwright) | 7 | 34 | rendering, real API wiring, and WCAG 2.2 AA conformance — things no unit test can observe |

Line + branch coverage over `packages/`: **85.6%** (15,215 statements, 1,785 uncovered, 3,030 branches).

## Security testing

The system rewrites source code and reads whole repositories, so its own attack surface is part of the claim. The API was probed live rather than reviewed on paper; both findings below were fixed and pinned by a regression test.

| probe | result |
|---|---|
| Unauthenticated access, bad token, empty token | rejected (401) |
| Path traversal in scan targets (`../../`, UNC, `/etc/passwd`) | rejected - target must exist and stay inside the configured roots |
| Command injection via git-URL targets (`;`, `&&`, backticks, `--upload-pack`) | not exploitable - the clone is `subprocess` with an argument list, never a shell |
| SQL injection on query parameters | rejected at the type boundary (UUID/int parsing) before any query is built |
| Stack traces or internals in 4xx bodies | none |
| TRACE / TRACK | 405 |
| **SSRF to cloud instance metadata (169.254.169.254)** | **was allowed — FIXED** |
| **Baseline security headers** | **were absent — FIXED** |

**SSRF to the metadata service.** Python's `ipaddress.is_private` returns true for link-local (169.254.0.0/16), so the network scanner's "local targets need no authorization" rule auto-allowed `169.254.169.254` — the AWS/Azure/GCP instance-metadata endpoint, and the standard pivot for stealing instance credentials. Measured against the running app: the scan was accepted and reported `succeeded`, while `8.8.8.8` and `example.com` were correctly refused. Link-local is now excluded from the auto-allow and needs the same explicit allowlist entry plus `authorized` flag as any other off-network target (`test_network_auth.py::TestLinkLocalIsNotTreatedAsSafeLocal`).

**Response headers.** No `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` or `Referrer-Policy` on any response — and the API serves the dashboard itself in desktop mode, so those land on HTML a real browser engine renders. All four are now set, with a CSP that forbids framing, objects, base-URI rewriting and `unsafe-eval` (`test_hardening.py::TestSecurityHeaders`).

## Accessibility conformance

EN 301 549 — the technical standard the European Accessibility Act has enforced since 28 June 2025 — is anchored to WCAG Level AA, so an accessibility defect in a shipped tool is a compliance defect. The dashboard was audited with axe-core in a real browser across all eight pages, plus checks for the WCAG 2.2 criteria automation cannot fully cover.

| check | before | after |
|---|---|---|
| axe-core violations (WCAG 2.0/2.1/2.2 A + AA) | 3 critical | **0** |
| SC 2.5.8 Target Size — targets below 24x24 CSS px | 21 | **0** |
| SC 2.4.7 Focus Visible — controls with no focus indicator | 0 | 0 |
| SC 2.4.11 Focus Not Obscured — focused controls hidden by other content | 0 | 0 |
| `prefers-reduced-motion` honoured | yes | yes |

The three axe violations were real Level A failures: two Settings inputs carried a label positioned above them but never associated with `htmlFor`/`id`, so a screen reader announced them as unlabelled; and the CRQC Timeline algorithm picker had no accessible name at all. The target-size failures were genuine usability defects independent of assistive technology — the scan-row delete control was 16x21 px and the dependency recheck 14x14.

All of it is pinned by `dashboard/e2e/accessibility.spec.ts`, which runs the same axe sweep, the target-size measurement and a 25-stop keyboard traversal against the built app, so a regression fails a test rather than reaching a user.
