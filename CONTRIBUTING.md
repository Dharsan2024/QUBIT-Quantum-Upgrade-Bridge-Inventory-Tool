# Contributing to QUBIT

Thanks for helping make post-quantum migration work safer and more reproducible. QUBIT is a research prototype with a security-sensitive source-code workflow. We value small, reviewable changes with concrete evidence over broad claims or large untested rewrites.

## Before you start

1. Read the [README](README.md), especially the project limits and evidence model.
2. Search existing issues and pull requests. Open an issue or discussion before starting a large feature, new model, benchmark, or architecture change.
3. Never include real credentials, customer repositories, private keys, production data, or unpublished research data in an issue, test, or pull request.
4. Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Local setup

QUBIT uses Python 3.12 or 3.13, `uv`, Node.js for the dashboard, and Rust for Tauri desktop builds.

```powershell
uv sync --all-packages --group dev
uv run poe unit

cd dashboard
npm ci
npm run lint
npm run build
```

Use the smallest relevant check while developing. Before requesting review, run the checks relevant to every modified area. The CI baseline includes Ruff, formatting, MyPy for workspace packages, unit tests, dashboard lint/build, browser checks, license checks, and secret scanning.

## What a good pull request contains

- A focused title and a short explanation of the problem and the intended behaviour.
- Tests that fail before the fix and pass after it, where practical.
- Any behaviour, API, schema, migration, rule-catalogue, or documentation changes called out clearly.
- A note on validation actually run, including skipped or unavailable checks.
- No unrelated formatting churn, generated outputs, dependency caches, local databases, model checkpoints, or private fixtures.

Keep pull requests small enough to review. If a change must be large, split it into independently testable commits or ask for maintainer guidance first.

## Special requirements for security-sensitive changes

### Scanner rules and normalisation

Each rule must have representative positive and negative fixtures. State its language and library scope precisely. A detection result is not a proof of reachability, safety, or a valid migration target; do not write documentation that implies otherwise.

### Migration transforms and generated patches

Do not make application automatic. A transform must preserve the approval boundary, validation record, and post-write re-scan. Add negative tests for unsafe, stale, ambiguous, or ownership-constrained inputs whenever the change can affect them.

Clearly distinguish these outcomes:

- **passed**: a stated validation gate ran and passed;
- **not applicable**: the gate is structurally inapplicable to the language or rule;
- **skipped**: an environment or dependency was unavailable; and
- **failed**: the gate ran and rejected the candidate.

A skipped test, a successful parse, or a lower finding count must never be described as semantic correctness.

### Risk and ML components

Document the data source, training/evaluation split, seed, hardware, configuration, and uncertainty before asserting any model result. Synthetic training data, analytical approximations, or project-authored digital twins must be labelled as such. Do not call a component production-ready, independently validated, or generally accurate without released evidence that supports that claim.

## Documentation and research contributions

Documentation is part of the engineering surface. Please update the README, API or user-facing documentation, and research artefacts when a change affects a user-visible workflow or published claim. Preserve negative results and limitations. Tables and figures must name their unit of analysis and avoid mixing scanner emissions, task outcomes, test cases, and application-level results in one denominator.

## Pull-request review

Maintainers review for correctness, evidence, safety impact, test quality, scope, and documentation. A request may be asked to narrow its claim, add a negative test, separate generated output, or defer a feature whose evaluation design is not yet mature. This is normal for a research-security project.

By contributing, you agree that your contribution may be distributed under the repository's MIT license.
