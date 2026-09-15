# Security Policy

## Scope

QUBIT processes security-sensitive source code and can prepare source changes. Security defects in the desktop shell, local API, authentication, filesystem handling, source-transfer controls, secret storage, migration approval boundary, and dependency chain are in scope.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability.

Use GitHub's private security-advisory flow for this repository where available, or contact `dharsanlingadurai24@gmail.com` with the subject `QUBIT security report`. Include:

1. a clear description of the impact;
2. affected version, commit, OS, and configuration;
3. minimal reproduction steps or a proof of concept that contains no real secrets or private code; and
4. any mitigation you recommend.

We will acknowledge a report as soon as practical, assess its impact, and coordinate a fix and disclosure timeline with the reporter. Please give maintainers reasonable time to investigate before public disclosure.

## Safe research boundaries

Do not test against systems, repositories, network services, or credentials you do not own or have explicit permission to assess. Never submit private keys, API tokens, customer data, or production source code. For potentially destructive migration behaviour, reproduce against a disposable local fixture.

## Security model reminder

QUBIT is an approval-gated research prototype. Candidate patches, model output, successful parsing, and scanner-removal counts are not equivalent to a security guarantee. Report any route that bypasses explicit approval, writes outside the selected repository, leaks source to an unapproved destination, or misrepresents validation evidence.

### Deployment boundary

The default tenant is the installation operator. Only that tenant can read or change shared LLM provider configuration, engine pools, provider budgets, and threat-intelligence settings. Read-only operator tokens cannot mutate them. Other tenants can use their own scan and migration records, but cannot administer shared credentials. Tenant separation is an API/database boundary, not an operating-system sandbox: do not expose the service to mutually untrusted users with unrestricted local filesystem access.

Use a unique configured API token, keep the desktop API bound to loopback, and protect any remote deployment with authenticated TLS and network access controls. Published development defaults are only for unconfigured local bootstrap. Protect the application data directory and its encryption-key file with OS permissions; encryption at rest does not protect against an attacker who can read both the database and the key.

### Exposed credentials and test fixtures

If a committed credential was issued by a provider, revoke or rotate it at that provider and inspect its usage. Removing a literal from the current tree does not revoke a key or remove earlier Git history. Do not close a secret alert as resolved solely because a source edit landed. Confirm the provider-side action, or independently establish that the value was never a credential.

Scanner tests must use synthetic values constructed at runtime. Never paste actual provider credentials into fixtures, screenshots, reports, issues, or test output. Existing secret-scanning CI remains enabled; do not add a broad allowlist to suppress an alert.
