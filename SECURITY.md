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
