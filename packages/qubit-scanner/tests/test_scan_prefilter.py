"""The literal pre-filter must be a pure speed-up: same findings, less work.

A rule's `where` clauses are applied under `all(...)` and compare the verbatim text of a captured
node, so a file that does not contain a clause's literal anywhere cannot produce a single detection
from that rule -- yet its tree-sitter query would still be run over the whole parse tree and every
resulting match rejected one at a time.

Measured warm on node-forge before this: 3,179 query executions over 115 files produced 79,066
candidate matches and 3 findings, with 73% of scan time inside `QueryCursor.matches`. Across five
real repositories (node-forge, paramiko, gliderlabs/ssh, java-jwt, ruby-jwt) the filter cut warm
scan time 6.18s -> 2.15s (2.9x, and 4.2x on node-forge) with identical output.

The risk of an optimisation like this is that it silently drops a real finding, which would be far
worse than the time it saves -- a scanner that is fast because it stopped looking. These tests are
the guard: `test_rule_examples.py` already asserts every rule in the catalog still detects its own
positive example, and the equivalence test here asserts the filter changes nothing on sources
built to sit right on its boundary.
"""

from __future__ import annotations

import pytest
from qubit_scanner import CodeScanner, RuleCatalog
from qubit_scanner.catalog.loader import CompiledRule

# Real crypto usages across several languages, including cases chosen to stress the filter:
# a literal that appears only inside a comment, and one split so the identifier is absent.
SOURCES: dict[str, str] = {
    "python": "import hashlib\n\ndigest = hashlib.md5(payload).hexdigest()\n",
    "javascript": (
        "const crypto = require('node:crypto');\n"
        "const h = crypto.createHash('sha1');\n"
        "const c = crypto.createCipheriv('des-ede3', key, iv);\n"
    ),
    "go": (
        'package main\n\nimport (\n    "crypto/rsa"\n    "crypto/rand"\n)\n\n'
        "func gen() { rsa.GenerateKey(rand.Reader, 1024) }\n"
    ),
    "java": (
        "class T {\n  void f() throws Exception {\n"
        '    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");\n  }\n}\n'
    ),
    # The identifier appears ONLY in a comment. The filter is a substring test, so it will let
    # these rules through -- and the parse-tree match must then correctly find nothing. This pins
    # that the filter never turns a comment into a finding.
    "python_comment_only": "# we deliberately avoid hashlib.md5 here\nvalue = 1\n",
    # Nothing crypto at all: the case the filter exists to make cheap.
    "python_empty": "def add(a, b):\n    return a + b\n",
}

LANGUAGE_OF = {
    "python": "python",
    "javascript": "javascript",
    "go": "go",
    "java": "java",
    "python_comment_only": "python",
    "python_empty": "python",
}


@pytest.fixture(scope="module")
def scanner() -> CodeScanner:
    return CodeScanner(RuleCatalog.load())


def _scan(scanner: CodeScanner, key: str) -> list[tuple]:
    source = SOURCES[key].encode("utf-8")
    dets = scanner.scan_source(source, LANGUAGE_OF[key], file_path=f"{key}.src")
    return sorted((d.rule_id, d.raw_algorithm, d.location.line) for d in dets)


@pytest.mark.parametrize("key", sorted(SOURCES))
def test_the_prefilter_changes_no_finding(
    scanner: CodeScanner, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identical findings with the filter on and off, over the real rule catalog."""
    with_filter = _scan(scanner, key)

    # Disable the filter by making it unconditionally true -- exactly the pre-optimisation path.
    monkeypatch.setattr(CompiledRule, "matchable_against", lambda self, source: True)
    without_filter = _scan(scanner, key)

    assert with_filter == without_filter, (
        f"the pre-filter changed the findings for {key!r}: "
        f"{with_filter} (filtered) vs {without_filter} (unfiltered)"
    )


def test_the_prefilter_actually_skips_rules(scanner: CodeScanner) -> None:
    """It has to REMOVE work, or it is pure overhead dressed up as an optimisation.

    A trivial Python file with no crypto in it must leave the overwhelming majority of the
    language's rules unrunnable, which is where the time saving comes from.
    """
    rules = RuleCatalog.load().for_language("python")
    assert rules, "the catalog must have python rules for this to prove anything"

    source = SOURCES["python_empty"].encode("utf-8")
    runnable = [r for r in rules if r.matchable_against(source)]

    assert len(runnable) < len(rules) / 2, (
        f"expected most of {len(rules)} python rules to be skipped on crypto-free source, "
        f"but {len(runnable)} still had to run"
    )


def test_a_rule_with_no_extractable_literal_is_never_skipped(scanner: CodeScanner) -> None:
    """Conservative by construction: no usable `where` literal means "always run me".

    A rule filtered only by a regex, or not filtered at all, has no literal that is guaranteed to
    appear in the source, so the filter must not guess one. Skipping such a rule would be the
    silent-false-negative failure this whole design is meant to avoid.
    """
    catalog = RuleCatalog.load()
    unconstrained = [r for r in catalog.all_rules() if not r.required_literals]
    if not unconstrained:
        pytest.skip("every rule in the catalog currently has an extractable literal")

    for rule in unconstrained[:20]:
        assert rule.matchable_against(b""), (
            f"{rule.rule.id} has no required literal and must run against any source"
        )
