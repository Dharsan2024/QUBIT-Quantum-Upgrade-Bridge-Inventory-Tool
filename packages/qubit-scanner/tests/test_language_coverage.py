"""Guards on the language surface itself, rather than on any one rule.

Every failure mode here is silent by construction — the scan succeeds, reports no findings, and
looks exactly like a clean repository:

* an extension mapped to a grammar that has **no rule pack** (`.cpp` was in this state for a long
  time: the file parsed, matched nothing, and counted as scanned);
* an extension **missing** from the map entirely, so the file is never opened (`.tsx` was missing,
  which meant every React component was skipped while the `.ts` files beside it were scanned);
* a pack that declares a sibling grammar in `additional_languages` whose queries **compile but
  never match** there;
* a literal node type the resolver does not know, so a matched rule yields `UNRESOLVED` instead of
  an algorithm;
* an unanchored wildcard argument capture, which reads a *later* argument as the algorithm.

None of these break a test that only checks rules against their own examples, which is why they
need their own file.
"""

from __future__ import annotations

import re

import pytest
from qubit_scanner import CodeScanner, RuleCatalog
from qubit_scanner.catalog.loader import BUILTIN_RULES_DIR
from qubit_scanner.code import resolve
from qubit_scanner.code.languages import (
    EXT_TO_LANGUAGE,
    NAME_TO_LANGUAGE,
    language_for,
    language_from_shebang,
)
from tree_sitter_language_pack import get_parser

_CATALOG = RuleCatalog.load()
_SCANNER = CodeScanner(_CATALOG)

# The grammars QUBIT claims to support. Kept as an explicit list rather than derived from the
# extension map so that DELETING a rule pack fails this test instead of quietly shrinking the
# claim — the README and the docs quote this number.
SUPPORTED_LANGUAGES = frozenset(
    {
        "bash",
        "c",
        "cpp",
        "csharp",
        "dart",
        "go",
        "java",
        "javascript",
        "kotlin",
        "php",
        "powershell",
        "python",
        "ruby",
        "rust",
        "scala",
        "sql",
        "swift",
        "tsx",
        "typescript",
    }
)


def test_every_supported_language_has_rules() -> None:
    """A language with zero rules parses cleanly and finds nothing — same output as safe code."""
    missing = sorted(lang for lang in SUPPORTED_LANGUAGES if not _CATALOG.for_language(lang))
    assert not missing, (
        f"These languages are claimed as supported but have no rules behind them: {missing}. "
        "A file in one of them is parsed, matches nothing, and is counted as scanned — which is "
        "indistinguishable from a file with no cryptography in it."
    )


def test_every_mapped_extension_leads_to_rules() -> None:
    """Mapping an extension to a grammar with no pack is worse than not mapping it at all."""
    unbacked = sorted(
        {
            f"{ext} -> {lang}"
            for ext, lang in EXT_TO_LANGUAGE.items()
            if not _CATALOG.for_language(lang)
        }
    )
    assert not unbacked, f"extensions mapped to grammars with no rule pack: {unbacked}"


def test_every_supported_language_is_reachable_from_a_file_extension() -> None:
    """A pack nothing can dispatch to is dead weight; the scan never selects that grammar."""
    reachable = set(EXT_TO_LANGUAGE.values()) | set(NAME_TO_LANGUAGE.values())
    unreachable = sorted(SUPPORTED_LANGUAGES - reachable)
    assert not unreachable, (
        f"languages with rules but no file extension mapped to them: {unreachable}"
    )


@pytest.mark.parametrize(
    "path,expected",
    [
        ("app/Component.tsx", "tsx"),
        ("app/Component.jsx", "javascript"),
        ("src/main.rs", "rust"),
        ("Program.cs", "csharp"),
        ("index.php", "php"),
        ("app/models.rb", "ruby"),
        ("Gemfile", "ruby"),
        ("Rakefile", "ruby"),
        ("MainActivity.kt", "kotlin"),
        ("build.gradle.kts", "kotlin"),
        ("Ledger.scala", "scala"),
        ("AppDelegate.swift", "swift"),
        ("main.dart", "dart"),
        ("deploy.sh", "bash"),
        ("Provision.ps1", "powershell"),
        ("V3__add_index.sql", "sql"),
        ("gateway.cpp", "cpp"),
        ("gateway.hpp", "cpp"),
        ("legacy.c", "c"),
    ],
)
def test_representative_files_resolve_to_the_right_grammar(path: str, expected: str) -> None:
    from pathlib import Path

    assert language_for(Path(path)) == expected


@pytest.mark.parametrize(
    "shebang,expected",
    [
        (b"#!/bin/bash\n", "bash"),
        (b"#!/bin/sh\n", "bash"),
        (b"#!/usr/bin/env bash\n", "bash"),
        (b"#!/usr/bin/env python3\n", "python"),
        (b"#!/usr/bin/env ruby\n", "ruby"),
        (b"#!/usr/bin/pwsh\n", "powershell"),
        (b"#!/usr/bin/env node\n", "javascript"),
        (b"not a shebang\n", None),
        (b"#!/usr/bin/env perl\n", None),  # no rule pack; must not claim a grammar
    ],
)
def test_shebang_identifies_extensionless_scripts(shebang: bytes, expected: str | None) -> None:
    assert language_from_shebang(shebang) == expected


# ── sibling grammars ────────────────────────────────────────────────────────────────────────────

# A pack declaring `additional_languages` promises its queries work there too. Compiling is not
# proof: a query can compile against a grammar and match nothing in it, which is the silent case.
_SIBLING_CHECKS = [
    ("c", "cpp", "#include <openssl/evp.h>\nvoid f(){ EVP_DigestInit_ex(c, EVP_sha1(), NULL); }\n"),
    (
        "typescript",
        "tsx",
        "import * as crypto from 'crypto';\n"
        "export const App = () => { crypto.createHash('md5'); return <div/>; };\n",
    ),
]


@pytest.mark.parametrize("primary,sibling,source", _SIBLING_CHECKS)
def test_sibling_grammar_actually_matches(primary: str, sibling: str, source: str) -> None:
    """The same source must produce findings under the sibling grammar, not merely compile."""
    found = _SCANNER.scan_source(source.encode(), sibling, file_path=f"ex.{sibling}")
    assert found, (
        f"the {primary} pack declares additional_languages: [{sibling}] but matched nothing there"
    )
    # And the finding must carry a resolvable algorithm, not an UNRESOLVED sentinel.
    assert any(d.raw_algorithm != "UNRESOLVED" for d in found)


def test_tsx_and_typescript_do_not_double_report() -> None:
    """Only the TypeScript pack claims TSX. If the JavaScript pack claimed it too, every `.tsx`
    finding would appear twice under two rule ids for one call."""
    source = "import * as crypto from 'crypto';\nconst f = () => crypto.createHash('md5');\n"
    rule_ids = {d.rule_id for d in _SCANNER.scan_source(source.encode(), "tsx", file_path="ex.tsx")}
    prefixes = {rid.split("-")[0] for rid in rule_ids}
    assert prefixes <= {"TS"}, f"tsx matched packs from more than one language: {sorted(rule_ids)}"


# ── literal reading and constant folding, per grammar ───────────────────────────────────────────

# `resolve.py` reads literals by NODE TYPE, and every grammar spells them differently. A missing
# name does not fail loudly: the rule still matches, and the algorithm comes back None.
_LITERAL_PROBES = {
    "python": ('f("MD5", 1024)', "MD5", 1024),
    "java": ('class C { void f(){ g("MD5", 1024); } }', "MD5", 1024),
    "go": ('package m\nfunc f(){ g("MD5", 1024) }', "MD5", 1024),
    "c": ('void f(){ g("MD5", 1024); }', "MD5", 1024),
    "cpp": ('void f(){ g("MD5", 1024); }', "MD5", 1024),
    "javascript": ('f("MD5", 1024);', "MD5", 1024),
    "typescript": ('f("MD5", 1024);', "MD5", 1024),
    "tsx": ('f("MD5", 1024);', "MD5", 1024),
    "csharp": ('class C { void F(){ G("MD5", 1024); } }', "MD5", 1024),
    "php": ('<?php f("MD5", 1024);', "MD5", 1024),
    "ruby": ('f("MD5", 1024)', "MD5", 1024),
    "rust": ('fn f(){ g("MD5", 1024); }', "MD5", 1024),
    "kotlin": ('fun f(){ g("MD5", 1024) }', "MD5", 1024),
    "scala": ('object A { def f() = { g("MD5", 1024) } }', "MD5", 1024),
    "swift": ('func f(){ g("MD5", 1024) }', "MD5", 1024),
    "dart": ('void f(){ g("MD5", 1024); }', "MD5", 1024),
    "bash": ('openssl dgst "MD5" 1024\n', "MD5", 1024),
    "powershell": ('f "MD5" 1024\n', "MD5", 1024),
    "sql": ("SELECT f('MD5', 1024);", "MD5", 1024),
}


def _all_nodes(node):  # type: ignore[no-untyped-def]
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.children)


@pytest.mark.parametrize("language", sorted(SUPPORTED_LANGUAGES))
def test_string_and_int_literals_are_readable_in_every_grammar(language: str) -> None:
    source, want_string, want_int = _LITERAL_PROBES[language]
    tree = get_parser(language).parse(source.encode())  # type: ignore[arg-type]

    strings = {resolve.string_literal_value(n) for n in _all_nodes(tree.root_node)}
    assert want_string in strings, (
        f"{language}: no node yielded the string {want_string!r}. A rule extracting an algorithm "
        f"name from a string literal in {language} would return None and report UNRESOLVED."
    )

    ints = {resolve.int_literal_value(n) for n in _all_nodes(tree.root_node)}
    assert want_int in ints, (
        f"{language}: no node yielded the integer {want_int}. A key-size extractor in {language} "
        f"would silently drop the size — an RSA-1024 keygen would report as bare RSA."
    )


_FOLD_PROBES = {
    "python": ('algo = "DES"\nf(algo)\n', "algo"),
    "java": ('class C { void f(){ String algo = "DES"; g(algo); } }', "algo"),
    "go": ('package m\nfunc f(){ algo := "DES"; g(algo) }', "algo"),
    "c": ('void f(){ const char *algo = "DES"; g(algo); }', "algo"),
    "cpp": ('void f(){ auto algo = "DES"; g(algo); }', "algo"),
    "javascript": ('const algo = "DES"; g(algo);', "algo"),
    "typescript": ('const algo: string = "DES"; g(algo);', "algo"),
    "tsx": ('const algo: string = "DES"; g(algo);', "algo"),
    "csharp": ('class C { void F(){ var algo = "DES"; G(algo); } }', "algo"),
    "php": ('<?php $algo = "DES"; g($algo);', "$algo"),
    "ruby": ('algo = "DES"\ng(algo)\n', "algo"),
    "rust": ('fn f(){ let algo = "DES"; g(algo); }', "algo"),
    "kotlin": ('fun f(){ val algo = "DES"; g(algo) }', "algo"),
    "scala": ('object A { def f() = { val algo = "DES"; g(algo) } }', "algo"),
    "swift": ('func f(){ let algo = "DES"; g(algo) }', "algo"),
    "dart": ('void f(){ var algo = "DES"; g(algo); }', "algo"),
    "bash": ('algo="DES"\nopenssl enc -$algo\n', "algo"),
}


@pytest.mark.parametrize("language", sorted(_FOLD_PROBES))
def test_string_constants_fold_in_every_grammar_that_has_variables(language: str) -> None:
    """`algo = "DES"; Cipher.getInstance(algo)` is the ordinary way real code hides its algorithm.

    Only Python's `assignment` node was handled originally, so the fold worked in Python and gave
    up everywhere else — every such call in Java, Go, C#, Kotlin or PHP became an UNRESOLVED
    finding carrying no algorithm name at all.
    """
    source, name = _FOLD_PROBES[language]
    tree = get_parser(language).parse(source.encode())  # type: ignore[arg-type]
    assert resolve.resolve_string_constant(name, tree.root_node) == "DES"


# ── query hygiene ───────────────────────────────────────────────────────────────────────────────

_ARG_CONTAINERS = ("argument_list", "arguments", "value_arguments")
_WILDCARD_CAPTURE_RE = re.compile(r"\(_\)\s*@")

# Node patterns that identify an argument by NAME rather than position. A wildcard inside one of
# these is already pinned — `(keyword_argument name: (identifier) @kw value: (_) @size)` with a
# `where` on @kw can only ever read the argument called `key_size`, so position is irrelevant and
# an anchor would add nothing. Only positional containers need `.`.
_KEYED_ARGUMENT_PATTERNS = (
    "keyword_argument",  # python
    "array_element_initializer",  # php
    "dictionary_literal",  # swift
    "value_argument_label",  # swift call labels
    "pair",  # js/ts object literal
)


def test_wildcard_argument_captures_are_anchored() -> None:
    """`(arguments (argument (_) @algo))` matches EVERY argument, not the first one.

    Measured, not theoretical: `hash_hmac("md5", $data, $key)` produced three findings — the
    correct HMAC-MD5 plus `UNKNOWN(HMAC-$data)` and `UNKNOWN(HMAC-$key)`, both rated NOT
    vulnerable. Typed captures like `(string_literal) @algo` are self-anchoring because a
    non-string argument cannot match them; a wildcard has no such protection and must use `.`.
    """
    import yaml

    offenders: list[str] = []
    for path in sorted(BUILTIN_RULES_DIR.rglob("*.yaml")):
        rule_file = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in rule_file["rules"]:
            query = rule["match"]["query"]
            if not _WILDCARD_CAPTURE_RE.search(query):
                continue
            if any(keyed in query for keyed in _KEYED_ARGUMENT_PATTERNS):
                continue  # the argument is identified by name, not position
            for container in _ARG_CONTAINERS:
                marker = f"({container}"
                index = query.find(marker)
                if index == -1:
                    continue
                tail = query[index + len(marker) :]
                if _WILDCARD_CAPTURE_RE.search(tail) and "." not in tail.split("@")[0]:
                    offenders.append(f"{path.parent.name}/{path.name}:{rule['id']}")
                    break

    assert not offenders, (
        "These rules capture an argument with a `(_)` wildcard and no `.` anchor, so any argument "
        "at any position can be read as the algorithm:\n  " + "\n  ".join(sorted(set(offenders)))
    )


# Grammar fields that a node carries MORE THAN ONCE. A typed capture is normally self-anchoring —
# `(string_literal) @algo` cannot match a column reference — but that protection evaporates when
# several arguments share the type, and a repeated field is exactly where that happens.
# Each entry is a (node type or empty, field) pair that must BOTH appear for the query to be
# suspect. `value:` alone is not a signal — it is an ordinary single-occurrence field in Python's
# `keyword_argument`, JS's `pair` and most others. It is only repeated on Swift's
# `dictionary_literal`, which carries one `key:`/`value:` pair per entry with no wrapper node.
_REPEATED_FIELD_PATTERNS = (
    ("", "parameter:"),  # sql `invocation` — one field per argument
    ("dictionary_literal", "value:"),  # swift
)


def test_repeated_field_captures_are_anchored() -> None:
    """A repeated field pairs every occurrence with every other unless positions are anchored.

    Found in production, not in review: `(invocation ... parameter: (term value: (literal) @algo))`
    read all three arguments of `encrypt('', 'helm-ops-key', 'des')`, emitting `UNKNOWN()` and
    `UNKNOWN(helm-ops-key)` beside the correct DES — the first two rated NOT vulnerable, and one of
    them printing a KEY into the inventory as if it were an algorithm name.

    The rule examples did not catch it because they all used a column reference for the data
    argument, which is the one shape where the type constraint happens to do the anchoring.
    """
    import yaml

    offenders: list[str] = []
    for path in sorted(BUILTIN_RULES_DIR.rglob("*.yaml")):
        rule_file = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in rule_file["rules"]:
            query = rule["match"]["query"]
            # Comment lines inside a query start with `;` and may name the field they warn about.
            code = "\n".join(
                line for line in query.splitlines() if not line.strip().startswith(";")
            )
            # Naming a repeated field is the defect itself, in ANY pattern of the query: the
            # correct form addresses those children positionally and never uses the field name.
            # Checking whether the rule contains an anchor somewhere was not enough — one
            # anchored pattern elsewhere in the same rule hid an unanchored one, and the lint
            # passed on a rule I had deliberately broken to test it.
            for node, field in _REPEATED_FIELD_PATTERNS:
                if node:
                    # Field is only repeated on this node type, so require an adjacency anchor.
                    suspect = node in code and field in code and f". {field}" not in code
                else:
                    # Field is repeated wherever it appears; naming it at all is the bug.
                    suspect = field in code
                if suspect:
                    offenders.append(f"{path.parent.name}/{path.name}:{rule['id']}")
                    break

    assert not offenders, (
        "These rules match on a repeated grammar field with no `.` anchor, so any occurrence can "
        "pair with any other — a key argument can be read as the algorithm:\n  "
        + "\n  ".join(sorted(set(offenders)))
    )


def test_rule_ids_are_unique_within_a_language() -> None:
    """Two rules sharing an id make `dedupe: per-file` collapse unrelated findings together."""
    seen: dict[tuple[str, str], int] = {}
    for compiled in _CATALOG.all_rules():
        key = (compiled.language, compiled.rule.id)
        seen[key] = seen.get(key, 0) + 1
    duplicates = sorted(f"{lang}:{rid}" for (lang, rid), n in seen.items() if n > 1)
    assert not duplicates, f"duplicate rule ids: {duplicates}"
