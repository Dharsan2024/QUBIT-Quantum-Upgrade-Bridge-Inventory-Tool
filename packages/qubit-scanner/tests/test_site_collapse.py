"""One call is one cryptographic fact, however many rules recognise it.

The catalog deliberately contains overlapping rules. A generic `Signature.getInstance(<alg>)` rule
gives broad coverage and hands the argument to the algorithm registry; a specific ML-DSA rule
constrains the string and carries the migration example the rewriter quotes. Both are wanted, and
on `Signature.getInstance("ML-DSA-65")` both fire.

What is not wanted is two entries in the inventory. Every count taken over the assets -- how much
ML-DSA a codebase has, how many findings a detector reported, the corpus comparison against other
tools -- is inflated by exactly the overlap between rules, which is invisible in any single result
and varies by language. `_one_per_site` reconciles them; this pins that it does.

The subtle half is that the reconciliation is on the **resolved** algorithm.
`Signature.getInstance("Dilithium3")` is reported as `ML-DSA-65` by the specific rule and as
`Dilithium3` by the generic one. Those are one algorithm under its pre-standard and standard names,
and a comparison on the raw text would let the duplicate through.
"""

from __future__ import annotations

from collections import Counter

import pytest
from qubit_scanner import CodeScanner, RuleCatalog

_SCANNER = CodeScanner(RuleCatalog.load())


def _assets(src: str, language: str) -> list:
    return _SCANNER.scan_source(src.encode(), language, file_path="ex")


JAVA_PQC = """
import java.security.Signature;
import java.security.KeyPairGenerator;

class D {
    void a() throws Exception { Signature.getInstance("ML-DSA-65"); }
    void b() throws Exception { Signature.getInstance("Dilithium3"); }
    void c() throws Exception { KeyPairGenerator.getInstance("ML-KEM-768"); }
    void d() throws Exception { Signature.getInstance("SLH-DSA-SHA2-128s"); }
}
"""


class TestOneAssetPerSite:
    def test_each_java_pqc_call_yields_exactly_one_detection(self) -> None:
        per_line = Counter(d.location.line for d in _assets(JAVA_PQC, "java"))
        assert per_line, "the fixture should detect something"
        duplicated = {line: n for line, n in per_line.items() if n > 1}
        assert not duplicated, f"lines reported more than once: {duplicated}"

    def test_the_pre_standard_name_collapses_with_the_standard_one(self) -> None:
        """`Dilithium3` and `ML-DSA-65` are one algorithm; the strings differ, the fact does not."""
        dilithium = [d for d in _assets(JAVA_PQC, "java") if d.location.line == 7]
        assert len(dilithium) == 1

    def test_the_more_specific_rule_is_the_one_kept(self) -> None:
        """Specificity, not iteration order, decides; the specific rule has the better name."""
        mldsa = [d for d in _assets(JAVA_PQC, "java") if d.location.line == 6]
        assert len(mldsa) == 1
        assert mldsa[0].rule_id == "JAVA-BC-PQC-MLDSA65"

    def test_distinct_algorithms_on_distinct_lines_are_all_kept(self) -> None:
        """Collapsing must not swallow genuinely different findings."""
        found = {d.raw_algorithm for d in _assets(JAVA_PQC, "java")}
        assert {"ML-DSA-65", "ML-KEM-768", "SLH-DSA-SHA2-128s"} <= found

    def test_collapse_can_be_switched_off_for_rule_level_assertions(self) -> None:
        """`test_rule_examples.py` needs the pre-reconciliation view; it must stay reachable."""
        raw = _SCANNER.scan_source(JAVA_PQC.encode(), "java", file_path="ex", collapse=False)
        collapsed = _assets(JAVA_PQC, "java")
        assert len(raw) > len(collapsed)


class TestCollapseIsConservative:
    @pytest.mark.parametrize(
        "src,language",
        [
            ('import hashlib\nhashlib.md5(b"")\nhashlib.sha1(b"")\n', "python"),
            (
                'package main\nimport "crypto/des"\n'
                "func f() { des.NewCipher(k); des.NewTripleDESCipher(k) }\n",
                "go",
            ),
        ],
    )
    def test_two_different_algorithms_stay_two_findings(self, src: str, language: str) -> None:
        found = _assets(src, language)
        algorithms = {d.raw_algorithm for d in found}
        assert len(algorithms) >= 2, f"collapse ate a distinct algorithm: {algorithms}"

    def test_the_same_algorithm_on_two_lines_stays_two_findings(self) -> None:
        """Reconciliation is per site. Two calls are two facts even for one algorithm."""
        src = 'import hashlib\nhashlib.md5(b"a")\nhashlib.md5(b"b")\n'
        lines = {d.location.line for d in _assets(src, "python")}
        assert len(lines) == 2
