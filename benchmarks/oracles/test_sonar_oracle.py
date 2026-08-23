"""The gate that decides which repositories sonar-cryptography is even pointed at.

`sonar-scanner` indexes every file it is given regardless of language, so the cost of asking it
about a repository it cannot read is paid in full before the answer comes back: openwrt is 11,555
files and would take longer than the rest of the sweep to produce a guaranteed zero. The gate exists
to make "sonar cannot read this" a fact settled in seconds.

Getting it wrong is quiet in both directions, which is why it is pinned here rather than trusted:

* **Too permissive** and the sweep spends an hour per large C repository to learn nothing.
* **Too strict** and a repository sonar *could* have read is silently dropped, which does not look
  like a bug -- it looks like a detector that found nothing there, and it would understate sonar's
  coverage in a published comparison.

The thresholds are a count *and* a share because the corpus contains a case that defeats either one
alone: openwrt has 25 analysable files, the same as a genuinely mixed Kotlin project, but they are
0.2% of it and every one is a build script.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sonar_oracle import (
    _MIN_READABLE_FILES,
    _MIN_READABLE_SHARE,
    SonarCryptographyDetector,
)

DETECTOR = SonarCryptographyDetector()


def _tree(root: Path, *, readable: int, other: int, suffix: str = ".java") -> Path:
    for n in range(readable):
        (root / f"src{n}{suffix}").write_text("class A {}", encoding="utf-8")
    for n in range(other):
        (root / f"other{n}.c").write_text("int main(void){return 0;}", encoding="utf-8")
    return root


def _scans(root: Path) -> bool:
    readable, share = DETECTOR.coverage(root)
    return readable >= _MIN_READABLE_FILES and share >= _MIN_READABLE_SHARE


class TestCoverage:
    def test_counts_java_python_and_go(self, tmp_path: Path) -> None:
        (tmp_path / "a.java").write_text("class A {}", encoding="utf-8")
        (tmp_path / "b.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "c.go").write_text("package main", encoding="utf-8")
        (tmp_path / "d.rs").write_text("fn main() {}", encoding="utf-8")
        readable, share = DETECTOR.coverage(tmp_path)
        assert readable == 3
        assert share == pytest.approx(0.75)

    def test_it_recurses(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        (nested / "deep.go").write_text("package main", encoding="utf-8")
        readable, _ = DETECTOR.coverage(tmp_path)
        assert readable == 1

    def test_an_empty_tree_is_zero_not_a_crash(self, tmp_path: Path) -> None:
        assert DETECTOR.coverage(tmp_path) == (0, 0.0)


class TestTheGate:
    def test_a_real_java_project_is_scanned(self, tmp_path: Path) -> None:
        assert _scans(_tree(tmp_path, readable=1486, other=2685))

    def test_a_mixed_project_with_a_meaningful_minority_is_scanned(self, tmp_path: Path) -> None:
        """CymChad: 25 java files in a Kotlin project, 9.5% of it. Small, but real coverage."""
        assert _scans(_tree(tmp_path, readable=25, other=238))

    def test_build_scripts_in_a_huge_c_repository_are_not_coverage(self, tmp_path: Path) -> None:
        """openwrt: 25 analysable files -- passes the count -- but 0.2% of 11,555.

        This is the case the count alone gets wrong, and the one that costs the most to get wrong.
        """
        assert not _scans(_tree(tmp_path, readable=25, other=1000, suffix=".py"))

    def test_a_handful_of_files_in_a_tiny_repository_is_not_coverage(self, tmp_path: Path) -> None:
        """The case the share alone gets wrong: 3 files out of 10 is 30% and still nothing."""
        assert not _scans(_tree(tmp_path, readable=3, other=7))

    def test_a_repository_with_none_of_its_languages_is_never_scanned(self, tmp_path: Path) -> None:
        assert not _scans(_tree(tmp_path, readable=0, other=500))


class TestScanShortCircuits:
    def test_an_unreadable_repository_returns_no_findings_without_running_docker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The gate must fire before the container starts, or it has saved nothing."""
        import sonar_oracle

        def explode(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("docker was invoked for a repository sonar cannot read")

        monkeypatch.setattr(sonar_oracle, "_docker", explode)
        assert DETECTOR.scan(_tree(tmp_path, readable=0, other=40)) == []


class TestCbomParsing:
    """The CBOM shape this depends on, pinned against a real fragment of the plugin's output."""

    payload: ClassVar[dict] = {
        "components": [
            {
                "name": "AES-128-CBC-PKCS5",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "block-cipher"},
                },
                "evidence": {"occurrences": [{"location": "src/Demo.java", "line": 6}]},
            },
            {
                "name": "private-key@6995bf3c",
                "cryptoProperties": {"assetType": "related-crypto-material"},
                "evidence": {"occurrences": [{"location": "src/demo.py", "line": 6}]},
            },
            {
                "name": "MD5",
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "a.java", "line": 7}, {"line": 9}]},
            },
        ]
    }

    def test_algorithms_become_findings(self) -> None:
        found = DETECTOR._findings(self.payload)
        assert {(f.path, f.line, f.algorithm) for f in found} == {
            ("src/Demo.java", 6, "AES-128-CBC-PKCS5"),
            ("a.java", 7, "MD5"),
        }

    def test_keys_and_certificates_are_not_findings(self) -> None:
        """`related-crypto-material` is a key, not an algorithm at a call site.

        Including it would put this detector into a population none of the others sample, which is
        precisely the assumption capture-recapture rests on.
        """
        assert all(f.algorithm != "private-key@6995bf3c" for f in DETECTOR._findings(self.payload))

    def test_an_occurrence_without_a_location_is_dropped(self) -> None:
        assert all(f.path and f.line for f in DETECTOR._findings(self.payload))

    def test_every_finding_is_attributed_to_this_detector(self) -> None:
        assert {f.detector for f in DETECTOR._findings(self.payload)} == {"sonar"}

    def test_an_empty_cbom_is_no_findings(self) -> None:
        assert DETECTOR._findings({"components": []}) == []
