"""An algorithm named through a variable is still that algorithm.

`Cipher.getInstance(crypto)`, with `String crypto = "DES/ECB/PKCS5Padding"` elsewhere in the file,
is ordinary Java. A purely syntactic AST match sees an identifier where it wanted a string literal
and reports nothing at all.

Measured against CryptoAPI-Bench's published ground truth, that was not a corner case: recall on
its interprocedural and multi-method groups was **0%**, against 82% on the identical misuses
written with a literal at the call site. These tests pin the fold that closed the gap, and the
boundary beyond which it deliberately stops.
"""

from __future__ import annotations

import pytest
from qubit_scanner import CodeScanner, RuleCatalog


@pytest.fixture(scope="module")
def scanner() -> CodeScanner:
    return CodeScanner(RuleCatalog.load())


def _algorithms(scanner: CodeScanner, source: str, language: str = "java") -> set[str]:
    detections = scanner.scan_source(source.encode(), language, file_path=f"T.{language}")
    return {d.raw_algorithm for d in detections if d.raw_algorithm}


class TestJavaConstantFolding:
    def test_a_cipher_named_by_a_local_resolves(self, scanner: CodeScanner) -> None:
        source = """
        import javax.crypto.Cipher;
        class A {
            void f() throws Exception {
                String crypto = "DES/ECB/PKCS5Padding";
                Cipher.getInstance(crypto);
            }
        }
        """
        assert "DES" in _algorithms(scanner, source)

    def test_the_binding_may_be_in_another_method(self, scanner: CodeScanner) -> None:
        """CryptoAPI-Bench's `Interprocedural (2 methods)` shape: the literal is in `main`, the
        call is in `go`. Both are in one file, which is as far as an intra-file fold reaches."""
        source = """
        import javax.crypto.Cipher;
        class A {
            void go(String crypto) throws Exception { Cipher.getInstance(crypto); }
            public static void main(String[] a) throws Exception {
                String crypto = "DES/ECB/PKCS5Padding";
                new A().go(crypto);
            }
        }
        """
        assert "DES" in _algorithms(scanner, source)

    def test_a_digest_named_by_a_local_resolves(self, scanner: CodeScanner) -> None:
        source = """
        import java.security.MessageDigest;
        class A {
            void f() throws Exception {
                String h = "MD4";
                MessageDigest.getInstance(h);
            }
        }
        """
        assert "MD4" in _algorithms(scanner, source)

    def test_md4_and_md2_are_detected_at_all(self, scanner: CodeScanner) -> None:
        """The broken-digest rule matched only `MD5|SHA-1`, so `MessageDigest.getInstance("MD4")`
        produced nothing even though MD4 is in the canonical registry and marked vulnerable."""
        for name in ("MD4", "MD2"):
            source = f"""
            import java.security.MessageDigest;
            class A {{ void f() throws Exception {{ MessageDigest.getInstance("{name}"); }} }}
            """
            assert name in _algorithms(scanner, source), name

    def test_a_key_generator_named_by_a_local_resolves(self, scanner: CodeScanner) -> None:
        source = """
        import javax.crypto.KeyGenerator;
        class A {
            void f() throws Exception {
                String keyAlgo = "DES";
                KeyGenerator.getInstance(keyAlgo);
            }
        }
        """
        assert "DES" in _algorithms(scanner, source)


class TestTheFoldStopsWhereItShould:
    """The fold is intra-file and single-assignment on purpose. Where it cannot be sure, the
    finding stays unresolved rather than being guessed -- a wrong algorithm name in an inventory is
    worse than an acknowledged gap, because it is acted on."""

    def test_two_conflicting_assignments_do_not_resolve(self, scanner: CodeScanner) -> None:
        source = """
        import javax.crypto.Cipher;
        class A {
            void f() throws Exception {
                String crypto = "DES/ECB/PKCS5Padding";
                if (x) { crypto = "AES/GCM/NoPadding"; }
                Cipher.getInstance(crypto);
            }
        }
        """
        # Ambiguous: two bindings, so neither is asserted as the answer.
        assert "DES" not in _algorithms(scanner, source)

    def test_an_unbound_name_does_not_invent_an_algorithm(self, scanner: CodeScanner) -> None:
        source = """
        import javax.crypto.Cipher;
        class A { void f(String fromCaller) throws Exception { Cipher.getInstance(fromCaller); } }
        """
        assert "DES" not in _algorithms(scanner, source)
        assert "fromCaller" not in _algorithms(scanner, source)


class TestOtherLanguagesKeepWorking:
    def test_python_still_resolves_a_literal(self, scanner: CodeScanner) -> None:
        got = _algorithms(scanner, "import hashlib\na = hashlib.md5()\n", "python")
        assert "MD5" in got

    def test_a_java_literal_still_resolves(self, scanner: CodeScanner) -> None:
        source = """
        import javax.crypto.Cipher;
        class A { void f() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); } }
        """
        assert "AES" in _algorithms(scanner, source)
