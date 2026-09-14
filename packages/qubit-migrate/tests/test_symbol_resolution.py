"""The `symbols` stage: the semantic check that is not locked to five languages.

`compiles` runs inside a Docker image and `_COMPILE_SANDBOX` has entries for python, php, ruby,
javascript and bash. For Go, Java, Rust, C#, Kotlin, Swift, Scala, Dart and TypeScript it SKIPS —
and `validate_patch` counts a skipped stage as a pass. That left `parses` as the only real gate,
and tree-sitter answers a weaker question than it looks: `mldsa65.PublicKey` is syntactically
perfect whether or not `mldsa65` is imported anywhere.

Measured on the go-ethereum ML-DSA migration, which QUBIT reported as "31 changes prepared and
validated": 23 of the 27 files written could not compile. The dominant failure was the model
"removing ECDSA" by deleting the `ecdsa`/`elliptic`/`big` import lines while leaving every call
that used them. All 23 passed `applies`, `parses` and `rescan`.
"""

from __future__ import annotations

from qubit_migrate.transform.validate import _stage_symbols

ORIGINAL_GO = """package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func gen() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
"""


class TestItCatchesWhatCompilesCannot:
    def test_a_package_used_without_being_imported_fails(self) -> None:
        """The exact go-ethereum defect: the new type is referenced, the import never added."""
        patched = ORIGINAL_GO.replace("*ecdsa.PrivateKey", "*mldsa65.PrivateKey")

        result = _stage_symbols(patched, "go", ORIGINAL_GO)

        assert result.status == "fail", "an undefined package is a hard compile error in Go"
        assert "mldsa65" in result.detail
        assert "import" in result.detail

    def test_deleting_an_import_that_is_still_used_fails(self) -> None:
        """The dominant real failure: 'removing ECDSA' by deleting its import line only."""
        patched = ORIGINAL_GO.replace('\t"crypto/elliptic"\n', "")

        result = _stage_symbols(patched, "go", ORIGINAL_GO)

        assert result.status == "fail"
        assert "elliptic" in result.detail

    def test_an_import_added_and_never_used_fails(self) -> None:
        """In Go an unused import is a compile ERROR, not a lint warning."""
        patched = ORIGINAL_GO.replace('\t"crypto/rand"\n', '\t"crypto/rand"\n\t"crypto/sha256"\n')

        result = _stage_symbols(patched, "go", ORIGINAL_GO)

        assert result.status == "fail"
        assert "sha256" in result.detail

    def test_a_correct_rewrite_passes(self) -> None:
        """The stage must not block a migration that genuinely resolves its own names."""
        patched = """package main

import (
	"crypto/rand"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func gen() (*mldsa65.PrivateKey, error) {
	_, priv, err := mldsa65.GenerateKey(rand.Reader)
	return priv, err
}
"""
        result = _stage_symbols(patched, "go", ORIGINAL_GO)

        assert result.status == "pass", result.detail


class TestItIsSafeOnRealCode:
    def test_local_variables_are_not_mistaken_for_packages(self) -> None:
        """`t.Run`, `err.Error`, `conn.Read` look exactly like package references to a regex.

        They are only safe to ignore because the stage DIFFS against the original: noise that was
        already there cancels out. A first version of this analysis judged the patched file alone
        and reported 173 'undefined packages' across 27 files, nearly all of them local variables.
        """
        original = """package main

import "testing"

func TestThing(t *testing.T) {
	res, err := doWork()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(res.Value)
}
"""
        # A patch that touches nothing relevant must not fail on the pre-existing t./err./res.
        patched = original.replace("t.Log(res.Value)", "t.Log(res.Value, res.Extra)")

        assert _stage_symbols(patched, "go", original).status == "pass"

    def test_no_baseline_skips_rather_than_guessing(self) -> None:
        assert _stage_symbols(ORIGINAL_GO, "go", None).status == "skipped"

    def test_a_language_with_no_grammar_skips(self) -> None:
        assert _stage_symbols("server { }", "nginx", "server { }").status == "skipped"

    def test_it_runs_for_a_language_the_compile_sandbox_has_no_image_for(self) -> None:
        """The whole point: Go has no compile image, so this is its only semantic check.

        Asserted on real Go rather than a toy snippet, because the safety valve below deliberately
        skips a file whose imports it could not read — and an invalid import block would trip it,
        making the test pass for the wrong reason.
        """
        from qubit_migrate.transform.validate import _COMPILE_SANDBOX

        assert "go" not in _COMPILE_SANDBOX, "go unexpectedly gained a compile image"
        assert _stage_symbols(ORIGINAL_GO, "go", ORIGINAL_GO).status == "pass"

    def test_a_file_whose_imports_cannot_be_read_skips_rather_than_flagging_everything(
        self,
    ) -> None:
        """The safety valve. Without it, a grammar whose import nodes are unmapped would make
        every newly added qualifier look undefined — rejecting correct patches confidently."""
        result = _stage_symbols("var x = a.B\n", "go", "var y = a.C\n")

        assert result.status == "skipped"
        assert "no imports could be read" in result.detail


class TestUnusedImportsAreJudgedPerLanguage:
    """An unused import is a COMPILE ERROR in Go and a lint warning almost everywhere else.

    Treating it as fatal everywhere failed the M2 acceptance test on a completely correct patch:
    the argon2 codemod rewrites the only `hashlib.sha1` call and leaves `import hashlib` behind —
    dead, untidy, and valid Python. Rejecting that throws away a working migration, which is the
    same over-strict-gate mistake that made QUBIT waste three model attempts per finding
    elsewhere. In Go the identical leftover genuinely will not build.
    """

    PY_BEFORE = "import hashlib\n\n\ndef store(pw):\n    return hashlib.sha1(pw).hexdigest()\n"
    PY_AFTER = (
        "from argon2 import PasswordHasher\n"
        "_ph = PasswordHasher()\n"
        "import hashlib\n\n\n"
        "def store(pw):\n    return _ph.hash(pw)\n"
    )

    def test_python_tolerates_a_leftover_import_and_says_so(self) -> None:
        result = _stage_symbols(self.PY_AFTER, "python", self.PY_BEFORE)

        assert result.status == "pass", result.detail
        assert "hashlib" in result.detail, "a tolerated leftover should still be reported"
        assert "unused" in result.detail

    def test_go_rejects_the_same_shape(self) -> None:
        before = 'package m\n\nimport "crypto/sha1"\n\nfunc h() { sha1.New() }\n'
        after = 'package m\n\nimport "crypto/sha1"\n\nfunc h() { newHash() }\n'

        result = _stage_symbols(after, "go", before)

        assert result.status == "fail"
        assert "sha1" in result.detail
        assert "compile time" in result.detail

    def test_the_language_property_is_declared_not_guessed(self) -> None:
        from qubit_migrate.transform.validate import _UNUSED_IMPORT_IS_AN_ERROR

        assert "go" in _UNUSED_IMPORT_IS_AN_ERROR
        assert "python" not in _UNUSED_IMPORT_IS_AN_ERROR


class TestAlgorithmConsistency:
    """A gate `compiles` and `behaves` cannot substitute for on Java: JCE does not validate that
    a `Mac`/`Cipher` instance's algorithm agrees with the algorithm named in the `SecretKeySpec`
    it is initialised with, at least not in a way any current stage here observes.

    Measured on `paymesh-gateway`'s `cardToken`, real campaign data, pre-fix: the accepted patch
    left `Mac.getInstance("HmacSHA256")` next to `new SecretKeySpec(..., "HmacSHA1")` two lines
    below. Evidence level 2 — `compiles` inapplicable to Java, `behaves` with no relations for
    this construct, `tests` skipped in this sandbox — so nothing else in the pipeline could have
    caught it. Swept against all 105 real applied patches still on disk from this evaluation
    (`applies`/`parses`/`symbols`/`rescan` already-accepted, real generations, not synthetic):
    flagged exactly 2, both this same file.
    """

    ORIGINAL_JAVA = (
        "import javax.crypto.Mac;\n"
        "import javax.crypto.spec.SecretKeySpec;\n\n"
        "public String cardToken(String pan) {\n"
        '    Mac mac = Mac.getInstance("HmacSHA1");\n'
        "    mac.init(new SecretKeySpec(pepper.getBytes(UTF_8), \"HmacSHA1\"));\n"
        "    return Hex.encode(mac.doFinal(pan.getBytes(UTF_8)));\n"
        "}\n"
    )

    def test_the_measured_defect_is_caught(self) -> None:
        """The exact real diff: only the `getInstance` argument changed, the `SecretKeySpec`
        argument was left behind."""
        broken = self.ORIGINAL_JAVA.replace('getInstance("HmacSHA1")', 'getInstance("HmacSHA256")')

        result = _stage_symbols(broken, "java", self.ORIGINAL_JAVA)

        assert result.status == "fail", result.detail
        assert "HMAC-SHA1" in result.detail and "HS256" in result.detail

    def test_a_consistent_rewrite_of_both_arguments_passes(self) -> None:
        """The near-miss that keeps this from being a blanket ban on touching either literal."""
        fixed = self.ORIGINAL_JAVA.replace("HmacSHA1", "HmacSHA256")

        result = _stage_symbols(fixed, "java", self.ORIGINAL_JAVA)

        assert result.status == "pass", result.detail

    def test_an_unchanged_file_is_never_flagged(self) -> None:
        """A file that mixed algorithms before the patch is not penalised for a pattern the
        patch did not create — see `_new_algorithm_inconsistency`."""
        result = _stage_symbols(self.ORIGINAL_JAVA, "java", self.ORIGINAL_JAVA)

        assert result.status == "pass"

    def test_two_genuinely_different_operations_far_apart_are_not_conflated(self) -> None:
        """The window exists so a file legitimately handling two distinct algorithms — a
        dispatch table, a list of accepted values — is not flagged for merely mentioning both."""
        before = (
            'String legacy() { return sign("HmacSHA1"); }\n'
            + "\n" * 20
            + 'String current() { return sign("HmacSHA256"); }\n'
        )

        from qubit_migrate.transform.validate import _new_algorithm_inconsistency

        assert _new_algorithm_inconsistency(before, "") == []


class TestNamesThePatchItselfBinds:
    """A local the patch declares is not a missing import.

    `unresolved_qualifiers` is differenced against the original file, which cancels a local that
    was always there (`t.Run`, `err.Error`). It cannot cancel one the patch INTRODUCES, because
    the patch is where it first appears -- and a PQC rewrite introduces locals by the handful.

    Measured on this corpus before the fix: one Java patch was rejected for 17 "missing imports",
    13 of which were variables it declared itself; a Go patch was rejected for `priv`, bound on the
    line above its use. Both were otherwise correct migrations, thrown away over a false positive.
    """

    ORIGINAL_GO_KEM = """package p

import (
	"crypto/rsa"
)

func seal() *rsa.PublicKey {
	return nil
}
"""

    def test_a_go_short_declaration_is_not_a_package(self) -> None:
        patched = self.ORIGINAL_GO_KEM.replace(
            "\treturn nil\n",
            "\tek, err := mlkem.GenerateKey768()\n\t_ = err\n\treturn ek.Public()\n",
        ).replace('\t"crypto/rsa"\n', '\t"crypto/rsa"\n\t"crypto/mlkem"\n')

        result = _stage_symbols(patched, "go", self.ORIGINAL_GO_KEM)

        assert result.status == "pass", result.detail
        assert "ek" not in result.detail

    def test_a_go_multiple_assignment_binds_every_name_on_the_left(self) -> None:
        """`pub, priv, err := ...` binds three names; only the right-hand side can need an import."""
        from qubit_migrate.transform.languages import locally_bound

        source = "package p\nfunc f() {\n\tpub, priv, err := mldsa65.GenerateKey(rand.Reader)\n}\n"

        bound = locally_bound(source, "go")

        assert {"pub", "priv", "err"} <= bound
        assert "mldsa65" not in bound, "the right-hand side is a use, not a binding"

    def test_a_java_local_declaration_is_not_a_package(self) -> None:
        # Both versions carry a real import: with none, the stage's safety valve skips the file
        # rather than judging it, and the test would pass without exercising anything.
        original = (
            "import java.security.KeyPairGenerator;\n\n"
            "class C {\n  void m() {\n    int x = 1;\n  }\n}\n"
        )
        patched = (
            "import java.security.KeyPairGenerator;\n\n"
            "class C {\n  void m() {\n"
            '    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");\n'
            "    KeyPair mlkemKeyPair = kpg.generateKeyPair();\n"
            "    byte[] out = mlkemKeyPair.getPublic().getEncoded();\n"
            "  }\n}\n"
        )

        result = _stage_symbols(patched, "java", original)

        assert result.status == "pass", result.detail

    def test_a_java_parameter_is_not_a_package(self) -> None:
        from qubit_migrate.transform.languages import locally_bound

        bound = locally_bound("class C { void m(String arg) { arg.length(); } }", "java")

        assert "arg" in bound

    def test_a_genuinely_missing_import_is_still_caught(self) -> None:
        """The guard against over-correcting: a package that is used, never bound and never
        imported must still fail, or this stage stops doing the job it exists for."""
        patched = self.ORIGINAL_GO_KEM.replace("*rsa.PublicKey", "*mldsa65.PublicKey")

        result = _stage_symbols(patched, "go", self.ORIGINAL_GO_KEM)

        assert result.status == "fail", "mldsa65 is neither imported nor bound anywhere"
        assert "mldsa65" in result.detail


class TestFullyQualifiedReferences:
    """`org.bouncycastle.pqc.jcajce.provider.X` spells its package out and needs no import.

    The qualifier pattern used to match at every interior position of a dotted chain, so this one
    reference yielded `org`, `bouncycastle`, `pqc`, `jcajce` and `provider` as "missing imports".
    Only the first segment of a chain can require an import; each later one is a member of
    whatever the segment before it resolved to.
    """

    def test_an_interior_segment_is_not_reported(self) -> None:
        from qubit_migrate.transform.languages import unresolved_qualifiers

        source = (
            "class C { void m() {\n"
            "  org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider p ="
            " new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider();\n"
            "} }\n"
        )

        unresolved = unresolved_qualifiers(source, "java")

        assert not ({"bouncycastle", "pqc", "jcajce", "provider"} & unresolved), unresolved

    def test_a_reverse_dns_root_is_not_reported(self) -> None:
        from qubit_migrate.transform.languages import unresolved_qualifiers

        source = "class C { void m() { java.security.MessageDigest.getInstance(\"SHA-256\"); } }\n"

        assert "java" not in unresolved_qualifiers(source, "java")

    def test_a_single_segment_qualifier_is_still_read(self) -> None:
        """Narrowing to chain roots must not stop the ordinary `pkg.Symbol` case being seen."""
        from qubit_migrate.transform.languages import unresolved_qualifiers

        assert "mldsa65" in unresolved_qualifiers(
            "package p\nfunc f() { mldsa65.GenerateKey() }\n", "go"
        )


class TestPythonBindingShapes:
    """Python writes a parameter five different ways, and only the plainest is a bare identifier.

    A `typed_parameter` wraps its name beside its ANNOTATION (`peer_public: bytes`), so reading
    every identifier under it would bind the annotation too, and reading only direct `identifier`
    children would bind neither. Taking the first identifier of each parameter is what gets the
    name and nothing else.
    """

    SOURCE = (
        "import os\n"
        "def derive(private_key, peer_public: bytes, salt=None, *args, **kw):\n"
        "    shared = private_key.exchange(peer_public)\n"
        '    with open("f") as fh:\n'
        "        data = fh.read()\n"
        "    for k, v in pairs:\n"
        "        pass\n"
        "    return bytes.fromhex(shared)\n"
    )

    def test_every_parameter_shape_binds_its_name(self) -> None:
        from qubit_migrate.transform.languages import locally_bound

        bound = locally_bound(self.SOURCE, "python")

        assert {"private_key", "peer_public", "salt", "args", "kw"} <= bound

    def test_an_annotation_is_not_a_binding(self) -> None:
        """`peer_public: bytes` binds `peer_public`. `bytes` is the type, not a second name."""
        from qubit_migrate.transform.languages import locally_bound

        assert "bytes" not in locally_bound(self.SOURCE, "python")

    def test_a_with_alias_binds_the_alias_not_the_expression(self) -> None:
        """`with open(p) as fh` binds `fh`. Binding `open` instead would be exactly backwards."""
        from qubit_migrate.transform.languages import locally_bound

        bound = locally_bound(self.SOURCE, "python")

        assert "fh" in bound
        assert "open" not in bound

    def test_a_builtin_used_with_member_access_is_not_a_missing_import(self) -> None:
        """`bytes.fromhex(...)` imports nothing, so reporting `bytes` is the same false positive
        as reporting a local."""
        from qubit_migrate.transform.languages import unresolved_qualifiers

        assert "bytes" not in unresolved_qualifiers(self.SOURCE, "python")

    def test_a_name_that_is_neither_bound_nor_imported_is_still_reported(self) -> None:
        """The over-correction guard for Python: `pairs` is never defined in this file."""
        from qubit_migrate.transform.languages import unresolved_qualifiers

        source = self.SOURCE.replace("for k, v in pairs:", "for k, v in undefined_thing.items():")

        assert "undefined_thing" in unresolved_qualifiers(source, "python")


class TestAnImportStatementIsNotAUse:
    """`from cryptography.hazmat.primitives.kdf.hkdf import HKDF` spells its own package path out,
    and that path is a qualified reference to any regex.

    Scanning the whole file therefore reported `cryptography` as a package nothing imports. It
    cancelled by differencing whenever the import was ALREADY there, and bit exactly when it was
    not -- so a patch that ADDS a dotted `from` import, which is the single most common shape in a
    PQC migration, was rejected for the root of the import it had just added.
    """

    ORIGINAL = "import hashlib\ndef wrap(data):\n    return hashlib.sha1(data).hexdigest()\n"

    def test_adding_a_dotted_from_import_passes(self) -> None:
        patched = (
            "import hashlib\n"
            "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
            "def wrap(data):\n"
            "    return HKDF(algorithm=hashlib.sha256, length=32, salt=None, info=b'')"
            ".derive(data)\n"
        )

        result = _stage_symbols(patched, "python", self.ORIGINAL)

        assert result.status == "pass", result.detail

    def test_adding_a_dotted_go_import_passes(self) -> None:
        before = 'package p\n\nimport (\n\t"crypto/sha1"\n)\n\nfunc h() { sha1.New() }\n'
        after = (
            "package p\n\nimport (\n"
            '\t"github.com/cloudflare/circl/sign/mldsa/mldsa65"\n'
            ")\n\nfunc h() { mldsa65.GenerateKey(nil) }\n"
        )

        result = _stage_symbols(after, "go", before)

        assert result.status == "pass", result.detail

    def test_a_package_used_but_never_imported_still_fails(self) -> None:
        """The over-correction guard: ignoring import statements must not stop this stage seeing
        a qualifier that genuinely has nothing to bind it."""
        patched = "import hashlib\ndef wrap(d):\n    return pqcrypto.kem.encap(d)\n"

        result = _stage_symbols(patched, "python", self.ORIGINAL)

        assert result.status == "fail"
        assert "pqcrypto" in result.detail
