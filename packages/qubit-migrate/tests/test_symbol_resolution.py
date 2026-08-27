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
