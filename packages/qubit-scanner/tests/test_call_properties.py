"""What the scanner reads at a call site beyond the algorithm name.

Cipher mode, padding scheme, KDF iteration count and PRF are properties of the CALL. Without them
`AES.new(key, AES.MODE_ECB)` and `AES.new(key, AES.MODE_GCM, nonce=n)` are the same finding, and
`PBKDF2` says nothing about whether the KDF is usable. Measured before this existed: the demo
corpus's AES-ECB PII vault produced no finding at all, because `AES.new` had no detection rule --
DES and 3DES were covered as broken primitives and AES is not, which is exactly why the mode has
to be read.
"""

from __future__ import annotations

import pytest
from qubit_scanner import CodeScanner, RuleCatalog
from qubit_scanner.normalize import normalize

_SCANNER = CodeScanner(RuleCatalog.load())


def _assets(source: str, language: str, suffix: str):
    return [
        normalize(d)
        for d in _SCANNER.scan_source(source.encode(), language, file_path=f"probe{suffix}")
    ]


def _extra(asset) -> dict:
    if asset.evidence is None or asset.evidence.context is None:
        return {}
    return dict(asset.evidence.context.extra or {})


def _weakness_ids(asset) -> list[str]:
    return [w["id"] for w in _extra(asset).get("weaknesses", []) if isinstance(w, dict)]


# --- cipher mode ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "language", "suffix", "expected_mode"),
    [
        (
            "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\n",
            "python",
            ".py",
            "ECB",
        ),
        (
            "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM, nonce=n)\n",
            "python",
            ".py",
            "GCM",
        ),
        (
            "import javax.crypto.Cipher;\nclass A { void f() throws Exception {"
            ' Cipher.getInstance("AES/ECB/PKCS5Padding"); } }\n',
            "java",
            ".java",
            "ECB",
        ),
        (
            "import javax.crypto.Cipher;\nclass A { void f() throws Exception {"
            ' Cipher.getInstance("AES/GCM/NoPadding"); } }\n',
            "java",
            ".java",
            "GCM",
        ),
        (
            'import crypto from "node:crypto";\n'
            'const c = crypto.createCipheriv("aes-256-ecb", key, null);\n',
            "javascript",
            ".js",
            "ECB",
        ),
    ],
)
def test_cipher_mode_is_read_from_the_call(
    source: str, language: str, suffix: str, expected_mode: str
) -> None:
    modes = {_extra(a).get("mode") for a in _assets(source, language, suffix)}
    assert expected_mode in modes, f"expected mode {expected_mode}, saw {modes}"


def test_aes_ecb_produces_a_finding_and_aes_gcm_does_not() -> None:
    """The whole point, on the shape that was previously invisible.

    `AES.new` had no rule at all, so the demo corpus's deterministic-PII vault - the clearest ECB
    misuse in the whole corpus - reported only the RSA keygen and the MD5 digest in the same file.
    """
    ecb = _assets(
        "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\n", "python", ".py"
    )
    assert any("ecb-mode" in _weakness_ids(a) for a in ecb), "AES-ECB produced no weakness"
    assert any(a.quantum_vulnerable.vulnerable for a in ecb)

    gcm = _assets(
        "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM, nonce=n)\n",
        "python",
        ".py",
    )
    assert all("ecb-mode" not in _weakness_ids(a) for a in gcm), "AES-GCM was flagged as ECB"


# --- padding ----------------------------------------------------------------------------------


def test_go_rsa_pkcs1v15_is_read_as_a_padding_weakness() -> None:
    source = (
        'package main\n\nimport (\n\t"crypto"\n\t"crypto/rand"\n\t"crypto/rsa"\n)\n\n'
        "func sign(k *rsa.PrivateKey, d []byte) ([]byte, error) {\n"
        "\treturn rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d)\n}\n"
    )
    assets = _assets(source, "go", ".go")
    assert any(_extra(a).get("padding") == "PKCS1v15" for a in assets)
    assert any("pkcs1v15-padding" in _weakness_ids(a) for a in assets)


def test_go_rsa_oaep_is_not_a_padding_weakness() -> None:
    source = (
        'package main\n\nimport (\n\t"crypto/rand"\n\t"crypto/rsa"\n\t"crypto/sha256"\n)\n\n'
        "func seal(k *rsa.PublicKey, m []byte) ([]byte, error) {\n"
        "\treturn rsa.EncryptOAEP(sha256.New(), rand.Reader, k, m, nil)\n}\n"
    )
    assets = _assets(source, "go", ".go")
    assert all("pkcs1v15-padding" not in _weakness_ids(a) for a in assets)


def test_java_rsa_transformation_reports_padding_without_inventing_an_ecb_finding() -> None:
    """`RSA/ECB/PKCS1Padding` must give exactly one weakness, and it is not ECB."""
    source = (
        "import javax.crypto.Cipher;\n"
        'class A { void f() throws Exception { Cipher.getInstance("RSA/ECB/PKCS1Padding"); } }\n'
    )
    for asset in _assets(source, "java", ".java"):
        found = _weakness_ids(asset)
        assert "ecb-mode" not in found, "RSA/ECB was read as a block-cipher mode"


# --- KDF parameters ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "language", "suffix", "iterations"),
    [
        (
            'import hashlib\nd = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)\n',
            "python",
            ".py",
            "1000",
        ),
        (
            "import javax.crypto.spec.PBEKeySpec;\n"
            "class A { void f() { PBEKeySpec s = new PBEKeySpec(pw, salt, 1000, 128); } }\n",
            "java",
            ".java",
            "1000",
        ),
        (
            'import crypto from "node:crypto";\n'
            'const d = crypto.pbkdf2Sync(pw, salt, 1000, 32, "sha256");\n',
            "javascript",
            ".js",
            "1000",
        ),
    ],
)
def test_kdf_iteration_count_is_read(
    source: str, language: str, suffix: str, iterations: str
) -> None:
    counts = {_extra(a).get("iterations") for a in _assets(source, language, suffix)}
    assert iterations in counts, f"expected {iterations} iterations, saw {counts}"


def test_a_weak_kdf_becomes_vulnerable_and_a_strong_one_does_not() -> None:
    weak = _assets(
        'import hashlib\nd = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)\n', "python", ".py"
    )
    assert any("kdf-iterations-below-floor" in _weakness_ids(a) for a in weak)
    assert any(a.quantum_vulnerable.vulnerable for a in weak), (
        "a KDF below the published floor must reach the migration queue"
    )

    strong = _assets(
        'import hashlib\nd = hashlib.pbkdf2_hmac("sha256", pw, salt, 600000)\n', "python", ".py"
    )
    assert all("kdf-iterations-below-floor" not in _weakness_ids(a) for a in strong), (
        "PBKDF2 at the OWASP floor must not be flagged"
    )


def test_prf_is_read_so_the_right_floor_applies() -> None:
    source = (
        "import javax.crypto.SecretKeyFactory;\n"
        "class A { void f() throws Exception {"
        ' SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); } }\n'
    )
    prfs = {_extra(a).get("prf") for a in _assets(source, "java", ".java")}
    assert "SHA1" in prfs, prfs


# --- JWT signature bypass ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "language", "suffix"),
    [
        (
            'import jwt\nclaims = jwt.decode(token, key, options={"verify_signature": False})\n',
            "python",
            ".py",
        ),
        ('import jwt\nclaims = jwt.decode(token, key, algorithms=["none"])\n', "python", ".py"),
        (
            'const jwt = require("jsonwebtoken");\nconst c = jwt.decode(token);\n',
            "javascript",
            ".js",
        ),
        (
            'const jwt = require("jsonwebtoken");\n'
            'const c = jwt.verify(token, key, { algorithms: ["none"] });\n',
            "javascript",
            ".js",
        ),
    ],
)
def test_a_jwt_read_without_verification_is_a_finding(
    source: str, language: str, suffix: str
) -> None:
    """The claim set anyone can write.

    Not a quantum finding, and more urgent than most that are: change `sub` to another user id and
    the application believes it. A crypto scanner that reports the token algorithm while missing
    that nothing verifies it has reported the least important half.
    """
    assets = _assets(source, language, suffix)
    assert any("jwt-signature-not-verified" in _weakness_ids(a) for a in assets), source
    assert any(a.quantum_vulnerable.vulnerable for a in assets), (
        "an unverified token must reach the migration queue"
    )


@pytest.mark.parametrize(
    ("source", "language", "suffix"),
    [
        ('import jwt\nclaims = jwt.decode(token, key, algorithms=["RS256"])\n', "python", ".py"),
        (
            'const jwt = require("jsonwebtoken");\n'
            'const c = jwt.verify(token, key, { algorithms: ["RS256"] });\n',
            "javascript",
            ".js",
        ),
    ],
)
def test_a_correctly_verified_jwt_is_not_flagged(source: str, language: str, suffix: str) -> None:
    """A pinned algorithm with a key is the CORRECT shape and must produce no bypass finding."""
    assets = _assets(source, language, suffix)
    assert all("jwt-signature-not-verified" not in _weakness_ids(a) for a in assets), source


# --- what the surrounding code says the key is FOR -----------------------------------------------


def test_an_rsa_key_inside_a_signer_is_a_signature_not_a_key_exchange() -> None:
    """The defect this closes cost a real, confidently-wrong migration.

    `InvoiceSigner`'s constructor calls `new RSACryptoServiceProvider(1024)`. Classified `kex`,
    it was claimed by `code-kex-01`, which targets ML-KEM-768 - and the model duly produced a
    "migration" replacing a SIGNING key with a key-encapsulation mechanism. Every stage passed it:
    the file parsed, RSA was gone, ML-KEM was present, which is all the rescan asks. The evidence
    needed to prevent it (`enclosing_class: InvoiceSigner`) was already on the finding and nothing
    read it.
    """
    source = (
        "namespace App;\n"
        "public sealed class InvoiceSigner\n{\n"
        "    private readonly RSACryptoServiceProvider _signingKey;\n"
        "    public InvoiceSigner()\n    {\n"
        "        _signingKey = new RSACryptoServiceProvider(1024);\n"
        "    }\n}\n"
    )
    rsa = [a for a in _assets(source, "csharp", ".cs") if a.algorithm.startswith("RSA")]
    assert rsa, "fixture must produce an RSA finding"
    assert all(a.usage_context.value == "signature" for a in rsa), (
        f"a key built inside a signer is not key exchange: {[a.usage_context.value for a in rsa]}"
    )


def test_an_rsa_key_inside_an_encrypt_routine_stays_key_transport() -> None:
    source = (
        "namespace App;\n"
        "public sealed class Envelope\n{\n"
        "    public byte[] EncryptPayload(byte[] data)\n    {\n"
        "        var rsa = new RSACryptoServiceProvider(2048);\n"
        "        return rsa.Encrypt(data, true);\n"
        "    }\n}\n"
    )
    rsa = [a for a in _assets(source, "csharp", ".cs") if a.algorithm.startswith("RSA")]
    assert rsa
    assert all(a.usage_context.value == "kex" for a in rsa)


def test_surroundings_that_say_nothing_leave_the_rule_alone() -> None:
    """A silent guess is worse than the rule's declared usage.

    The reclassification decides which migration rule claims the finding, and that rule will
    carry out whatever it is told - so it fires only on an unambiguous word.
    """
    source = (
        "namespace App;\n"
        "public sealed class Widget\n{\n"
        "    public void Configure()\n    {\n"
        "        var rsa = new RSACryptoServiceProvider(2048);\n"
        "    }\n}\n"
    )
    rsa = [a for a in _assets(source, "csharp", ".cs") if a.algorithm.startswith("RSA")]
    assert rsa
    assert all(a.usage_context.value == "kex" for a in rsa), "the rule's own answer must stand"


def test_the_function_name_outvotes_the_class_name() -> None:
    """The more local fact wins.

    A `TokenVerifier` class with an `EncryptPayload` method is doing key transport in that method
    whatever the class is called; letting the class name decide would relabel the one call site
    that was unambiguous.
    """
    from qubit_scanner.normalize import _usage_from_surroundings

    assert (
        _usage_from_surroundings(
            {"enclosing_function": "EncryptPayload", "enclosing_class": "TokenVerifier"}
        )
        == "kex"
    )
    assert (
        _usage_from_surroundings(
            {"enclosing_function": "Configure", "enclosing_class": "InvoiceSigner"}
        )
        == "signature"
    ), "a function that says nothing falls through to the class, which does"


def test_the_operation_performed_on_a_key_outranks_every_name() -> None:
    """The signal CogniCrypt and CryptoGuard get from typestate and data-flow analysis.

    A key passed to `SignData` is a signing key however its class is named - and a class named
    `Thing` gives no name signal at all while its operations give a decisive one. A full
    flow-sensitive analysis is beyond a tree-sitter query, but the operations invoked in the same
    class are cheap to collect and carry most of the same information.
    """
    head = (
        "namespace App;\npublic sealed class Thing\n{\n"
        "    private readonly RSACryptoServiceProvider _k;\n"
    )
    signer = (
        head + "    public Thing() { _k = new RSACryptoServiceProvider(1024); }\n"
        "    public byte[] Go(byte[] d) => _k.SignData(d, HashAlgorithmName.SHA256);\n}\n"
    )
    transport = (
        head + "    public Thing() { _k = new RSACryptoServiceProvider(2048); }\n"
        "    public byte[] Go(byte[] d) => _k.Encrypt(d, true);\n}\n"
    )
    for source, want in ((signer, "signature"), (transport, "kex")):
        rsa = [a for a in _assets(source, "csharp", ".cs") if a.algorithm.startswith("RSA")]
        assert rsa, "fixture must produce an RSA finding"
        assert all(a.usage_context.value == want for a in rsa), (
            f"expected {want}, got {[a.usage_context.value for a in rsa]}"
        )


def test_the_key_is_found_through_the_class_not_just_the_constructor() -> None:
    """A key built in a constructor and held as a field is USED in a sibling method.

    Scanning only the innermost function finds the constructor, which performs no operation and
    says nothing. The class is where the evidence lives, so both scopes are scanned.
    """
    source = (
        "namespace App;\npublic sealed class Thing\n{\n"
        "    private readonly RSACryptoServiceProvider _k;\n"
        "    public Thing() { _k = new RSACryptoServiceProvider(1024); }\n"
        "    public byte[] Go(byte[] d) => _k.SignData(d);\n}\n"
    )
    rsa = [a for a in _assets(source, "csharp", ".cs") if a.algorithm.startswith("RSA")]
    assert rsa
    assert "signdata" in _extra(rsa[0]).get("scope_operations", "")


def test_a_scope_that_both_signs_and_encrypts_is_left_to_the_names() -> None:
    """Genuinely ambiguous. Guessing here would be worse than deferring."""
    source = (
        "namespace App;\npublic sealed class Thing\n{\n"
        "    private readonly RSACryptoServiceProvider _k;\n"
        "    public Thing() { _k = new RSACryptoServiceProvider(2048); }\n"
        "    public byte[] A(byte[] d) => _k.SignData(d);\n"
        "    public byte[] B(byte[] d) => _k.Encrypt(d, true);\n}\n"
    )
    rsa = [a for a in _assets(source, "csharp", ".cs") if a.algorithm.startswith("RSA")]
    assert rsa
    assert all(a.usage_context.value == "kex" for a in rsa), (
        "with both operations present the rule's own answer must stand"
    )


# ── an EC key generation, and what the surroundings say it is for ───────────────────────────────


def _assets_named(source: str, language: str, file_path: str):
    """Like `_assets`, but the FILE NAME matters to what is under test here."""
    return [
        normalize(d)
        for d in _SCANNER.scan_source(source.encode(), language, file_path=file_path)
    ]


_EC_KEYGEN = (
    "from cryptography.hazmat.primitives.asymmetric import ec\n"
    "\n"
    "def generate_referral_keypair():\n"
    "    private_key = ec.generate_private_key(ec.SECP256R1())\n"
    "    return private_key\n"
)


def test_an_ec_keygen_in_a_key_exchange_module_is_key_agreement() -> None:
    """MV-10, measured on `medivault-emr/app/services/keyexchange.py`.

    `PY-CRYPTOGRAPHY-EC-KEYGEN` hardcodes `ECDSA-P256`/`signature` for every
    `ec.generate_private_key(...)`, because a key generation alone does not say what the key is
    for. Here nothing closer says anything either - the function performs no operation the
    vocabulary knows and is named after neither signing nor transport - so for the whole
    evaluation this P-256 KEY AGREEMENT keypair was routed to `py-signature-01`, a signature rule,
    which then could only refuse it. The file is called `keyexchange.py`.

    The curve is kept and only the operation corrected: it is the same keypair either way.
    """
    ec_assets = [
        a for a in _assets_named(_EC_KEYGEN, "python", "app/services/keyexchange.py")
        if a.algorithm.startswith("EC")
    ]
    assert ec_assets
    assert all(a.algorithm == "ECDH-P256" for a in ec_assets), [a.algorithm for a in ec_assets]
    assert all(a.usage_context.value == "kex" for a in ec_assets)


def test_the_same_keygen_elsewhere_keeps_the_rules_own_answer() -> None:
    """The control, and the reason this is safe to add.

    Identical source, a file name that says nothing. The rule's declared `signature` stands, so
    the only behaviour that changed is the one that was measurably wrong.
    """
    ec_assets = [
        a for a in _assets_named(_EC_KEYGEN, "python", "app/services/util.py")
        if a.algorithm.startswith("EC")
    ]
    assert ec_assets
    assert all(a.algorithm == "ECDSA-P256" for a in ec_assets)
    assert all(a.usage_context.value == "signature" for a in ec_assets)


def test_a_signing_scope_still_beats_the_file_name() -> None:
    """The composite-signature case `test_rescan_e2e` pins, which must not move.

    An EC keygen whose key is passed to `.sign()` in the same scope is a signing key however the
    file is named - the operation is the more local fact, and it is asked first.
    """
    source = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "\n"
        "def sign(data):\n"
        "    classical = ec.generate_private_key(ec.SECP256R1())\n"
        "    return classical.sign(data, ec.ECDSA(None))\n"
    )
    ec_assets = [
        a for a in _assets_named(source, "python", "app/services/keyexchange.py")
        if a.algorithm.startswith("EC")
    ]
    assert ec_assets
    assert all(a.algorithm == "ECDSA-P256" for a in ec_assets), [a.algorithm for a in ec_assets]


def test_a_file_name_is_read_as_whole_words_not_substrings() -> None:
    """`design.py` contains "sign". Splitting first is what keeps every design module out of it."""
    from qubit_scanner.normalize import _path_words, _usage_from_surroundings

    assert _path_words("app/design.py") == ("design",)
    assert _usage_from_surroundings({}, "app/design.py") is None
    assert _usage_from_surroundings({}, "app/services/keyexchange.py") == "kex"
    assert _usage_from_surroundings({}, "app/services/key_exchange.py") == "kex"
    assert _usage_from_surroundings({}, "lib/inkwell/crypto/signing.rb") == "signature"
