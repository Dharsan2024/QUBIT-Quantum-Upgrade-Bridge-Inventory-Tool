"""The classifier that decides what a finding is evidence OF.

It is a screening heuristic, not a verdict, but it is load-bearing: the 26-repository corpus is far
too large to read by hand, and this is what says where reading is worth doing. Its first version got
the headline backwards, so its behaviour is pinned here rather than trusted.

Both directions of error matter, and they are not symmetric:

* Scoring noise as `code` inflates the pattern detectors and makes QUBIT look like it is missing
  cryptography that was never there. This is what happened on gatsbyjs/gatsby.
* Scoring real usage as `substring` dismisses genuine findings as false positives and flatters
  QUBIT. This is what happened to `des.NewTripleDESCipher`.

Cases for both are below, taken from the corpus rather than invented.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from adjudicate import (
    CODE,
    COMMENT,
    NOT_APPLICABLE,
    STRING_LITERAL,
    SUBSTRING,
    classify,
    is_category,
    is_repository_source,
)


class TestSubstringNoise:
    """Real lines from gatsbyjs/gatsby that pqaudit reported as 3DES."""

    @pytest.mark.parametrize(
        "line",
        [
            "id: CODES.BadResponse,",
            "allMarkdownRemark(sort: {frontmatter: {date: DESC}}) {",
            "codesandbox = { ...OPTION_DEFAULT_CODESANDBOX, ...codesandbox }",
            "for (let nodeNum = 0; nodeNum < NUM_NODES; nodeNum++) {",
            'import { CODES } from "./report"',
        ],
    )
    def test_des_inside_a_longer_word_is_not_3des(self, line: str) -> None:
        assert classify(line, "3DES") == SUBSTRING

    def test_ec_inside_encode_is_not_elliptic_curve(self) -> None:
        assert classify("let x = encodesomething()", "EC") == SUBSTRING


class TestRealUsageSurvives:
    """The opposite error: dismissing genuine cryptography as a coincidence of letters."""

    def test_go_camel_case_identifiers_count(self) -> None:
        """`NewTripleDESCipher` really does contain the word `TripleDES`."""
        assert classify("cipher := des.NewTripleDESCipher(key)", "3DES") == CODE

    @pytest.mark.parametrize(
        ("line", "algorithm"),
        [
            ("h := sha1.New()", "SHA-1"),
            ("expectedSHA1 := sha1.Sum(k.Certificates[0].Raw)", "SHA-1"),
            ("priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)", "EC"),
            ("kem := mlkem.GenerateKey768()", "ML-KEM"),
            ("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "RSA"),
            ("const AES_KEY = process.env.AES_KEY", "AES"),
        ],
    )
    def test_ordinary_calls_are_code(self, line: str, algorithm: str) -> None:
        assert classify(line, algorithm) == CODE


class TestMentions:
    """A name that only appears as text: a ban list, a fixture, a lookup key."""

    @pytest.mark.parametrize(
        ("line", "algorithm"),
        [
            ('BannedAlgorithms: []string{"3DES", "RC4", "MD5", "SHA1"},', "3DES"),
            ('"RC4":        "Immediately",', "RC4"),
            ('if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5") {', "SHA-1"),
            ('Cipher.getInstance("DESede/CBC/PKCS5Padding")', "3DES"),
        ],
    )
    def test_quoted_only_is_a_mention(self, line: str, algorithm: str) -> None:
        assert classify(line, algorithm) == STRING_LITERAL

    def test_a_ban_list_is_not_a_usage(self) -> None:
        """The finding this whole module exists for: a project that BANS RC4 is not using RC4."""
        line = 'BannedAlgorithms: []string{"3DES", "RC4", "MD5", "SHA1"},'
        assert classify(line, "RC4") != CODE


class TestComments:
    @pytest.mark.parametrize(
        "line",
        ["// legacy MD5 checksum", "# MD5 is used here for cache keys", "-- MD5 hash"],
    )
    def test_whole_line_comments(self, line: str) -> None:
        assert classify(line, "MD5") == COMMENT

    @pytest.mark.parametrize("line", ["", "   ", "\t"])
    def test_a_blank_line_is_not_a_comment(self, line: str) -> None:
        """A blank line carries no evidence either way, which is what `not-applicable` means.

        It used to be scored `comment`, which put a judgement where the line makes none.
        """
        assert classify(line, "MD5") == NOT_APPLICABLE


class TestTrailingComments:
    """Only whole-line comments used to be detected, so a trailing one scored as real usage.

    That biases the use/mention split towards USE, in the same direction as the human-vs-model
    disagreement, so the two compounded rather than cancelling.
    """

    @pytest.mark.parametrize(
        "line",
        [
            "x = 1  # uses MD5 historically",
            "hash := sha256.New()  // replaced MD5 in 2019",
            "value = compute()  /* MD5 was here */",
        ],
    )
    def test_a_name_only_in_a_trailing_comment_is_a_comment(self, line: str) -> None:
        assert classify(line, "MD5") == COMMENT

    def test_a_name_in_the_code_part_survives_a_trailing_comment(self) -> None:
        """The cut must not swallow real usage that happens to sit on a commented line."""
        assert classify("h = md5.New()  // legacy, remove me", "MD5") == CODE

    def test_a_marker_inside_a_string_does_not_truncate_the_line(self) -> None:
        """Quotes are blanked before the marker search, so a URL is not read as a comment."""
        assert classify('client.Get("https://example.com/x")  # fine', "MD5") == SUBSTRING
        assert classify('h = md5.New("//not-a-comment")', "MD5") == CODE

    def test_a_marker_without_leading_space_is_not_a_comment(self) -> None:
        """`https://md5.example.com` has no whitespace before the `//`, so nothing is cut."""
        assert classify('url = "https://md5.example.com"', "MD5") == STRING_LITERAL


class TestBoundaries:
    def test_underscores_and_hyphens_are_boundaries(self) -> None:
        """`\\b` treats `_` as a word character, which would hide `AES` in `AES_KEY`."""
        assert classify("cfg.AES_KEY = load()", "AES") == CODE
        assert classify("const sha-1-hash = x", "SHA-1") == CODE

    def test_an_uppercase_neighbour_is_not_a_word_break(self) -> None:
        """`CO|DES` must stay noise even though `New|TripleDES` is a real break."""
        assert classify("return CODES.Timeout", "3DES") == SUBSTRING

    def test_an_empty_algorithm_makes_no_claim(self) -> None:
        """There is no name to look for, so there is no answer. It used to say `code` --
        confidently, about nothing."""
        assert classify("something", "") == NOT_APPLICABLE
        assert classify("something", "   ") == NOT_APPLICABLE


class TestCategoriesItCannotJudge:
    """QUBIT's HNDL pass reports categories, not algorithm names.

    `PII: EMAIL ADDRESS` is never the text of the line it was found on, so a classifier that
    searches for the family name finds nothing and concludes the finding is a coincidence of
    letters. All nine of QUBIT's exclusive findings on gatsbyjs/gatsby were scored `substring`
    that way -- real detections dismissed as noise by a heuristic that had no business ruling on
    them at all.
    """

    @pytest.mark.parametrize(
        ("line", "family"),
        [
            ('email: { "en-US": `john@doe.com` },', "PII: EMAIL ADDRESS"),
            ('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG"', "SECRET: AWS ACCESS KEY"),
            ("card = '4111111111111111'", "PII: CREDIT CARD"),
        ],
    )
    def test_a_category_is_not_scored(self, line: str, family: str) -> None:
        assert classify(line, family) == NOT_APPLICABLE

    def test_it_does_not_silently_become_absent(self) -> None:
        """The specific regression: `substring` reads as "the detector was wrong"."""
        assert classify("siteEmailUrl: `me@x.com`,", "PII: EMAIL ADDRESS") != SUBSTRING


class TestFilePopulation:
    """Which files the corpus is about, applied identically to every detector."""

    @pytest.mark.parametrize(
        "path",
        [
            ".yarn/releases/yarn-1.21.0.js",
            "node_modules/bcrypt/index.js",
            "vendor/golang.org/x/crypto/sha3/sha3.go",
            "third_party/openssl/crypto/rsa/rsa_lib.c",
            "web/dist/bundle.js",
        ],
    )
    def test_vendored_code_is_not_this_repositorys_cryptography(self, path: str) -> None:
        assert not is_repository_source(path)

    @pytest.mark.parametrize(
        "path",
        [
            "packages/gatsby/src/schema/queries.js",
            "internal/analyzer/cnsa2.go",
            "src/main/java/com/example/Crypto.java",
        ],
    )
    def test_the_repositorys_own_source_is_kept(self, path: str) -> None:
        assert is_repository_source(path)

    def test_a_data_file_is_not_source(self) -> None:
        """The cryptodeps case: 3 432 findings in one JSON lookup table."""
        assert not is_repository_source("data/crypto-database.json")

    def test_a_directory_name_matches_only_as_a_whole_segment(self) -> None:
        """`vendor` must not exclude `src/vendored_helpers.py` or `app/vendors/list.py`."""
        assert is_repository_source("src/vendored_helpers.py")
        assert is_repository_source("app/vendors/list.py")


class TestDigitBoundary:
    """The classifier's largest single error, found by hand-labelling 601 of its own outputs.

    `_bounded` accepted a word break only at punctuation or a camelCase hump, so a DIGIT after the
    name was treated as the word continuing: `SHA` could not match `sha256`, `ARGON2` could not
    match `argon2i`, `CHACHA20` could not match `chacha20poly1305`. `hmac.New(sha256.New, key)` --
    a plain, unmistakable use -- was scored as a coincidence of letters.

    107 of the 601 labelled findings were wrong for this one reason, and Cohen's kappa against the
    hand labels was 0.279 because of it.
    """

    @pytest.mark.parametrize(
        ("line", "algorithm"),
        [
            ("mac := hmac.New(sha256.New, []byte(secret))", "SHA"),
            ("SHA256_Update(&ctx, buf, len);", "SHA"),
            ("return await argon2.hash(password)", "ARGON2"),
            ("let sealed = try ChaChaPoly.seal(inner, using: key)", "POLY1305"),
            ("h = md5.new()", "MD5"),
            ("cipher = AES128_CBC_encrypt(key)", "AES"),
        ],
    )
    def test_a_digit_after_the_name_is_a_word_break(self, line: str, algorithm: str) -> None:
        assert classify(line, algorithm) == CODE

    def test_a_quoted_algorithm_argument_is_still_only_a_string(self) -> None:
        """The boundary fix reaches the name; it does not decide what the name is doing there.

        `createHash('sha256')` selects SHA-256 as plainly as any call can, and this classifier still
        says `string-literal`, because its only rule is "does the name survive outside quotes". That
        is the largest remaining disagreement with the hand labels -- 29 of 449 -- and it is a limit
        of the design rather than a bug in it. A classifier that guessed which quoted names are
        arguments and which are ban-list entries would be the AST detector this benchmark exists to
        measure.
        """
        assert classify("const hash = createHash('sha256')", "SHA") == STRING_LITERAL

    def test_it_does_not_reopen_the_substring_hole(self) -> None:
        """The left boundary is what rejects `CODES`, so relaxing the right one is safe."""
        assert classify("id: CODES.BadResponse,", "3DES") == SUBSTRING
        assert classify("bag[j] = NNODES - j - 1;", "3DES") == SUBSTRING
        assert classify("var c = HTML_CODES[i];", "3DES") == SUBSTRING


class TestSpellingsFoundByHand:
    """Names the corpus writes in a way no general rule reaches."""

    @pytest.mark.parametrize(
        ("line", "algorithm"),
        [
            ("openssl genrsa -out ${SSL_KEY} 2048", "RSA"),
            ("openssl dhparam -out tests/tls/redis.dh 2048", "DH"),
            ("if not DiffieHellman.is_valid_public_key_static(k, prime):", "DH"),
            ('else if (!strcasecmp(tokens[i], "tlsv1.3")) {', "TLS"),
            ("_ = try XChaCha20Poly1305Compat.seal(plaintext: p, key: k)", "CHACHA20"),
        ],
    )
    def test_the_spelling_the_corpus_actually_uses(self, line: str, algorithm: str) -> None:
        assert classify(line, algorithm) in {CODE, STRING_LITERAL}

    def test_a_wrapped_family_is_unwrapped(self) -> None:
        """`UNKNOWN(CHACHAPOLY)` is a real family label: search for what it wrapped."""
        line = "let sealed = try ChaChaPoly.seal(inner, using: symmetricKey)"
        assert classify(line, "UNKNOWN(CHACHAPOLY)") == CODE


class TestCategoriesWithoutPunctuationTells:
    """The `":"` test caught `PII: EMAIL ADDRESS` and missed four more categories.

    35 further findings were scored `substring` -- "the detector matched nothing real" -- for
    families that this classifier had no business ruling on at all.
    """

    @pytest.mark.parametrize(
        ("line", "family"),
        [
            ('APIKey:   "test-key",', "HARDCODED PASSWORD/SECRET"),
            ('"TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"', "GITHUB TOKEN"),
            ('pem := "-----BEGIN PRIVATE KEY-----\n" +', "PRIVATE KEY MATERIAL"),
            ("this(MessageDigest.getInstance(algorithm), extension)", "RUNTIME"),
        ],
    )
    def test_a_category_is_not_scored(self, line: str, family: str) -> None:
        assert classify(line, family) == NOT_APPLICABLE

    def test_an_algorithm_name_containing_a_dot_is_still_scored(self) -> None:
        """`X.509` is a name, not a category: only spaces, colons and slashes disqualify."""
        assert not is_category("X.509")
        assert not is_category("SHA-1")
