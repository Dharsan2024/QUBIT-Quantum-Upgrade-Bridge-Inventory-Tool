"""What QUBIT learns from its own migrations, and what it used to throw away.

The line cache learns only the easiest fixes: `record` refuses any rewrite whose line count moved,
which is exactly the multi-statement change the generator prompt asks for. Measured on this
project's own store, it held 21 rows against 59 accepted LLM patches - roughly two thirds of
everything the model got RIGHT taught it nothing, and the harder the rewrite the more certain it
was to be discarded.

These pin the four properties that fixes:

* a whole-function rewrite is retained;
* a rejection is retained, so the next attempt is warned instead of rediscovering it;
* the model's own verified reasoning is retained and replayed;
* retrieval is by STRUCTURAL SHAPE, so two findings differing only in variable names match.
"""

from __future__ import annotations

import pytest
from qubit_core.db import Base, session_factory
from qubit_core.db.models import LearnedOutcome
from qubit_migrate.transform import learn
from sqlalchemy import create_engine, select


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'x.db').as_posix()}")
    Base.metadata.create_all(engine)
    with session_factory(engine)() as s:
        yield s


# --- the shape key ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "same"),
    [
        # Names differ, the call is the same problem. The exact-line cache sees two unrelated
        # findings here, which is why it answered so few reuses across a repetitive corpus.
        (
            "digest = hashlib.md5(payload).hexdigest()",
            "checksum = hashlib.md5(data).hexdigest()",
            True,
        ),
        # The algorithm is the whole point and must separate.
        (
            "digest = hashlib.md5(payload).hexdigest()",
            "digest = hashlib.sha1(payload).hexdigest()",
            False,
        ),
        # The MODE is the finding for an ECB migration; folding it away would make an ECB call and
        # a GCM call the same shape, which is the one distinction that matters here.
        ("c = AES.new(key, AES.MODE_ECB)", "c = AES.new(key, AES.MODE_GCM)", False),
        ("c = AES.new(k1, AES.MODE_ECB)", "cipher = AES.new(secret, AES.MODE_ECB)", True),
        (
            'crypto.createCipheriv("aes-256-ecb", key, null)',
            'crypto.createCipheriv("aes-256-gcm", key, n)',
            False,
        ),
        # A parameter VALUE is not part of the shape - the same migration applies at any count.
        (
            'hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)',
            'hashlib.pbkdf2_hmac("sha256", password, s, 600000)',
            True,
        ),
    ],
)
def test_shape_collapses_names_and_separates_meaning(left: str, right: str, same: bool) -> None:
    assert (learn.shape_key("r", "python", left) == learn.shape_key("r", "python", right)) is same


def test_language_never_collides() -> None:
    assert learn.shape_key("r", "go", "x = md5(a)") != learn.shape_key("r", "java", "x = md5(a)")


def test_a_language_the_lookup_cannot_ask_for_is_normalised() -> None:
    """`multi` is a RULE's language, never a file's, so a row carrying it can never be retrieved.

    17 of the 21 rows in this installation's older store are in exactly that state - written with
    the rule's language while every lookup passes the file's, so they were dead for grounding from
    the moment they were created.
    """
    assert learn.shape_key("r", "multi", "x") == learn.shape_key("r", "unknown", "x")


# --- hunks --------------------------------------------------------------------------------------


def test_a_multi_line_rewrite_is_retained() -> None:
    """The case the line cache drops on the floor."""
    before = (
        "def seal(key, data):\n    c = AES.new(key, AES.MODE_ECB)\n    return c.encrypt(data)\n"
    )
    after = (
        "def seal(key, data):\n"
        "    nonce = os.urandom(12)\n"
        "    c = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
        "    ct, tag = c.encrypt_and_digest(data)\n"
        "    return nonce + ct + tag\n"
    )
    hunk_before, hunk_after = learn.extract_hunk(before, after, 2)
    assert "MODE_ECB" in hunk_before
    assert "MODE_GCM" in hunk_after and "nonce" in hunk_after
    # `record` would keep nothing at all here: the line count moved.
    assert len(before.splitlines()) != len(after.splitlines())


def test_a_hunk_is_not_the_whole_file() -> None:
    """Several hunks have to fit in a 7B model's prompt beside the file being edited."""
    before = "\n".join(f"line{i}" for i in range(300))
    after = before.replace("line150", "CHANGED")
    hunk_before, hunk_after = learn.extract_hunk(before, after, 151)
    assert len(hunk_before.splitlines()) < 30, "a hunk that large is just the file again"
    assert "line150" in hunk_before and "CHANGED" in hunk_after


# --- the store ----------------------------------------------------------------------------------


def test_a_success_is_retrievable_by_shape_with_its_reasoning(session) -> None:
    shape = learn.shape_key("code-ecb-01", "python", "c = AES.new(key, AES.MODE_ECB)")
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape=shape,
        passed=True,
        hunk_before="c = AES.new(key, AES.MODE_ECB)",
        hunk_after="c = AES.new(key, AES.MODE_GCM, nonce=nonce)",
        reasoning="- Fresh nonce per message, stored with the ciphertext.",
        model_name="m",
    )
    session.commit()

    # A DIFFERENT file, same structure, different names.
    other = learn.shape_key("code-ecb-01", "python", "cipher = AES.new(secret, AES.MODE_ECB)")
    assert other == shape, "the point of the shape key"
    found = learn.experience_for(session, rule_id="code-ecb-01", language="python", shape=other)
    assert found.exact_shape, "a structurally identical rewrite is the strongest grounding there is"
    assert found.proven[0][1] == "c = AES.new(key, AES.MODE_GCM, nonce=nonce)"
    assert "Fresh nonce" in found.proven[0][2], "the verified reasoning must come back with it"


def test_a_failure_is_retained_and_replayed_as_a_warning(session) -> None:
    """The half that was never learned from at all.

    29 genuine failures across today's runs taught the store nothing. The next attempt at the same
    shape started from zero and spent three more model calls rediscovering the same rejection.
    """
    shape = learn.shape_key("code-kex-01", "rust", "let key = Rsa::generate(1024)?;")
    learn.record_outcome(
        session,
        rule_id="code-kex-01",
        language="rust",
        algorithm="RSA-1024",
        shape=shape,
        passed=False,
        hunk_before="let key = Rsa::generate(1024)?;",
        failure_reason="the file came back unchanged - the flagged algorithm was not migrated",
        model_name="m",
    )
    session.commit()

    found = learn.experience_for(session, rule_id="code-kex-01", language="rust", shape=shape)
    assert found.failures == [
        "the file came back unchanged - the flagged algorithm was not migrated"
    ]
    assert not found.proven, "a failure must never be offered as an example to copy"


def test_the_same_lesson_is_not_stored_twice(session) -> None:
    """A corpus repeats itself; fifty copies of one lesson crowd the prompt without adding to it."""
    shape = learn.shape_key("code-ecb-01", "python", "c = AES.new(key, AES.MODE_ECB)")
    for _ in range(4):
        learn.record_outcome(
            session,
            rule_id="code-ecb-01",
            language="python",
            algorithm="AES",
            shape=shape,
            passed=True,
            hunk_before="before",
            hunk_after="after",
        )
    session.commit()
    rows = session.scalars(select(LearnedOutcome)).all()
    assert len(rows) == 1
    assert rows[0].hit_count == 3, "repeats rank the evidence instead of duplicating it"


def test_reasoning_is_filled_in_by_a_later_run_that_has_it(session) -> None:
    shape = learn.shape_key("code-ecb-01", "python", "c = AES.new(key, AES.MODE_ECB)")
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape=shape,
        passed=True,
        hunk_before="b",
        hunk_after="a",
        reasoning="",
    )
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape=shape,
        passed=True,
        hunk_before="b",
        hunk_after="a",
        reasoning="- The nonce is fresh per message.",
    )
    session.commit()
    row = session.scalars(select(LearnedOutcome)).one()
    assert "nonce is fresh" in row.reasoning


def test_reliability_counts_both_sides(session) -> None:
    """Reported, never used to refuse work - a ceiling measured on one model is not the task's."""
    for i, passed in enumerate([True, False, False]):
        learn.record_outcome(
            session,
            rule_id="code-kex-01",
            language="go",
            algorithm="RSA",
            shape=f"shape{i}",
            passed=passed,
            hunk_before="b",
            hunk_after="a" if passed else "",
            failure_reason="" if passed else "unchanged",
        )
    session.commit()
    assert learn.reliability(session, rule_id="code-kex-01", language="go") == (1, 2)


def test_grounding_prefers_the_same_shape_then_the_most_reused(session) -> None:
    exact = learn.shape_key("code-ecb-01", "python", "c = AES.new(key, AES.MODE_ECB)")
    for i in range(3):
        learn.record_outcome(
            session,
            rule_id="code-ecb-01",
            language="python",
            algorithm="AES",
            shape=f"other{i}",
            passed=True,
            hunk_before=f"other-before-{i}",
            hunk_after=f"other-after-{i}",
        )
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape=exact,
        passed=True,
        hunk_before="exact-before",
        hunk_after="exact-after",
    )
    session.commit()
    found = learn.experience_for(
        session, rule_id="code-ecb-01", language="python", shape=exact, limit=3
    )
    assert found.exact_shape
    assert found.proven[0][0] == "exact-before", "the same shape has to come first"
    assert len(found.proven) == 3


def test_nothing_learned_yet_is_an_empty_experience(session) -> None:
    found = learn.experience_for(session, rule_id="code-ecb-01", language="python", shape="s")
    assert not found
    assert not found.proven and not found.failures


def test_the_shape_vocabulary_follows_the_algorithm_registry() -> None:
    """A hand-kept list of primitives falls behind the registry the first time one is added.

    A shape key that does not recognise an algorithm folds it to `_`, which makes two DIFFERENT
    algorithms hash to the same shape - the one failure this key must never have. So the
    vocabulary is derived from the canonical registry rather than typed out beside it.
    """
    from qubit_core import algorithms
    from qubit_migrate.transform.learn import _ALIAS_STOPWORDS, _KEEP

    for entry in algorithms.ALGORITHMS:
        flat = "".join(ch for ch in entry.canonical.lower() if ch.isalnum())
        if flat.isdigit() or len(flat) < 3 or flat in _ALIAS_STOPWORDS:
            # The stoplist is deliberate and tested by the case below: a registry name that is
            # also an ordinary word in ordinary code costs more as a token than it is worth.
            continue
        assert flat in _KEEP, f"{entry.canonical} is in the registry and unknown to the shape key"


def test_an_ordinary_word_that_happens_to_be_an_alias_is_not_a_crypto_token() -> None:
    """The price of deriving from aliases, paid deliberately.

    `null` is a registry alias and also a JavaScript literal. Folded in, it broke a real shape
    match: `createCipheriv("aes-256-ecb", key, null)` and the same call with an IV stopped being
    the same shape. Better to drop three words than to make every `null` cryptographic.
    """
    left = learn.shape_key("r", "javascript", 'crypto.createCipheriv("aes-256-ecb", key, null)')
    right = learn.shape_key("r", "javascript", 'crypto.createCipheriv("aes-256-ecb", k, iv)')
    assert left == right


# --- near-miss retrieval (Type-3) -----------------------------------------------------------------


def test_overlap_similarity_is_sourcerercc_s_formula() -> None:
    """`S(M1, M2) = |M1 ∩ M2| / max(|M1|, |M2|)` over token multisets.

    Adopted rather than invented: it is the published measure for near-miss clone detection, and
    multiset intersection is what makes it sensitive to a repeated call rather than treating
    presence as binary.
    """
    from collections import Counter

    assert learn.overlap_similarity(Counter("aab"), Counter("aab")) == 1.0
    assert learn.overlap_similarity(Counter("aab"), Counter("ab")) == 2 / 3
    assert learn.overlap_similarity(Counter("ab"), Counter("cd")) == 0.0
    assert learn.overlap_similarity(Counter(), Counter("ab")) == 0.0


def test_a_statement_added_around_the_call_still_matches() -> None:
    """The case the exact shape key cannot reach.

    The key hashes an ORDERED token sequence, so it finds only Type-1 and Type-2 clones - the same
    code, and code differing in names. One extra statement changes the hash completely, and that
    is the common case in a real repository: the same call wrapped in a try/except.
    """
    plain = "cipher = AES.new(key, AES.MODE_ECB)"
    wrapped = "try:\n    cipher = AES.new(secret, AES.MODE_ECB)\nexcept ValueError:\n    raise"
    assert learn.shape_key("r", "python", plain) != learn.shape_key("r", "python", wrapped), (
        "if these hashed equal there would be nothing for the near-miss tier to do"
    )
    score = learn.overlap_similarity(
        learn.token_bag("r", "python", plain), learn.token_bag("r", "python", wrapped)
    )
    assert score >= learn.NEAR_MISS_THRESHOLD, score


def test_a_different_mode_stays_below_the_threshold() -> None:
    """Near-miss must not become "near enough". ECB and GCM are the distinction that matters."""
    score = learn.overlap_similarity(
        learn.token_bag("r", "python", "c = AES.new(key, AES.MODE_ECB)"),
        learn.token_bag("r", "python", "c = AES.new(key, AES.MODE_GCM, nonce=n)"),
    )
    assert score < learn.NEAR_MISS_THRESHOLD, score


def test_the_near_miss_tier_retrieves_and_says_so(session) -> None:
    stored = "cipher = AES.new(key, AES.MODE_ECB)"
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape=learn.shape_key("code-ecb-01", "python", stored),
        passed=True,
        hunk_before=stored,
        hunk_after="cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)",
        reasoning="- Fresh nonce per message.",
    )
    session.commit()

    query = "try:\n    cipher = AES.new(secret, AES.MODE_ECB)\nexcept ValueError:\n    raise"
    found = learn.experience_for(
        session,
        rule_id="code-ecb-01",
        language="python",
        shape=learn.shape_key("code-ecb-01", "python", query),
        text=query,
    )
    assert found.proven, "the near-miss tier found nothing the exact key had missed"
    assert found.near_miss and not found.exact_shape, (
        "it must report WHICH tier answered - claiming an exact shape would be a false claim"
    )


# --- false negatives --------------------------------------------------------------------------


def test_a_rejection_the_checker_caused_is_not_learned(session) -> None:
    """A bad negative example misleads rather than teaches.

    `unverifiable_reason` already diagnoses the case: a `present` expectation fails when QUBIT
    ships no verified target shape for that language, so no output could have satisfied it.
    Retaining that as "this shape defeats the model" would tell the next attempt to avoid a
    rewrite that may have been perfectly good.
    """
    unwinnable = (
        "LLM rewrite rejected after 3 attempt(s): Expected one of ['ML-KEM'] present, but not "
        "found. QUBIT ships no verified ML-KEM shape for ruby, so the rescan may be unsatisfiable "
        "here regardless of what is generated"
    )
    assert learn.is_false_negative(unwinnable)
    learn.record_outcome(
        session,
        rule_id="code-kex-01",
        language="ruby",
        algorithm="RSA",
        shape="s",
        passed=False,
        hunk_before="x",
        failure_reason=unwinnable,
    )
    session.commit()
    assert session.scalars(select(LearnedOutcome)).all() == []


def test_a_real_rejection_is_still_learned(session) -> None:
    real = "LLM rewrite rejected after 3 attempt(s): the file came back unchanged"
    assert not learn.is_false_negative(real)
    learn.record_outcome(
        session,
        rule_id="code-kex-01",
        language="ruby",
        algorithm="RSA",
        shape="s",
        passed=False,
        hunk_before="x",
        failure_reason=real,
    )
    session.commit()
    assert len(session.scalars(select(LearnedOutcome)).all()) == 1


def test_an_exact_hit_topped_up_by_the_near_miss_tier_is_still_reported_as_exact(session) -> None:
    """The two flags decide what the prompt CLAIMS, so they have to mean what they say.

    The near-miss tier also runs to top up an exact hit with more evidence. Flagging that as a
    near miss would make the prompt say "very close" about code that is structurally identical -
    understating what was found.
    """
    text = "cipher = AES.new(key, AES.MODE_ECB)"
    shape = learn.shape_key("code-ecb-01", "python", text)
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape=shape,
        passed=True,
        hunk_before=text,
        hunk_after="cipher = AES.new(key, AES.MODE_GCM, nonce=n)",
    )
    learn.record_outcome(
        session,
        rule_id="code-ecb-01",
        language="python",
        algorithm="AES",
        shape="a-different-shape",
        passed=True,
        hunk_before="c = AES.new(k, AES.MODE_ECB)  # near, not identical",
        hunk_after="c = AES.new(k, AES.MODE_GCM, nonce=n)",
    )
    session.commit()

    found = learn.experience_for(
        session, rule_id="code-ecb-01", language="python", shape=shape, text=text
    )
    assert found.exact_shape, "the identical shape is present and must be reported"
    assert not found.near_miss, "an exact hit topped up is not a near miss"
