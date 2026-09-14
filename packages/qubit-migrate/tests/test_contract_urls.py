"""A service URL can be the contract, and the guard was reading the wrong place for it.

`_CONTRACT_PATHS` has carried `gravatar` since the module was written — matched against the **file
path**. That refuses a project with a `gravatar.py` and clears every project that puts the same
three lines in `integrations.py`, which is where an application actually puts them.

The knowledge was already right; only the place it was consulted was wrong. `_CONTRACT_URLS` moves
it onto the evidence, which is what the module's own docstring says the rules are supposed to do:

    Matched on the SNIPPET rather than on `auth.py`, so a project that happens to keep its login
    code in a file of that name is not refused for its filename.
"""

from __future__ import annotations

import pytest
from qubit_migrate.protocol_contract import external_contract

#: The Gravatar call as an application writes it, in a file named for what the module does rather
#: than for the service it happens to call. This is the exact shape from the MediVault twin.
GRAVATAR = (
    '    """Gravatar URL for a clinician."""\n'
    "    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()\n"
    '    return f"https://www.gravatar.com/avatar/{digest}?d=identicon"\n'
)


class TestTheUrlIsTheContract:
    def test_a_gravatar_url_in_a_neutrally_named_file_is_refused(self) -> None:
        verdict = external_contract("MD5", "app/services/integrations.py", GRAVATAR)
        assert verdict is not None
        assert "gravatar" in verdict.signal

    def test_the_reason_says_why_rather_than_only_that(self) -> None:
        """An operator reading this has to be able to act on it. 'It is protocol-mandated' is not
        actionable; 'Gravatar addresses an avatar by the MD5 of the lowercased email' is."""
        verdict = external_contract("MD5", "app/services/integrations.py", GRAVATAR)
        assert verdict is not None
        assert "lowercased email" in verdict.reason

    def test_libravatar_too(self) -> None:
        snippet = (
            "    digest = hashlib.md5(email.lower().encode()).hexdigest()\n"
            '    return f"https://seccdn.libravatar.org/avatar/{digest}"\n'
        )
        assert external_contract("MD5", "app/avatars.py", snippet) is not None

    def test_the_file_path_route_still_works(self) -> None:
        """`_CONTRACT_PATHS` is not removed — a `gravatar.py` is still refused on its name, which
        costs nothing and catches a snippet too narrow to include the URL."""
        verdict = external_contract("MD5", "app/gravatar.py", "d = hashlib.md5(x).hexdigest()\n")
        assert verdict is not None
        assert "path contains" in verdict.signal


class TestItDoesNotOverReach:
    """The control. A URL rule that fires on any URL would refuse most of a web application."""

    @pytest.mark.parametrize(
        ("label", "snippet"),
        [
            (
                "a hash near an unrelated URL",
                "    key = hashlib.md5(url.encode()).hexdigest()\n"
                '    return f"https://cdn.example.com/thumbs/{key}.jpg"\n',
            ),
            (
                "a hash with no URL at all",
                "    return hashlib.md5(payload).hexdigest()\n",
            ),
            (
                "an avatar URL that is not addressed by a digest",
                '    return f"https://example.com/avatar/{user_id}.png"\n',
            ),
        ],
    )
    def test_an_unrelated_url_is_not_a_contract(self, label: str, snippet: str) -> None:
        assert external_contract("MD5", "app/services/media.py", snippet) is None, label
