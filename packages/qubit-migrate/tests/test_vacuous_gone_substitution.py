"""When a rule's `gone` list does not name the asset, sometimes the asset can name itself.

`_stage_rescan` narrows its `gone` prefixes to the ones describing the asset's algorithm and, when
none match, falls through to the full list -- which the asset then satisfies by construction. That
is the vacuous case, and it is not a hypothetical cost:

`code-weakcipher-01` declares `gone: [DES, 3DES, RC4, RC2, Blowfish, CAST5, IDEA]` with
`present: [AES]`. For **any** AES asset the `gone` half never matches and the `present` half passes,
so the file is reported already-migrated and no codemod and no model ever runs. Measured on
inkwell-esign through the desktop app: `encrypt_draft` and `decrypt_draft` are AES-128-CBC and were
both parked as finished work -- two of that twin's five migratable findings.

The fix is not "reject every vacuous pass". That was tried, and it breaks the case the probe exists
for: a Go file already using AES-256-GCM resolves to bare `AES` (the key length lives on the key
variable, not the call), the rule matches it, and skipping the model there is correct --
`test_guidance.py::test_a_file_that_already_meets_the_rule_is_not_sent_to_the_model` pins it. The
two cases are the same code path with opposite right answers.

The discriminator is whether the asset's algorithm names a parameter set that is BELOW the floor.
`AES-128` does, so "AES-128 gone from this line" is a criterion it can fail. Bare `AES` does not,
and neither does `AES-256-GCM` -- which is where a correct migration lands, so demanding it change
would send already-correct files to a model.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform.validate import _BELOW_SYMMETRIC_FLOOR, _names_a_parameter


class TestTheDiscriminator:
    @pytest.mark.parametrize("algorithm", ["AES-128", "AES-128-CBC", "AES-192", "aes-128-cbc"])
    def test_a_below_floor_parameter_set_can_name_itself(self, algorithm: str) -> None:
        assert _names_a_parameter(algorithm), (
            f"{algorithm} is below the floor, so 'this is gone' is a criterion it can fail — "
            "leaving it vacuous is what parked the two inkwell AES findings as finished work"
        )

    @pytest.mark.parametrize(
        "algorithm",
        [
            "AES",  # the Go/C spelling of an already-correct file; must stay vacuous
            "AES-256",
            "AES-256-GCM",  # where a correct migration LANDS
            "ChaCha20-Poly1305",
        ],
    )
    def test_an_acceptable_algorithm_is_left_alone(self, algorithm: str) -> None:
        assert not _names_a_parameter(algorithm), (
            f"{algorithm} would be told to migrate away from itself, and the probe that exists to "
            "skip already-correct files would start sending them to a model"
        )

    @pytest.mark.parametrize("algorithm", ["RSA-2048", "SHA-1", "3DES", "MD5", "ECDSA-P256"])
    def test_non_symmetric_and_unparameterised_algorithms_are_untouched(
        self, algorithm: str
    ) -> None:
        """This substitution is scoped to symmetric key sizes only.

        `SHA-1` and `RSA-2048` are named directly by their own rules' `gone` lists, so they never
        reach the vacuous branch — and a digit in the name is not evidence of a key size, which an
        earlier version of this predicate wrongly assumed.
        """
        assert not _names_a_parameter(algorithm)

    def test_the_floor_does_not_include_its_own_target(self) -> None:
        """The guard against the whole class of mistake: never demand a migration away from
        AES-256."""
        assert not any(f.startswith("AES-256") for f in _BELOW_SYMMETRIC_FLOOR)
        assert _BELOW_SYMMETRIC_FLOOR, "an empty floor silently disables the substitution"
