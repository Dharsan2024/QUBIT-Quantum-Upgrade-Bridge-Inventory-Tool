"""The recommendation endpoint must report the construction the rule actually declares.

Found by driving the native app: `/assets/{id}/recommendation` returned
`"target": {"algorithm": "ML-KEM-768", "mode": "pure"}` while its own `rationale` in the same
response read "Migrate to a HYBRID construction".

The cause was that tier 1 recomputed the mode by searching the target's NAME for the word
"hybrid". No hybrid is named that way — `X25519MLKEM768` is the industry standard and the agility
policy's own default — so every rule carrying `mode: hybrid` was reported as `pure`.

It matters beyond the inconsistency: a pure ML-KEM-768 is an ANSSI certified-track violation and a
BSI advisory, while X25519MLKEM768 satisfies both. Reporting the wrong construction inverts the
compliance answer for the asset class that most needs it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from qubit_migrate.regimes import is_hybrid
from qubit_migrate.transform.rules import load_rules
from test_api import _make_client, _wait_for_scan


def _declared_targets() -> list[tuple[str, dict]]:
    return [(r.id, r.target or {}) for r in load_rules() if (r.target or {}).get("mode")]


class TestTheDeclaredConstructionIsReported:
    """A rule that states `mode:` is authoritative about its own construction."""

    def test_the_catalog_actually_contains_hybrid_rules(self) -> None:
        """Guards the fixture. If no rule declared `mode: hybrid`, every assertion below would
        hold vacuously and this file would prove nothing."""
        modes = {t["mode"] for _, t in _declared_targets()}
        assert "hybrid" in modes
        assert "pure" in modes

    @pytest.mark.parametrize("rule_id,target", _declared_targets())
    def test_the_structural_check_agrees_with_every_declaration(
        self, rule_id: str, target: dict
    ) -> None:
        """`is_hybrid` is the fallback for rules that omit `mode`, so it must not contradict the
        ones that state it. A disagreement means the fallback would mislabel a rule the moment its
        `mode` were dropped."""
        pqc = target.get("pqc_target") or target.get("algorithm", "")
        structural = "hybrid" if is_hybrid(pqc, target.get("hybrid_group"), None) else "pure"
        assert structural == target["mode"], rule_id

    def test_the_naive_substring_check_would_get_most_of_them_wrong(self) -> None:
        """The regression this file exists for, stated as a measurement rather than a story.

        If this ever drops to zero it means no rule targets a hybrid any more, and the guard above
        has quietly stopped testing anything.
        """
        wrong = [
            rule_id
            for rule_id, target in _declared_targets()
            if ("hybrid" in (target.get("pqc_target") or target.get("algorithm", "")).lower())
            != (target["mode"] == "hybrid")
        ]
        assert len(wrong) >= 10, (
            f"expected the substring check to mislabel most hybrid rules; it mislabels {len(wrong)}"
        )


class TestTheEndpointReadsTheDeclaration:
    """The fix through the ENDPOINT, not through a copy of its logic.

    An earlier version of this class re-implemented the resolution inline and asserted on the
    result. A mutation run reverting the endpoint to the substring search left it green — it was
    testing a paraphrase. This drives the real route.
    """

    def test_an_undeclared_mode_falls_back_to_structure_not_spelling(self) -> None:
        """`X25519MLKEM768` carries no "hybrid" in its name and must still read as one."""
        assert is_hybrid("X25519MLKEM768", None, None)
        assert is_hybrid("ML-KEM-768", "X25519MLKEM768", None)
        assert not is_hybrid("ML-KEM-1024", None, None)

    def test_the_route_reports_hybrid_for_a_hybrid_rule(self, tmp_path: Path) -> None:
        """End to end: scan a repo with a Diffie-Hellman key agreement, ask for the
        recommendation, and require the reported construction to be the hybrid the rule declares.

        This is the case the bug was found on — a `kex` asset, which is the harvest-now-decrypt-
        later class and the one where the construction matters most.
        """
        repo = tmp_path / "repo"
        repo.mkdir()
        # Finite-field DH deliberately, not ECDH. When this was written an
        # `ec.generate_private_key(...)` / `.exchange(ec.ECDH(), ...)` pair produced only a
        # `signature` asset, so it would have exercised the wrong rule; that gap is now closed by
        # `PY-CRYPTOGRAPHY-ECDH-EXCHANGE` and covered by `TestECDHIsClassifiedAsKeyAgreement`
        # below. The fixture stays on `dh.generate_parameters` regardless: it yields exactly one
        # kex asset, where the `ec` form still yields a spurious signature asset beside the real
        # one, and this test is about the ENDPOINT's construction reporting rather than about
        # detection.
        (repo / "app.py").write_text(
            "from cryptography.hazmat.primitives.asymmetric import dh\n"
            "params = dh.generate_parameters(generator=2, key_size=2048)\n"
            "private_key = params.generate_private_key()\n",
            encoding="utf-8",
        )

        with _make_client(tmp_path) as client:
            pid = client.post(
                "/api/v1/projects", json={"name": "construction", "root_path": str(repo)}
            ).json()["id"]
            scan_id = client.post(
                f"/api/v1/projects/{pid}/scans", json={"targets": [str(repo)]}
            ).json()["scan"]["id"]
            assert _wait_for_scan(client, scan_id)["status"] == "succeeded"

            assets = client.get(f"/api/v1/scans/{scan_id}/assets").json()["items"]
            # By usage context, not by algorithm name. The same file's `generate_private_key` is an
            # EC asset too, and it is a SIGNATURE asset whose correct target is a pure ML-DSA-65 —
            # picking the first EC match tests the wrong rule and fails for the right reason.
            asset = next((a for a in assets if a.get("usage_context") == "kex"), None)
            # Asserted, not skipped. A skip here would make this file green while proving
            # nothing, which is the exact failure mode the rest of the project keeps finding.
            assert asset is not None, [a["algorithm"] for a in assets]

            rec = client.get(f"/api/v1/assets/{asset['id']}/recommendation")
            assert rec.status_code == 200, rec.text
            body = rec.json()
            if body["source"] != "rule":
                pytest.skip(f"asset resolved via {body['source']}, not the tier under test")

            target = body["target"]
            # The bug: `mode` was recomputed from the target's NAME, so this read "pure".
            assert target["mode"] == "hybrid", target
            # And the operator is told WHICH hybrid, because the regimes disagree on exactly that.
            assert target.get("hybrid_group"), target

    def test_the_route_does_not_call_a_pure_target_hybrid(self, tmp_path: Path) -> None:
        """The other direction, so the fix cannot be "always say hybrid".

        A weak-hash finding migrates to SHA-256. There is no hybrid construction for a hash, and
        reporting one would be as wrong as the original bug.
        """
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "import hashlib\ndigest = hashlib.md5(data).hexdigest()\n", encoding="utf-8"
        )

        with _make_client(tmp_path) as client:
            pid = client.post(
                "/api/v1/projects", json={"name": "pure-case", "root_path": str(repo)}
            ).json()["id"]
            scan_id = client.post(
                f"/api/v1/projects/{pid}/scans", json={"targets": [str(repo)]}
            ).json()["scan"]["id"]
            assert _wait_for_scan(client, scan_id)["status"] == "succeeded"

            assets = client.get(f"/api/v1/scans/{scan_id}/assets").json()["items"]
            asset = next((a for a in assets if "MD5" in (a["algorithm"] or "").upper()), None)
            if asset is None:
                pytest.skip("scanner produced no MD5 asset")

            body = client.get(f"/api/v1/assets/{asset['id']}/recommendation").json()
            assert body["target"]["mode"] == "pure", body["target"]
            assert "hybrid_group" not in body["target"], body["target"]


class TestECDHIsClassifiedAsKeyAgreement:
    """An ECDH key agreement written through `ec` resolves to a KEX asset and a hybrid KEM target.

    This class replaces `TestAKnownDetectionGap`, which asserted the opposite and was written to
    fail the moment the scanner learned to read the exchange — the intended signal to move it into
    the passing set rather than delete it. That is what happened.

    The gap it recorded was not a mislabel. `ec.generate_private_key(...)` alone does not say what
    the key is for, so `PY-CRYPTOGRAPHY-EC-KEYGEN` attributed it to signing, an ECDH agreement
    resolved to **ML-DSA-65**, and the tool answered a key exchange with a signature algorithm —
    the worst class to get wrong, because key agreement is the harvest-now-decrypt-later case that
    a signature is not.

    `PY-CRYPTOGRAPHY-ECDH-EXCHANGE` reads the call that says what the key is FOR. Measured cost of
    the gap, before the fix: on the MediVault twin it routed `negotiate_referral_key` to
    `py-signature-01` and the resulting patch broke agreement between two clinics, caught only by
    the `tests` rung. See `qubit-v2/11-implementation-findings.md` §25.
    """

    SOURCE = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "private_key = ec.generate_private_key(ec.SECP256R1())\n"
        "shared_key = private_key.exchange(ec.ECDH(), peer_public_key)\n"
    )

    def _scan(self, client: Any, tmp_path: Path, source: str) -> list[dict]:
        repo = tmp_path / "repo"
        repo.mkdir(exist_ok=True)
        (repo / "app.py").write_text(source, encoding="utf-8")
        pid = client.post("/api/v1/projects", json={"name": "ecdh", "root_path": str(repo)}).json()[
            "id"
        ]
        scan_id = client.post(
            f"/api/v1/projects/{pid}/scans", json={"targets": [str(repo)]}
        ).json()["scan"]["id"]
        assert _wait_for_scan(client, scan_id)["status"] == "succeeded"
        return list(client.get(f"/api/v1/scans/{scan_id}/assets").json()["items"])

    def test_the_exchange_produces_a_kex_asset(self, tmp_path: Path) -> None:
        with _make_client(tmp_path) as client:
            assets = self._scan(client, tmp_path, self.SOURCE)
        contexts = {a["algorithm"]: a.get("usage_context") for a in assets}
        assert contexts, "the scanner found nothing at all, which is a different bug"
        assert any(c == "kex" for c in contexts.values()), contexts
        assert any(a.startswith("ECDH") for a in contexts), contexts

    def test_the_kex_asset_gets_a_hybrid_KEM_target_not_a_signature(self, tmp_path: Path) -> None:
        """The point of the fix. A signature target here would be the original defect."""
        with _make_client(tmp_path) as client:
            assets = self._scan(client, tmp_path, self.SOURCE)
            kex = next(a for a in assets if a.get("usage_context") == "kex")
            body = client.get(f"/api/v1/assets/{kex['id']}/recommendation").json()

        target = body["target"]
        assert "ML-KEM" in target["algorithm"], target
        assert target["mode"] == "hybrid", target
        assert "DSA" not in target["algorithm"], target

    def test_the_keygen_line_is_STILL_attributed_to_signing(self, tmp_path: Path) -> None:
        """What the fix does NOT do, asserted so it cannot quietly be assumed fixed.

        `PY-CRYPTOGRAPHY-ECDH-EXCHANGE` is additive: it sees the exchange, it does not re-label the
        key generation two lines above it. Deciding that `ec.generate_private_key(...)` is for
        agreement rather than signing needs dataflow between the two statements, which the rule
        schema deliberately does not have — every condition it supports is scoped to a single
        match. So this source still yields a spurious `signature` asset alongside the correct
        `kex` one, and a migration run still opens a task for it.

        If that ever changes, this test fails and the record gets updated rather than going stale.
        """
        with _make_client(tmp_path) as client:
            assets = self._scan(client, tmp_path, self.SOURCE)
        contexts = {a["algorithm"]: a.get("usage_context") for a in assets}
        assert any(c == "signature" for c in contexts.values()), (
            "the keygen is no longer attributed to signing - the gap is now narrower than this "
            f"test claims, so update the record: {contexts}"
        )
