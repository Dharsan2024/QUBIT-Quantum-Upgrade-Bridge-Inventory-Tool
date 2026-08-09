"""push_assets_to_api returns success/failure honestly (no false 'Pushed' on an unreachable API)."""

from unittest.mock import MagicMock, patch

import httpx
from qubit_bridge.assets import push_assets_to_api


def test_push_returns_true_on_success():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    with patch("qubit_bridge.assets.httpx.post", return_value=mock_resp) as post:
        assert push_assets_to_api([], api_url="http://localhost:8000") is True
        post.assert_called_once()


def test_push_returns_false_when_api_unreachable():
    with patch(
        "qubit_bridge.assets.httpx.post",
        side_effect=httpx.ConnectError("refused"),
    ):
        # Must NOT raise, and must report failure so the caller doesn't print a false success.
        assert push_assets_to_api([], api_url="http://localhost:8000") is False
