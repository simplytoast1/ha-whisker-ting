"""The token cache uses timezone-aware time and refreshes near expiry."""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.whisker_ting.api import WhiskerApiClient
import homeassistant.util.dt as dt_util


@pytest.fixture
def client() -> WhiskerApiClient:
    return WhiskerApiClient(MagicMock(), "u", "p")


async def test_valid_token_is_reused(client):
    client._access_token = "tok"
    client._token_expiry = dt_util.utcnow() + timedelta(hours=1)
    client._authenticate = AsyncMock()
    assert await client._ensure_token() == "tok"
    client._authenticate.assert_not_awaited()


async def test_expiring_token_triggers_refresh(client):
    client._access_token = "old"
    client._token_expiry = dt_util.utcnow() + timedelta(minutes=1)  # < 5 min buffer
    client._refresh_token = None

    async def _auth():
        client._access_token = "new"
        client._token_expiry = dt_util.utcnow() + timedelta(hours=1)

    client._authenticate = AsyncMock(side_effect=_auth)
    assert await client._ensure_token() == "new"
    client._authenticate.assert_awaited_once()
