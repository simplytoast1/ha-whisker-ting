"""Common fixtures for Whisker Ting tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.syrupy import (
    HomeAssistantSnapshotExtension,
)

from custom_components.whisker_ting.api import WhiskerApiClient
from custom_components.whisker_ting.const import DOMAIN

from .const import TEST_USER_ID, TEST_USERNAME, USER_INPUT

if TYPE_CHECKING:
    from syrupy.assertion import SnapshotAssertion


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable loading of the custom integration in every test."""
    return


@pytest.fixture
def snapshot(snapshot: SnapshotAssertion) -> SnapshotAssertion:
    """Return the snapshot fixture wired to the Home Assistant extension."""
    return snapshot.use_extension(HomeAssistantSnapshotExtension)


@pytest.fixture
def user_data_dict() -> dict:
    """Return the canned /Users/{id} payload as a dict."""
    path = Path(__file__).parent / "fixtures" / "user_data.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return a mock config entry for the test account."""
    return MockConfigEntry(
        domain=DOMAIN,
        unique_id=str(TEST_USER_ID),
        title=f"Whisker Ting ({TEST_USERNAME})",
        data=USER_INPUT,
    )


@pytest.fixture
def mock_client(user_data_dict):
    """Patch WhiskerApiClient at its construction seams with an AsyncMock.

    Device states are produced by the real parser so tests use realistic data.
    """
    parser = WhiskerApiClient(MagicMock(), "u", "p")
    user = parser._parse_user_data(user_data_dict)

    client = AsyncMock(spec=WhiskerApiClient)
    client.user_id = TEST_USER_ID
    client.api_key = "fake-api-key"
    client.get_user_data.return_value = user
    client.get_all_device_states.return_value = {
        d.serial_number: d for d in user.devices
    }
    client.get_notifications.return_value = []
    with (
        patch("custom_components.whisker_ting.WhiskerApiClient", return_value=client),
        patch(
            "custom_components.whisker_ting.config_flow.WhiskerApiClient",
            return_value=client,
        ),
    ):
        yield client
