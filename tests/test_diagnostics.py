"""Diagnostics redaction test."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.whisker_ting.diagnostics import (
    async_get_config_entry_diagnostics,
)
from homeassistant.core import HomeAssistant


@pytest.fixture
def mock_ws_manager():
    manager = MagicMock()
    manager.connect_device = AsyncMock(return_value=True)
    manager.wait_for_data = AsyncMock(return_value=True)
    manager.get_voltage_data = MagicMock(return_value=None)
    manager.is_data_fresh = MagicMock(return_value=True)
    manager.disconnect_all = AsyncMock()
    with patch(
        "custom_components.whisker_ting.coordinator.WhiskerWebSocketManager",
        return_value=manager,
    ):
        yield manager


async def test_diagnostics_redacts_secrets(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    diag = await async_get_config_entry_diagnostics(hass, mock_config_entry)
    text = str(diag)
    assert "hunter2" not in text  # password
    assert (
        "80:6a:10:19:2a:b7" not in text
    )  # wifi mac (normalized physical form held by DeviceState)
    assert "ada@example.com" not in text  # email
    assert "TG-0001" in text  # non-secret serial is retained
