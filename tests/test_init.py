"""Setup / unload tests for the Whisker Ting integration."""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.whisker_ting.api import WhiskerAuthError, WhiskerConnectionError
from custom_components.whisker_ting.const import (
    CONF_ALERT_NOTIFICATIONS,
    CONF_SCAN_INTERVAL,
    CONF_VOLTAGE_PUBLISH_INTERVAL,
    DOMAIN,
)
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr


@pytest.fixture
def mock_ws_manager():
    """Patch the WebSocket manager so setup is hermetic (no real socket)."""
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


async def test_setup_and_unload(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    assert "TG-0001" in mock_config_entry.runtime_data.data

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED
    mock_ws_manager.disconnect_all.assert_awaited()


async def test_setup_auth_failed_triggers_reauth(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_client.get_all_device_states.side_effect = WhiskerAuthError("bad")
    mock_config_entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)


async def test_setup_cannot_connect_retries(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_client.get_all_device_states.side_effect = WhiskerConnectionError("down")
    mock_config_entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY


async def test_ws_manager_created_on_setup(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.runtime_data._ws_manager is mock_ws_manager


async def test_options_update_applies_scan_interval_and_notify_enabled(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    """async_options_updated must push every option onto the live coordinator."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    coordinator = mock_config_entry.runtime_data
    assert coordinator.update_interval != timedelta(seconds=120)
    assert coordinator.notify_enabled is False
    assert coordinator.voltage_publish_interval == 5

    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={
            CONF_SCAN_INTERVAL: 120,
            CONF_ALERT_NOTIFICATIONS: True,
            CONF_VOLTAGE_PUBLISH_INTERVAL: 10,
        },
    )
    await hass.async_block_till_done()

    assert coordinator.update_interval == timedelta(seconds=120)
    assert coordinator.notify_enabled is True
    assert coordinator.voltage_publish_interval == 10


async def test_stale_reversed_mac_connections_removed(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    """Reversed-MAC registry rows from older builds are migrated away.

    Pre-1.2.0 builds registered the Wi-Fi MAC (and pre-3.0.1 the Bluetooth
    MAC) in the API's reversed byte order; the registry only merges
    connections, so those rows persisted next to the corrected ones.
    """
    mock_config_entry.add_to_hass(hass)
    registry = dr.async_get(hass)
    device = registry.async_get_or_create(
        config_entry_id=mock_config_entry.entry_id,
        identifiers={(DOMAIN, "TG-0001")},
        connections={
            # reversed Wi-Fi (pre-1.2.0) and reversed Bluetooth (pre-3.0.1)
            (dr.CONNECTION_NETWORK_MAC, "b7:2a:19:10:6a:80"),
            (dr.CONNECTION_BLUETOOTH, "aa:bb:cc:dd:ee:ff"),
            # correct Wi-Fi, as 1.2.0+ merged it
            (dr.CONNECTION_NETWORK_MAC, "80:6a:10:19:2a:b7"),
        },
    )

    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    device = registry.async_get(device.id)
    assert (dr.CONNECTION_NETWORK_MAC, "b7:2a:19:10:6a:80") not in device.connections
    assert (dr.CONNECTION_BLUETOOTH, "aa:bb:cc:dd:ee:ff") not in device.connections
    # The correct forms remain/merge in
    assert (dr.CONNECTION_NETWORK_MAC, "80:6a:10:19:2a:b7") in device.connections
    assert (dr.CONNECTION_BLUETOOTH, "ff:ee:dd:cc:bb:aa") in device.connections
