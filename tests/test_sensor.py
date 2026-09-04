"""Entity snapshot tests."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from syrupy.assertion import SnapshotAssertion

from custom_components.whisker_ting.api import _reverse_mac
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er


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


async def test_entities(
    hass: HomeAssistant,
    mock_client,
    mock_config_entry,
    mock_ws_manager,
    snapshot: SnapshotAssertion,
):
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(reg, mock_config_entry.entry_id)
    assert entries
    for entry in sorted(entries, key=lambda e: e.entity_id):
        assert entry == snapshot(name=f"{entry.entity_id}-entry")
        if entry.disabled:
            # Entities disabled by default (entity_registry_enabled_default=False)
            # are registered but never get a State object.
            continue
        assert (state := hass.states.get(entry.entity_id))
        assert state == snapshot(name=f"{entry.entity_id}-state")


async def test_mac_addresses_normalized_to_physical_order(hass, mock_config_entry):
    """Both Wi-Fi AND Bluetooth MACs arrive byte-reversed from the API."""
    assert _reverse_mac("b7:2a:19:10:6a:80") == "80:6a:10:19:2a:b7"
    # Regression: bluetoothMacAddress was passed through unreversed.
    assert _reverse_mac("aa:bb:cc:dd:ee:ff") == "ff:ee:dd:cc:bb:aa"
