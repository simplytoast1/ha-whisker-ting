"""Station-id handling: the serial is authoritative, probing is retired.

The hub answers every InitializeStreaming with a void Completion no matter
what StationId is supplied, so the old candidate-rotation probe could never
discriminate — it only ever subscribed to the wrong station. These tests
lock in that the serial is used and that no probing happens.
"""

from unittest.mock import AsyncMock, MagicMock

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.whisker_ting.api import DeviceState
from custom_components.whisker_ting.const import CONF_STATION_IDS, DOMAIN
from custom_components.whisker_ting.coordinator import WhiskerDataUpdateCoordinator
from homeassistant.core import HomeAssistant


def _device() -> DeviceState:
    return DeviceState(
        serial_number="TG-0001",
        name="Test Ting",
        device_type="FireSensor",
        site_id=555,
        soc_serial_number="SOC-9",
        station_id="TG-0001",
        group_id=42,
    )


def _coordinator(hass: HomeAssistant, entry: MockConfigEntry, manager):
    client = MagicMock()
    client.api_key = "key"
    client.user_id = 7
    coordinator = WhiskerDataUpdateCoordinator(
        hass, client, MagicMock(), config_entry=entry
    )
    coordinator._ws_manager = manager
    return coordinator


def _manager():
    manager = MagicMock()
    manager.wait_for_data = AsyncMock(return_value=False)
    manager.connect_device = AsyncMock(return_value=True)
    manager.disconnect_device = AsyncMock()
    return manager


async def test_connect_uses_device_serial_as_station_id(hass: HomeAssistant):
    """StationId must be the sensor serial, matching the official app."""
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    manager = _manager()
    coordinator = _coordinator(hass, entry, manager)
    device = _device()

    await coordinator._connect_websocket({"TG-0001": device})

    assert device.station_id == "TG-0001"
    manager.connect_device.assert_awaited_with(
        api_key="key", user_id=7, station_id="TG-0001"
    )


async def test_no_probe_is_started_when_stream_is_silent(hass: HomeAssistant):
    """A silent stream must NOT trigger station-id rotation.

    Regression: rotation subscribed to site/group ids (e.g. '1118490')
    because a void Completion looks identical for every candidate.
    """
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    manager = _manager()
    coordinator = _coordinator(hass, entry, manager)
    device = _device()

    coordinator._maybe_start_station_probe(device)

    assert coordinator._probe_tasks == {}
    assert device.station_id == "TG-0001"
    manager.connect_device.assert_not_called()


async def test_persisted_station_id_is_still_honored(hass: HomeAssistant):
    """A station id persisted by an older version keeps working."""
    entry = MockConfigEntry(
        domain=DOMAIN, options={CONF_STATION_IDS: {"TG-0001": "555"}}
    )
    entry.add_to_hass(hass)
    manager = _manager()
    coordinator = _coordinator(hass, entry, manager)
    device = _device()

    await coordinator._connect_websocket({"TG-0001": device})

    assert device.station_id == "555"
    manager.connect_device.assert_awaited_with(
        api_key="key", user_id=7, station_id="555"
    )
