"""Tests for Ting notification parsing, coordinator wiring, and alert entities."""

from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.whisker_ting.api import (
    DeviceState,
    FireHazardStatus,
    TingNotification,
    VoltageReading,
    WhiskerApiClient,
    WhiskerApiError,
)
from custom_components.whisker_ting.binary_sensor import _is_power_outage
from custom_components.whisker_ting.const import (
    BROWNOUT_EVENT_TYPES,
    WEATHER_EVENT_TYPES,
)
from custom_components.whisker_ting.sensor import _latest_notification_of
from custom_components.whisker_ting.websocket import VoltageData
from homeassistant.helpers import entity_registry as er
import homeassistant.util.dt as dt_util

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant


def _load(name: str):
    return json.loads((Path(__file__).parent / "fixtures" / name).read_text())


def test_parse_notifications():
    raw = _load("notifications.json")
    # _parse_notification is a staticmethod: no __init__/instance needed for parse.
    parsed = [WhiskerApiClient._parse_notification(n) for n in raw]
    assert len(parsed) == 4
    outage = next(n for n in parsed if n.event_type == "PowerOutage")
    assert isinstance(outage, TingNotification)
    assert outage.serial_number == "TG-0001"
    assert outage.title == "Power Outage"
    assert outage.timestamp is not None
    assert outage.timestamp.tzinfo is not None
    assert outage.sent_utc is not None
    assert outage.is_acknowledged is False


def test_parse_notification_naive_timestamp_coerced_to_utc():
    """A naive eventTimestampLocal/sentUtc (missing UTC offset) must still parse tz-aware."""
    raw = {
        "id": "n-naive",
        "eventType": "PowerOutage",
        "eventTimestampLocal": "2026-07-20T20:05:12",
        "sentUtc": "2026-07-20T20:05:12",
        "serialNumber": "TG-0001",
    }
    parsed = WhiskerApiClient._parse_notification(raw)
    assert parsed.timestamp is not None
    assert parsed.timestamp.tzinfo is not None
    assert parsed.sent_utc is not None
    assert parsed.sent_utc.tzinfo is not None


def test_device_named_by_site():
    raw = _load("user_data_multi.json")
    parser = WhiskerApiClient.__new__(WhiskerApiClient)
    user = WhiskerApiClient._parse_user_data(parser, raw)
    by_serial = {d.serial_number: d for d in user.devices}
    assert by_serial["TG-0001"].site_name == "Home - Kitchen"
    assert by_serial["TG-0002"].site_name == "Home - Bedroom"


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


def _notif(**kw):
    return TingNotification(**kw)


async def test_coordinator_attaches_notifications(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_client.get_notifications.return_value = [
        _notif(
            id="a",
            event_type="PowerOutage",
            serial_number="TG-0001",
            sent_utc=dt_util.utcnow(),
            timestamp=dt_util.utcnow(),
        ),
        _notif(
            id="b",
            event_type="Sag",
            serial_number="OTHER",
            sent_utc=dt_util.utcnow(),
            timestamp=dt_util.utcnow(),
        ),
    ]
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    device = mock_config_entry.runtime_data.data["TG-0001"]
    assert [n.id for n in device.notifications] == ["a"]  # only this device's


async def test_multi_device_notification_attribution(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    """With 2 real devices, each gets only its own serial's notifications."""
    raw = _load("user_data_multi.json")
    parser = WhiskerApiClient.__new__(WhiskerApiClient)
    user = WhiskerApiClient._parse_user_data(parser, raw)
    mock_client.get_all_device_states.return_value = {
        d.serial_number: d for d in user.devices
    }
    mock_client.get_notifications.return_value = [
        _notif(
            id="a1",
            event_type="PowerOutage",
            serial_number="TG-0001",
            sent_utc=dt_util.utcnow(),
            timestamp=dt_util.utcnow(),
        ),
        _notif(
            id="b1",
            event_type="Sag",
            serial_number="TG-0002",
            sent_utc=dt_util.utcnow(),
            timestamp=dt_util.utcnow(),
        ),
    ]
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    data = mock_config_entry.runtime_data.data
    assert [n.id for n in data["TG-0001"].notifications] == ["a1"]
    assert [n.id for n in data["TG-0002"].notifications] == ["b1"]


async def test_notifications_preserved_on_transient_failure(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    mock_client.get_notifications.return_value = [
        _notif(
            id="a",
            event_type="PowerOutage",
            serial_number="TG-0001",
            sent_utc=dt_util.utcnow(),
            timestamp=dt_util.utcnow(),
        ),
    ]
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    coordinator = mock_config_entry.runtime_data
    assert [n.id for n in coordinator.data["TG-0001"].notifications] == ["a"]

    mock_client.get_notifications.side_effect = WhiskerApiError("x")
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert [n.id for n in coordinator.data["TG-0001"].notifications] == ["a"]
    assert coordinator.last_update_success is True


async def test_auto_notify_posts_only_when_enabled(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    t0 = dt_util.utcnow()
    mock_client.get_notifications.return_value = []  # seed: no notifications
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    coordinator = mock_config_entry.runtime_data
    coordinator.notify_enabled = True

    # A new significant alert + a new brownout appear on the next poll.
    mock_client.get_notifications.return_value = [
        _notif(
            id="new-outage",
            event_type="PowerOutage",
            title="Power Outage",
            message="out",
            serial_number="TG-0001",
            sent_utc=t0,
            timestamp=t0,
        ),
        _notif(
            id="new-sag",
            event_type="Sag",
            title="Brownout",
            message="sag",
            serial_number="TG-0001",
            sent_utc=t0,
            timestamp=t0,
        ),
    ]

    # Patch-and-assert the call rather than depending on persistent_notification
    # internals (version-robust across HA releases).
    with patch(
        "custom_components.whisker_ting.coordinator.persistent_notification.async_create"
    ) as create:
        await coordinator.async_refresh()
        await hass.async_block_till_done()

    create.assert_called_once_with(
        hass,
        message="out",
        title="Ting: Power Outage",
        notification_id="whisker_ting_new-outage",
    )


async def test_auto_notify_disabled_does_not_post(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    t0 = dt_util.utcnow()
    mock_client.get_notifications.return_value = []  # seed: no notifications
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    coordinator = mock_config_entry.runtime_data
    assert coordinator.notify_enabled is False  # opt-in: off by default

    # A new significant alert appears on the next poll.
    mock_client.get_notifications.return_value = [
        _notif(
            id="new-outage",
            event_type="PowerOutage",
            title="Power Outage",
            message="out",
            serial_number="TG-0001",
            sent_utc=t0,
            timestamp=t0,
        ),
    ]

    with patch(
        "custom_components.whisker_ting.coordinator.persistent_notification.async_create"
    ) as create:
        await coordinator.async_refresh()
        await hass.async_block_till_done()

    create.assert_not_called()


async def test_event_fires_on_new_no_backlog_replay(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    t0 = dt_util.utcnow()
    # Setup with a backlog present — must NOT replay it as events.
    mock_client.get_notifications.return_value = [
        TingNotification(
            id="old",
            event_type="PowerRestored",
            title="R",
            serial_number="TG-0001",
            sent_utc=t0,
            timestamp=t0,
        ),
    ]
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reg = er.async_get(hass)
    ent = next(
        e
        for e in er.async_entries_for_config_entry(reg, mock_config_entry.entry_id)
        if e.domain == "event" and e.unique_id == "TG-0001_alerts"
    )
    state = hass.states.get(ent.entity_id)
    assert state is not None
    assert state.state in (None, "unknown")  # no replay

    # A genuinely new notification on the next poll fires an event.
    mock_client.get_notifications.return_value = [
        TingNotification(
            id="old",
            event_type="PowerRestored",
            title="R",
            serial_number="TG-0001",
            sent_utc=t0,
            timestamp=t0,
        ),
        TingNotification(
            id="new",
            event_type="PowerOutage",
            title="Outage",
            message="m",
            serial_number="TG-0001",
            sent_utc=t0 + timedelta(minutes=1),
            timestamp=t0 + timedelta(minutes=1),
        ),
    ]
    await mock_config_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    state = hass.states.get(ent.entity_id)
    assert state.attributes["event_type"] == "PowerOutage"
    assert state.attributes["message"] == "m"


async def test_event_unknown_type_maps_to_unknown(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    t0 = dt_util.utcnow()
    mock_client.get_notifications.return_value = []
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    mock_client.get_notifications.return_value = [
        TingNotification(
            id="x",
            event_type="SomethingNew",
            title="t",
            serial_number="TG-0001",
            sent_utc=t0 + timedelta(minutes=1),
            timestamp=t0 + timedelta(minutes=1),
        ),
    ]
    await mock_config_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    reg = er.async_get(hass)
    ent = next(
        e
        for e in er.async_entries_for_config_entry(reg, mock_config_entry.entry_id)
        if e.domain == "event" and e.unique_id == "TG-0001_alerts"
    )
    state = hass.states.get(ent.entity_id)
    assert state.attributes["event_type"] == "unknown"
    assert state.attributes["event_type"] != state.attributes.get("category")


async def test_voltage_push_fires_no_event(
    hass: HomeAssistant, mock_client, mock_config_entry, mock_ws_manager
):
    """A throttled real-time voltage push must never fire the alerts event entity."""
    t0 = dt_util.utcnow()
    mock_client.get_notifications.return_value = [
        TingNotification(
            id="seed",
            event_type="PowerRestored",
            title="R",
            serial_number="TG-0001",
            sent_utc=t0,
            timestamp=t0,
        ),
    ]
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reg = er.async_get(hass)
    ent = next(
        e
        for e in er.async_entries_for_config_entry(reg, mock_config_entry.entry_id)
        if e.domain == "event" and e.unique_id == "TG-0001_alerts"
    )
    state_before = hass.states.get(ent.entity_id)
    assert state_before is not None

    coordinator = mock_config_entry.runtime_data
    station_id = coordinator.data["TG-0001"].station_id
    coordinator._handle_voltage_update(
        station_id,
        VoltageData(
            timestamp=dt_util.utcnow(),
            voltage=120.1,
            voltage_hi=121.0,
            voltage_lo=119.0,
            average_peaks_max=122.0,
        ),
    )
    await hass.async_block_till_done()

    state_after = hass.states.get(ent.entity_id)
    assert state_after.state == state_before.state
    assert state_after.attributes == state_before.attributes


def test_power_outage_derivation():
    t0 = dt_util.utcnow()

    def dev(notes):
        return DeviceState(
            serial_number="TG-0001",
            name="x",
            device_type="FireSensor",
            site_id=1,
            fire_hazard_status=FireHazardStatus(),
            voltage=VoltageReading(),
            notifications=notes,
        )

    assert _is_power_outage(dev([])) is False
    out = _notif(
        id="o",
        event_type="PowerOutage",
        serial_number="TG-0001",
        timestamp=t0,
        sent_utc=t0,
    )
    restored = _notif(
        id="r",
        event_type="PowerRestored",
        serial_number="TG-0001",
        timestamp=t0 + timedelta(minutes=5),
        sent_utc=t0 + timedelta(minutes=5),
    )
    assert _is_power_outage(dev([out])) is True
    assert _is_power_outage(dev([out, restored])) is False  # latest is restore
    new_outage = _notif(
        id="o2",
        event_type="PowerOutage",
        serial_number="TG-0001",
        timestamp=t0 + timedelta(minutes=10),
        sent_utc=t0 + timedelta(minutes=10),
    )
    assert _is_power_outage(dev([restored, new_outage])) is True  # latest is outage
    outage_and_restored = _notif(
        id="oar",
        event_type="PowerOutageAndRestored",
        serial_number="TG-0001",
        timestamp=t0 + timedelta(minutes=15),
        sent_utc=t0 + timedelta(minutes=15),
    )
    assert _is_power_outage(dev([outage_and_restored])) is False
    outage_with_none_timestamp = _notif(
        id="o3",
        event_type="PowerOutage",
        serial_number="TG-0001",
        timestamp=None,
        sent_utc=t0,
    )
    assert _is_power_outage(dev([outage_with_none_timestamp])) is False


def test_last_event_sensors():
    t0 = dt_util.utcnow()
    notes = [
        _notif(id="s1", event_type="Sag", timestamp=t0, message="old sag"),
        _notif(
            id="s2",
            event_type="Swell",
            timestamp=t0 + timedelta(minutes=10),
            message="new",
        ),
        _notif(
            id="w1",
            event_type="WeatherAlert",
            timestamp=t0 + timedelta(minutes=5),
            title="Storm",
            message="storm",
        ),
    ]
    dev = DeviceState(
        serial_number="TG-0001",
        name="x",
        device_type="FireSensor",
        site_id=1,
        fire_hazard_status=FireHazardStatus(),
        voltage=VoltageReading(),
        notifications=notes,
    )
    assert _latest_notification_of(dev, BROWNOUT_EVENT_TYPES).id == "s2"
    assert _latest_notification_of(dev, WEATHER_EVENT_TYPES).id == "w1"
    assert _latest_notification_of(dev, BROWNOUT_EVENT_TYPES).message == "new"
