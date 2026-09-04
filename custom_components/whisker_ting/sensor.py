"""Sensor platform for Whisker Ting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfElectricPotential
from homeassistant.util import dt as dt_util

from .const import BROWNOUT_EVENT_TYPES, WEATHER_EVENT_TYPES
from .entity import WhiskerEntity

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .api import DeviceState, TingNotification

PARALLEL_UPDATES = 0  # Coordinator handles all updates


@dataclass(frozen=True, kw_only=True)
class WhiskerSensorEntityDescription(SensorEntityDescription):
    """Describes a Whisker Ting sensor entity."""

    value_fn: Callable[[DeviceState], Any]
    # True for sensors fed by the real-time WebSocket stream; these go
    # unavailable when the stream is disconnected/stale rather than showing a
    # frozen last value forever.
    realtime: bool = False
    attributes_fn: Callable[[DeviceState], dict[str, Any] | None] | None = None


SENSOR_DESCRIPTIONS: tuple[WhiskerSensorEntityDescription, ...] = (
    # Real-time voltage sensors (from WebSocket)
    WhiskerSensorEntityDescription(
        key="voltage",
        name="Current voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        realtime=True,
        value_fn=lambda state: (
            state.voltage.voltage if state.voltage.voltage > 0 else None
        ),
    ),
    WhiskerSensorEntityDescription(
        key="voltage_high",
        name="Voltage high",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        realtime=True,
        value_fn=lambda state: (
            state.voltage.voltage_hi if state.voltage.voltage_hi > 0 else None
        ),
    ),
    WhiskerSensorEntityDescription(
        key="voltage_low",
        name="Voltage low",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        realtime=True,
        value_fn=lambda state: (
            state.voltage.voltage_lo if state.voltage.voltage_lo > 0 else None
        ),
    ),
    WhiskerSensorEntityDescription(
        key="average_peaks_max",
        name="Average peaks max",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        entity_registry_enabled_default=False,
        realtime=True,
        value_fn=lambda state: (
            state.voltage.average_peaks_max
            if state.voltage.average_peaks_max > 0
            else None
        ),
    ),
    # Primary status sensors (enabled by default)
    WhiskerSensorEntityDescription(
        key="hazard_status",
        translation_key="hazard_status",
        device_class=SensorDeviceClass.ENUM,
        options=["no_hazards", "hazard_detected", "reviewed_not_fire", "learning"],
        # Not just an unnecessary wrapper: _get_hazard_status is defined below
        # this tuple, so a direct reference would be a NameError at module
        # load; the lambda defers the lookup to call time.
        value_fn=lambda state: _get_hazard_status(state),  # noqa: PLW0108
    ),
    WhiskerSensorEntityDescription(
        key="hazard_message",
        translation_key="hazard_message",
        value_fn=lambda state: state.fire_hazard_status.message,
    ),
    WhiskerSensorEntityDescription(
        key="efh_status",
        translation_key="efh_status",
        value_fn=lambda state: state.fire_hazard_status.efh_status.status or "none",
    ),
    WhiskerSensorEntityDescription(
        key="efh_message",
        translation_key="efh_message",
        value_fn=lambda state: state.fire_hazard_status.efh_status.message,
    ),
    WhiskerSensorEntityDescription(
        key="efh_level",
        name="Electrical fire hazard level",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda state: state.fire_hazard_status.efh_status.level,
    ),
    WhiskerSensorEntityDescription(
        key="ufh_status",
        translation_key="ufh_status",
        value_fn=lambda state: state.fire_hazard_status.ufh_status.status or "none",
    ),
    WhiskerSensorEntityDescription(
        key="ufh_message",
        translation_key="ufh_message",
        value_fn=lambda state: state.fire_hazard_status.ufh_status.message,
    ),
    WhiskerSensorEntityDescription(
        key="device_type",
        translation_key="device_type",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda state: state.device_type,
    ),
    # Diagnostic sensors (disabled by default)
    WhiskerSensorEntityDescription(
        key="firmware_version",
        translation_key="firmware_version",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.version,
    ),
    WhiskerSensorEntityDescription(
        key="wifi_mac",
        translation_key="wifi_mac",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.wifi_mac_address,
    ),
    WhiskerSensorEntityDescription(
        key="bluetooth_mac",
        translation_key="bluetooth_mac",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.bluetooth_mac_address,
    ),
    WhiskerSensorEntityDescription(
        key="serial_number",
        translation_key="serial_number",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.serial_number,
    ),
    WhiskerSensorEntityDescription(
        key="subscription_start",
        translation_key="subscription_start",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: (
            dt_util.parse_datetime(state.subscription_start_date)
            if state.subscription_start_date
            else None
        ),
    ),
    WhiskerSensorEntityDescription(
        key="group_name",
        translation_key="group_name",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.group_name,
    ),
    # Recency-of-event sensors: state is the timestamp of the most recent
    # matching notification, with details in attributes.
    WhiskerSensorEntityDescription(
        key="last_brownout",
        translation_key="last_brownout",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda s: (
            n.timestamp
            if (n := _latest_notification_of(s, BROWNOUT_EVENT_TYPES))
            else None
        ),
        attributes_fn=lambda s: (
            {"message": n.message}
            if (n := _latest_notification_of(s, BROWNOUT_EVENT_TYPES))
            else None
        ),
    ),
    WhiskerSensorEntityDescription(
        key="last_weather_alert",
        translation_key="last_weather_alert",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda s: (
            n.timestamp
            if (n := _latest_notification_of(s, WEATHER_EVENT_TYPES))
            else None
        ),
        attributes_fn=lambda s: (
            {"title": n.title, "message": n.message}
            if (n := _latest_notification_of(s, WEATHER_EVENT_TYPES))
            else None
        ),
    ),
)


def _latest_notification_of(
    state: DeviceState, types: set[str]
) -> TingNotification | None:
    """Return the most recent notification of the given event types, if any."""
    matching = [
        n
        for n in state.notifications
        if n.event_type in types and n.timestamp is not None
    ]
    return max(matching, key=lambda n: n.timestamp) if matching else None


def _get_hazard_status(state: DeviceState) -> str:
    """Get the overall hazard status."""
    if state.fire_hazard_status.learning_mode:
        return "learning"
    if state.is_fire:
        return "hazard_detected"
    efh = state.fire_hazard_status.efh_status
    if efh.status == "ReviewedNotFire":
        return "reviewed_not_fire"
    if efh.level is not None and efh.level > 0:
        return "hazard_detected"
    ufh = state.fire_hazard_status.ufh_status
    if ufh.level is not None and ufh.level > 0:
        return "hazard_detected"
    return "no_hazards"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Whisker Ting sensors from a config entry."""
    coordinator = entry.runtime_data

    entities: list[WhiskerSensor] = [
        WhiskerSensor(
            coordinator=coordinator, device_id=device_id, description=description
        )
        for device_id in coordinator.data
        for description in SENSOR_DESCRIPTIONS
    ]

    async_add_entities(entities)


class WhiskerSensor(WhiskerEntity, SensorEntity):
    """Representation of a Whisker Ting sensor."""

    entity_description: WhiskerSensorEntityDescription

    def __init__(
        self,
        coordinator,
        device_id: str,
        description: WhiskerSensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, device_id)
        self.entity_description = description
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not super().available:
            return False
        # Real-time voltage sensors depend on a live WebSocket stream; report
        # unavailable when it is disconnected/stale instead of a frozen value.
        if self.entity_description.realtime:
            return self.coordinator.voltage_is_live(self._device_id)
        return True

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        device_state = self.coordinator.data.get(self._device_id)
        if device_state is None:
            return None
        return self.entity_description.value_fn(device_state)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return additional notification details, if the description provides any."""
        if self.entity_description.attributes_fn is None:
            return None
        device_state = self.coordinator.data.get(self._device_id)
        if device_state is None:
            return None
        return self.entity_description.attributes_fn(device_state)
