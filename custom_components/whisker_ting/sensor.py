"""Sensor platform for Whisker Ting."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfElectricPotential
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import DeviceState
from .const import DOMAIN
from .coordinator import WhiskerDataUpdateCoordinator

PARALLEL_UPDATES = 0  # Coordinator handles all updates


@dataclass(frozen=True, kw_only=True)
class WhiskerSensorEntityDescription(SensorEntityDescription):
    """Describes a Whisker Ting sensor entity."""

    value_fn: Callable[[DeviceState], Any]


SENSOR_DESCRIPTIONS: tuple[WhiskerSensorEntityDescription, ...] = (
    # Real-time voltage sensors (from WebSocket)
    WhiskerSensorEntityDescription(
        key="voltage",
        name="Current voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        value_fn=lambda state: state.voltage.voltage if state.voltage.voltage > 0 else None,
    ),
    WhiskerSensorEntityDescription(
        key="voltage_high",
        name="Voltage high",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        value_fn=lambda state: state.voltage.voltage_hi if state.voltage.voltage_hi > 0 else None,
    ),
    WhiskerSensorEntityDescription(
        key="voltage_low",
        name="Voltage low",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        value_fn=lambda state: state.voltage.voltage_lo if state.voltage.voltage_lo > 0 else None,
    ),
    WhiskerSensorEntityDescription(
        key="average_peaks_max",
        name="Average peaks max",
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=2,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.voltage.average_peaks_max if state.voltage.average_peaks_max > 0 else None,
    ),
    # Primary status sensors (enabled by default)
    WhiskerSensorEntityDescription(
        key="hazard_status",
        translation_key="hazard_status",
        device_class=SensorDeviceClass.ENUM,
        options=["no_hazards", "hazard_detected", "reviewed_not_fire", "learning"],
        value_fn=lambda state: _get_hazard_status(state),
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
        key="group_name",
        translation_key="group_name",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.group_name,
    ),
)


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

    entities: list[WhiskerSensor] = []
    for device_id, device_state in coordinator.data.items():
        for description in SENSOR_DESCRIPTIONS:
            entities.append(
                WhiskerSensor(
                    coordinator=coordinator,
                    device_id=device_id,
                    description=description,
                )
            )

    async_add_entities(entities)


class WhiskerSensor(CoordinatorEntity[WhiskerDataUpdateCoordinator], SensorEntity):
    """Representation of a Whisker Ting sensor."""

    entity_description: WhiskerSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: WhiskerDataUpdateCoordinator,
        device_id: str,
        description: WhiskerSensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._device_id = device_id
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        device_state = self.coordinator.data.get(self._device_id)
        if device_state:
            return DeviceInfo(
                identifiers={(DOMAIN, self._device_id)},
                name=device_state.name,
                manufacturer="Whisker Labs",
                model="Ting Fire Sensor",
                sw_version=device_state.version,
            )
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            name=self._device_id,
            manufacturer="Whisker Labs",
        )

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return super().available and self._device_id in self.coordinator.data

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        device_state = self.coordinator.data.get(self._device_id)
        if device_state is None:
            return None
        return self.entity_description.value_fn(device_state)
