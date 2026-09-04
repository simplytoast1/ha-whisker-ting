"""Binary sensor platform for Whisker Ting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory

from .const import POWER_OUTAGE_EVENT_TYPES
from .entity import WhiskerEntity

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .api import DeviceState

PARALLEL_UPDATES = 0  # Coordinator handles all updates


def _is_power_outage(state: DeviceState) -> bool:
    """Return True while the device's most recent power event is an unrestored outage."""
    power = [
        n
        for n in state.notifications
        if n.event_type in POWER_OUTAGE_EVENT_TYPES and n.timestamp is not None
    ]
    if not power:
        return False
    latest = max(power, key=lambda n: n.timestamp)
    return latest.event_type == "PowerOutage"


@dataclass(frozen=True, kw_only=True)
class WhiskerBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes a Whisker Ting binary sensor entity."""

    value_fn: Callable[[DeviceState], bool]
    # True for the connectivity sensor, whose state derives from the live
    # WebSocket stream rather than from a DeviceState field.
    connectivity: bool = False


BINARY_SENSOR_DESCRIPTIONS: tuple[WhiskerBinarySensorEntityDescription, ...] = (
    # Primary hazard sensors (enabled by default)
    WhiskerBinarySensorEntityDescription(
        key="fire_hazard",
        translation_key="fire_hazard",
        device_class=BinarySensorDeviceClass.SAFETY,
        value_fn=lambda state: state.is_fire,
    ),
    WhiskerBinarySensorEntityDescription(
        key="electrical_fire_hazard",
        translation_key="electrical_fire_hazard",
        device_class=BinarySensorDeviceClass.SAFETY,
        value_fn=lambda state: (
            state.fire_hazard_status.efh_status.level is not None
            and state.fire_hazard_status.efh_status.level > 0
        ),
    ),
    WhiskerBinarySensorEntityDescription(
        key="unverified_fire_hazard",
        translation_key="unverified_fire_hazard",
        device_class=BinarySensorDeviceClass.SAFETY,
        value_fn=lambda state: (
            state.fire_hazard_status.ufh_status.level is not None
            and state.fire_hazard_status.ufh_status.level > 0
        ),
    ),
    WhiskerBinarySensorEntityDescription(
        key="frozen_pipe",
        translation_key="frozen_pipe",
        device_class=BinarySensorDeviceClass.COLD,
        value_fn=lambda state: state.has_frozen_pipe,
    ),
    WhiskerBinarySensorEntityDescription(
        key="power_quality_hazard",
        translation_key="power_quality_hazard",
        device_class=BinarySensorDeviceClass.SAFETY,
        value_fn=lambda state: state.is_power_quality_hazard,
    ),
    WhiskerBinarySensorEntityDescription(
        key="power_outage",
        translation_key="power_outage",
        device_class=BinarySensorDeviceClass.PROBLEM,
        value_fn=_is_power_outage,
    ),
    WhiskerBinarySensorEntityDescription(
        key="connectivity",
        translation_key="connectivity",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        connectivity=True,
        # Derived from stream liveness in is_on; this field is unused for it.
        value_fn=lambda state: False,
    ),
    WhiskerBinarySensorEntityDescription(
        key="learning_mode",
        translation_key="learning_mode",
        device_class=BinarySensorDeviceClass.RUNNING,
        value_fn=lambda state: state.fire_hazard_status.learning_mode,
    ),
    # Diagnostic sensors (disabled by default)
    WhiskerBinarySensorEntityDescription(
        key="hvac_verified",
        translation_key="hvac_verified",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.is_hvac_verified,
    ),
    WhiskerBinarySensorEntityDescription(
        key="is_owner",
        translation_key="is_owner",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.is_owner,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Whisker Ting binary sensors from a config entry."""
    coordinator = entry.runtime_data

    entities: list[WhiskerBinarySensor] = [
        WhiskerBinarySensor(
            coordinator=coordinator, device_id=device_id, description=description
        )
        for device_id in coordinator.data
        for description in BINARY_SENSOR_DESCRIPTIONS
    ]

    async_add_entities(entities)


class WhiskerBinarySensor(WhiskerEntity, BinarySensorEntity):
    """Representation of a Whisker Ting binary sensor."""

    entity_description: WhiskerBinarySensorEntityDescription

    def __init__(
        self,
        coordinator,
        device_id: str,
        description: WhiskerBinarySensorEntityDescription,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator, device_id)
        self.entity_description = description
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        # Connectivity reflects whether the real-time stream is live, not a
        # DeviceState field.
        if self.entity_description.connectivity:
            return self.coordinator.voltage_is_live(self._device_id)
        device_state = self.coordinator.data.get(self._device_id)
        if device_state is None:
            return None
        return self.entity_description.value_fn(device_state)
