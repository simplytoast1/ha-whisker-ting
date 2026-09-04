"""Base entity for the Whisker Ting integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import (
    CONNECTION_BLUETOOTH,
    CONNECTION_NETWORK_MAC,
    DeviceInfo,
    format_mac,
)
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import WhiskerDataUpdateCoordinator


class WhiskerEntity(CoordinatorEntity[WhiskerDataUpdateCoordinator]):
    """Base class for Whisker Ting entities."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: WhiskerDataUpdateCoordinator, device_id: str
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._device_id = device_id

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        device_state = self.coordinator.data.get(self._device_id)
        if device_state is None:
            return DeviceInfo(
                identifiers={(DOMAIN, self._device_id)},
                name=self._device_id,
                manufacturer="Whisker Labs",
            )
        connections = set()
        if device_state.wifi_mac_address:
            connections.add(
                (CONNECTION_NETWORK_MAC, format_mac(device_state.wifi_mac_address))
            )
        if device_state.bluetooth_mac_address:
            connections.add(
                (CONNECTION_BLUETOOTH, format_mac(device_state.bluetooth_mac_address))
            )
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            connections=connections,
            name=device_state.site_name or device_state.name,
            manufacturer="Whisker Labs",
            model="Ting Fire Sensor",
            sw_version=device_state.version,
        )

    @property
    def available(self) -> bool:
        """Return True if the device is present in coordinator data."""
        return super().available and self._device_id in self.coordinator.data
