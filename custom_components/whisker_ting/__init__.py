"""The Whisker Ting integration."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import TYPE_CHECKING

from homeassistant.const import Platform
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import (
    CONNECTION_BLUETOOTH,
    CONNECTION_NETWORK_MAC,
    format_mac,
)

from .api import WhiskerApiClient, _reverse_mac
from .const import (
    CONF_ALERT_NOTIFICATIONS,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    CONF_VOLTAGE_PUBLISH_INTERVAL,
    DEFAULT_ALERT_NOTIFICATIONS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_VOLTAGE_PUBLISH_INTERVAL,
    DOMAIN,
)
from .coordinator import WhiskerConfigEntry, WhiskerDataUpdateCoordinator

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.EVENT, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: WhiskerConfigEntry) -> bool:
    """Set up Whisker Ting from a config entry."""
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    notify_enabled = entry.options.get(
        CONF_ALERT_NOTIFICATIONS, DEFAULT_ALERT_NOTIFICATIONS
    )
    voltage_publish_interval = entry.options.get(
        CONF_VOLTAGE_PUBLISH_INTERVAL, DEFAULT_VOLTAGE_PUBLISH_INTERVAL
    )

    session = async_get_clientsession(hass)
    client = WhiskerApiClient(session, username, password)

    coordinator = WhiskerDataUpdateCoordinator(
        hass,
        client,
        session,
        scan_interval,
        notify_enabled,
        voltage_publish_interval,
        config_entry=entry,
    )
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator

    _async_cleanup_stale_mac_connections(hass, coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_options_updated))
    return True


def _async_cleanup_stale_mac_connections(
    hass: HomeAssistant, coordinator: WhiskerDataUpdateCoordinator
) -> None:
    """Drop byte-reversed MAC connections registered by older versions.

    Builds before 1.2.0 registered the Wi-Fi MAC — and before 3.0.1 the
    Bluetooth MAC — in the API's reversed byte order. The device registry
    only ever merges connections, so the stale reversed rows sat alongside
    the corrected ones forever. Remove exactly the reversed forms of the
    currently known MACs; any other connection (including ones shared with
    other integrations, e.g. a network integration merged via the correct
    MAC) is left untouched.
    """
    registry = dr.async_get(hass)
    for device_state in (coordinator.data or {}).values():
        device = registry.async_get_device(
            identifiers={(DOMAIN, device_state.serial_number)}
        )
        if device is None:
            continue

        stale: set[tuple[str, str]] = set()
        for conn_type, mac in (
            (CONNECTION_NETWORK_MAC, device_state.wifi_mac_address),
            (CONNECTION_BLUETOOTH, device_state.bluetooth_mac_address),
        ):
            if not mac:
                continue
            reversed_mac = _reverse_mac(mac)
            if reversed_mac and reversed_mac != mac:
                stale.add((conn_type, format_mac(reversed_mac)))

        to_remove = stale & device.connections
        if to_remove:
            _LOGGER.info(
                "Removing stale reversed MAC connections from device %s: %s",
                device_state.serial_number,
                sorted(to_remove),
            )
            registry.async_update_device(
                device.id, new_connections=device.connections - to_remove
            )


async def async_options_updated(hass: HomeAssistant, entry: WhiskerConfigEntry) -> None:
    """Handle options update."""
    coordinator: WhiskerDataUpdateCoordinator = entry.runtime_data
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    coordinator.update_interval = timedelta(seconds=scan_interval)
    coordinator.notify_enabled = entry.options.get(
        CONF_ALERT_NOTIFICATIONS, DEFAULT_ALERT_NOTIFICATIONS
    )
    coordinator.set_voltage_publish_interval(
        entry.options.get(
            CONF_VOLTAGE_PUBLISH_INTERVAL, DEFAULT_VOLTAGE_PUBLISH_INTERVAL
        )
    )
    _LOGGER.debug(
        "Updated options: scan_interval=%s notify_enabled=%s "
        "voltage_publish_interval=%s",
        scan_interval,
        coordinator.notify_enabled,
        coordinator.voltage_publish_interval,
    )


async def async_unload_entry(hass: HomeAssistant, entry: WhiskerConfigEntry) -> bool:
    """Unload a config entry."""
    # Shutdown the coordinator (disconnects WebSocket)
    coordinator: WhiskerDataUpdateCoordinator = entry.runtime_data
    await coordinator.async_shutdown()

    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
