"""Diagnostics support for Whisker Ting."""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from homeassistant.components.diagnostics import async_redact_data

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .coordinator import WhiskerConfigEntry

TO_REDACT = {
    # entry.data stores the account email under CONF_USERNAME ("username"),
    # not "email" - redact the actual key so it doesn't leak in entry_data.
    "username",
    "password",
    "api_key",
    "email",
    "phone_number",
    "wifi_mac_address",
    "bluetooth_mac_address",
    "soc_serial_number",
    "address_line1",
    "latitude",
    "longitude",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: WhiskerConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data
    devices = {
        device_id: async_redact_data(asdict(state), TO_REDACT)
        for device_id, state in coordinator.data.items()
    }
    return {
        "entry_data": async_redact_data(dict(entry.data), TO_REDACT),
        "devices": devices,
    }
