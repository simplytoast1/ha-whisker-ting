"""Data coordinator for Whisker Ting."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

import aiohttp

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import DeviceState, VoltageReading, WhiskerApiClient, WhiskerApiError, WhiskerAuthError
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .websocket import VoltageData, WhiskerWebSocketManager

_LOGGER = logging.getLogger(__name__)


class WhiskerDataUpdateCoordinator(DataUpdateCoordinator[dict[str, DeviceState]]):
    """Class to manage fetching Whisker Ting data."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: WhiskerApiClient,
        session: aiohttp.ClientSession,
        update_interval_seconds: int = DEFAULT_SCAN_INTERVAL,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval_seconds),
        )
        self.client = client
        self._session = session
        self._last_update_success: bool | None = None
        self._ws_manager: WhiskerWebSocketManager | None = None
        self._ws_connected = False

    @callback
    def _handle_voltage_update(self, station_id: str, voltage_data: VoltageData) -> None:
        """Handle real-time voltage update from WebSocket."""
        if self.data is None:
            return

        # Find the device with this station_id
        for device_id, device_state in self.data.items():
            if device_state.station_id == station_id:
                # Update the voltage reading
                device_state.voltage = VoltageReading(
                    voltage=voltage_data.voltage,
                    voltage_hi=voltage_data.voltage_hi,
                    voltage_lo=voltage_data.voltage_lo,
                    average_peaks_max=voltage_data.average_peaks_max,
                )
                # Trigger an update for listeners
                self.async_set_updated_data(self.data)
                break

    async def _connect_websocket(self, data: dict[str, DeviceState]) -> None:
        """Connect to WebSocket for real-time updates."""
        if self._ws_manager is None:
            self._ws_manager = WhiskerWebSocketManager(
                session=self._session,
                on_voltage_update=self._handle_voltage_update,
            )

        if not data or self._ws_connected:
            return

        # Get api_key and user_id from the client
        api_key = self.client.api_key
        user_id = self.client.user_id

        if not api_key or not user_id:
            _LOGGER.debug("No api_key or user_id, skipping WebSocket connection")
            return

        # Connect to each device's WebSocket stream
        for device_id, device_state in data.items():
            if device_state.station_id:
                try:
                    connected = await self._ws_manager.connect_device(
                        api_key=api_key,
                        user_id=user_id,
                        station_id=device_state.station_id,
                    )
                    if connected:
                        _LOGGER.info(
                            "Connected to WebSocket for device %s (station %s)",
                            device_id,
                            device_state.station_id,
                        )
                        self._ws_connected = True
                except Exception as err:
                    _LOGGER.warning(
                        "Failed to connect WebSocket for device %s: %s",
                        device_id,
                        err,
                    )

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        if self._ws_manager:
            await self._ws_manager.disconnect_all()
            self._ws_connected = False
        await super().async_shutdown()

    async def _async_update_data(self) -> dict[str, DeviceState]:
        """Fetch data from the API."""
        try:
            data = await self.client.get_all_device_states()

            # Preserve existing voltage data from WebSocket
            if self.data:
                for device_id, device_state in data.items():
                    existing = self.data.get(device_id)
                    if existing and existing.voltage.voltage > 0:
                        device_state.voltage = existing.voltage

            if self._last_update_success is False:
                _LOGGER.info("Connection to Whisker Ting API restored")
            self._last_update_success = True

            # Connect WebSocket on first fetch and wait for data
            if not self._ws_connected:
                await self._connect_websocket(data)
                # Wait for actual voltage data to arrive (not arbitrary sleep)
                if self._ws_connected and self._ws_manager:
                    # Wait for data from all devices in parallel
                    wait_tasks = [
                        self._ws_manager.wait_for_data(device_state.station_id, timeout=5.0)
                        for device_state in data.values()
                        if device_state.station_id
                    ]
                    if wait_tasks:
                        await asyncio.gather(*wait_tasks)
                    # Update data with voltage readings received
                    for device_id, device_state in data.items():
                        if device_state.station_id:
                            voltage_data = self._ws_manager.get_voltage_data(device_state.station_id)
                            if voltage_data:
                                device_state.voltage = VoltageReading(
                                    voltage=voltage_data.voltage,
                                    voltage_hi=voltage_data.voltage_hi,
                                    voltage_lo=voltage_data.voltage_lo,
                                    average_peaks_max=voltage_data.average_peaks_max,
                                )

            return data
        except WhiskerAuthError as err:
            self._last_update_success = False
            raise ConfigEntryAuthFailed(
                "Authentication failed - credentials may have changed"
            ) from err
        except WhiskerApiError as err:
            if self._last_update_success is not False:
                _LOGGER.warning("Unable to connect to Whisker Ting API: %s", err)
            self._last_update_success = False
            raise UpdateFailed(
                f"Error communicating with Whisker Ting API: {err}"
            ) from err
