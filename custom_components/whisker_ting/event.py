"""Event platform for Whisker Ting alerts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.event import EventEntity
from homeassistant.core import HomeAssistant, callback

from .const import NOTIFICATION_EVENT_TYPES
from .entity import WhiskerEntity

if TYPE_CHECKING:
    from datetime import datetime

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .api import TingNotification
    from .coordinator import WhiskerDataUpdateCoordinator

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Whisker Ting alert event entities."""
    coordinator = entry.runtime_data
    async_add_entities(
        WhiskerAlertsEvent(coordinator, device_id) for device_id in coordinator.data
    )


class WhiskerAlertsEvent(WhiskerEntity, EventEntity):
    """Fires when a new Ting notification arrives for this device."""

    _attr_translation_key = "alerts"
    _attr_event_types = NOTIFICATION_EVENT_TYPES

    def __init__(
        self, coordinator: WhiskerDataUpdateCoordinator, device_id: str
    ) -> None:
        """Initialize the alerts event entity."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_alerts"
        # Seed from whatever backlog the coordinator already fetched at
        # construction time (entities are created *after* the coordinator's
        # first refresh, so `_handle_coordinator_update` below only ever runs
        # from the second fetch onward — seeding there would be one poll too
        # late and would replay whatever changed between poll 1 and poll 2).
        notifications = self._device_notifications()
        self._last_fired: datetime | None = (
            notifications[-1].sent_utc if notifications else None
        )

    def _device_notifications(self) -> list[TingNotification]:
        device_state = self.coordinator.data.get(self._device_id)
        if device_state is None:
            return []
        return sorted(
            (n for n in device_state.notifications if n.sent_utc is not None),
            key=lambda n: n.sent_utc,
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        for note in self._device_notifications():
            if self._last_fired is not None and note.sent_utc <= self._last_fired:
                continue
            event_type = (
                note.event_type
                if note.event_type in NOTIFICATION_EVENT_TYPES
                else "unknown"
            )
            self._trigger_event(
                event_type,
                {
                    "title": note.title,
                    "subtitle": note.subtitle,
                    "message": note.message,
                    "category": note.event_category,
                    "raw_event_type": note.event_type,
                    "timestamp": note.timestamp.isoformat() if note.timestamp else None,
                    "notification_id": note.id,
                    "acknowledged": note.is_acknowledged,
                    "cleared": note.is_cleared,
                },
            )
            self._last_fired = note.sent_utc
        super()._handle_coordinator_update()
