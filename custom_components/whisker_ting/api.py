"""API client for Whisker Ting."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import logging
from typing import Any

import aiohttp

from homeassistant.util import dt as dt_util

from .auth import AuthenticationError, WhiskerAuth
from .const import API_BASE_URL, API_NOTIFICATIONS_ENDPOINT, API_USERS_ENDPOINT

_LOGGER = logging.getLogger(__name__)


def _reverse_mac(mac: str | None) -> str | None:
    """Reverse the octet order of a MAC reported by the Ting API.

    The API serializes both the Wi-Fi and Bluetooth MACs in reversed
    (little-endian) byte order, so a device whose physical address is
    ``80:6a:10:19:2a:b7`` is reported as ``b7:2a:19:10:6a:80``. Normalize
    to physical order and return a lowercase,
    colon-delimited string. The input is returned unchanged when it is missing
    or not a parseable 6-octet MAC.
    """
    if not mac:
        return mac
    hex_only = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(hex_only) != 12:
        return mac
    try:
        int(hex_only, 16)
    except ValueError:
        return mac
    octets = [hex_only[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(reversed(octets)).lower()


def _parse_aware_datetime(value: str | None) -> datetime | None:
    """Parse an ISO datetime string, coercing a naive result to UTC.

    All observed Ting API timestamps include a UTC offset, but a naive
    result (missing offset) would blank a ``device_class=timestamp`` sensor
    and risk a ``TypeError`` when compared against aware datetimes elsewhere.
    """
    if not value:
        return None
    parsed = dt_util.parse_datetime(value)
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


@dataclass
class HazardStatus:
    """Represents a hazard status (EFH or UFH)."""

    status: str | None = None
    timestamp_utc: str | None = None
    level: int | None = None
    message: str = "No Hazards Detected"
    hex_color: str = "#00FF00"


@dataclass
class FireHazardStatus:
    """Represents the fire hazard status of a device."""

    learning_mode: bool = False
    message: str = "No Hazards Detected"
    efh_status: HazardStatus = field(default_factory=HazardStatus)
    ufh_status: HazardStatus = field(default_factory=HazardStatus)
    hex_color_light: str = "#00FF00"
    hex_color_medium: str = "#358C15"
    hex_color_dark: str = "#233016"


@dataclass
class VoltageReading:
    """Real-time voltage reading."""

    voltage: float = 0.0
    voltage_hi: float = 0.0
    voltage_lo: float = 0.0
    average_peaks_max: float = 0.0


@dataclass
class DeviceState:
    """Represents the state of a Whisker Ting device."""

    serial_number: str
    name: str
    device_type: str
    site_id: int

    # Device info
    version: str | None = None
    wifi_mac_address: str | None = None
    bluetooth_mac_address: str | None = None
    soc_serial_number: str | None = None
    station_id: str | None = None  # For WebSocket connection
    subscription_start_date: str | None = None

    # Status flags
    is_fire: bool = False
    is_hvac_verified: bool = False
    has_frozen_pipe: bool = False
    is_owner: bool = False
    # Site-level flag, joined from the device's site by siteId.
    is_power_quality_hazard: bool = False

    # Hazard status
    fire_hazard_status: FireHazardStatus = field(default_factory=FireHazardStatus)

    # Real-time voltage (from WebSocket)
    voltage: VoltageReading = field(default_factory=VoltageReading)

    # Group info
    group_name: str | None = None
    group_id: int | None = None

    site_name: str | None = None
    notifications: list[TingNotification] = field(default_factory=list)


@dataclass
class Site:
    """Represents a site/location."""

    id: int
    user_id: int
    display_name: str
    address_line1: str | None = None
    city: str | None = None
    state_province: str | None = None
    postal_code: str | None = None
    country: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    is_power_quality_hazard: bool = False


@dataclass
class TingNotification:
    """A Ting notification (alert)."""

    id: str
    event_type: str
    event_category: str | None = None
    title: str | None = None
    subtitle: str | None = None
    message: str | None = None
    timestamp: datetime | None = None  # from eventTimestampLocal (tz-aware)
    sent_utc: datetime | None = None
    serial_number: str | None = None
    site_id: int | None = None
    is_acknowledged: bool = False
    is_cleared: bool = False


@dataclass
class UserData:
    """Represents user data from the API."""

    user_id: int
    email: str
    first_name: str
    last_name: str
    phone_number: str | None = None
    devices: list[DeviceState] = field(default_factory=list)
    sites: list[Site] = field(default_factory=list)


class WhiskerApiError(Exception):
    """Base exception for Whisker API errors."""


class WhiskerAuthError(WhiskerApiError):
    """Authentication error."""


class WhiskerConnectionError(WhiskerApiError):
    """Connection error."""


class WhiskerApiClient:
    """Client for the Whisker Ting API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
    ) -> None:
        """Initialize the API client."""
        self._session = session
        self._username = username
        self._password = password
        self._auth = WhiskerAuth(session)

        # Token storage
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._id_token: str | None = None
        self._api_key: str | None = None
        self._user_id: int | None = None
        self._token_expiry: datetime | None = None
        self._lock = asyncio.Lock()

    @property
    def user_id(self) -> int | None:
        """Return the user ID."""
        return self._user_id

    @property
    def api_key(self) -> str | None:
        """Return the API key."""
        return self._api_key

    async def _ensure_token(self) -> str:
        """Ensure we have a valid access token."""
        async with self._lock:
            # Refresh if token expires in less than 5 minutes
            if (
                self._access_token
                and self._token_expiry
                and dt_util.utcnow() < self._token_expiry - timedelta(minutes=5)
            ):
                return self._access_token

            # Need to authenticate or refresh
            if self._refresh_token:
                try:
                    await self._refresh_access_token()
                except AuthenticationError:
                    # Refresh failed, try full auth
                    pass
                else:
                    return self._access_token

            # Full authentication
            await self._authenticate()
            return self._access_token

    async def _authenticate(self) -> None:
        """Perform full authentication."""
        _LOGGER.debug("Performing full authentication")
        try:
            result = await self._auth.authenticate(self._username, self._password)

            self._access_token = result["access_token"]
            self._refresh_token = result["refresh_token"]
            self._id_token = result["id_token"]

            # Use the lifetime Cognito reports rather than assuming one hour.
            expires_in = int(result.get("expires_in", 3600))
            self._token_expiry = dt_util.utcnow() + timedelta(seconds=expires_in)

            # Extract user info from attributes
            user_attrs = {
                attr["Name"]: attr["Value"]
                for attr in result.get("user_attributes", [])
            }
            self._user_id = int(user_attrs.get("custom:user_id", 0))
            self._api_key = user_attrs.get("custom:api_key")

            _LOGGER.debug("Authentication successful, user_id=%s", self._user_id)

        except AuthenticationError as err:
            raise WhiskerAuthError(str(err)) from err

    async def _refresh_access_token(self) -> None:
        """Refresh the access token."""
        _LOGGER.debug("Refreshing access token")
        try:
            result = await self._auth.refresh_tokens(self._refresh_token)

            self._access_token = result["AccessToken"]
            self._id_token = result.get("IdToken", self._id_token)
            expires_in = int(result.get("ExpiresIn", 3600))
            self._token_expiry = dt_util.utcnow() + timedelta(seconds=expires_in)

            _LOGGER.debug("Access token refreshed")

        except AuthenticationError as err:
            raise WhiskerAuthError(str(err)) from err

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated request to the API."""
        token = await self._ensure_token()

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "x-wl-api-key": self._api_key or "",
        }

        url = f"{API_BASE_URL}{endpoint}"

        try:
            async with self._session.request(
                method, url, headers=headers, **kwargs
            ) as response:
                if response.status == 401:
                    # Token might have expired, try refreshing once
                    async with self._lock:
                        await self._authenticate()
                    token = self._access_token
                    headers["Authorization"] = f"Bearer {token}"
                    async with self._session.request(
                        method, url, headers=headers, **kwargs
                    ) as retry_response:
                        if retry_response.status == 401:
                            raise WhiskerAuthError("Authentication failed")
                        retry_response.raise_for_status()
                        return await retry_response.json()

                if response.status != 200:
                    text = await response.text()
                    raise WhiskerApiError(
                        f"API request failed with status {response.status}: {text}"
                    )

                return await response.json()

        except aiohttp.ClientError as err:
            raise WhiskerConnectionError(f"Connection error: {err}") from err

    async def get_user_data(self) -> UserData:
        """Get user data including devices."""
        if not self._user_id:
            await self._ensure_token()

        endpoint = API_USERS_ENDPOINT.format(user_id=self._user_id)
        data = await self._request("GET", endpoint)

        return self._parse_user_data(data)

    def _parse_user_data(self, data: dict[str, Any]) -> UserData:
        """Parse user data from API response."""
        # Parse sites first so device parsing can join site-level fields.
        sites = []
        site_map: dict[int, Site] = {}
        for site_data in data.get("sites", []):
            site = Site(
                id=site_data.get("id", 0),
                user_id=site_data.get("userId", 0),
                display_name=site_data.get("displayName", ""),
                address_line1=site_data.get("addressLine1"),
                city=site_data.get("city"),
                state_province=site_data.get("stateProvince"),
                postal_code=site_data.get("postalCode"),
                country=site_data.get("country"),
                latitude=site_data.get("latitude"),
                longitude=site_data.get("longitude"),
                is_power_quality_hazard=site_data.get("isPowerQualityHazard", False),
            )
            sites.append(site)
            site_map[site.id] = site

        devices = []
        for device_data in data.get("devices", []):
            device = self._parse_device(device_data, site_map)
            devices.append(device)

        return UserData(
            user_id=data.get("id", 0),
            email=data.get("email", ""),
            first_name=data.get("firstName", ""),
            last_name=data.get("lastName", ""),
            phone_number=data.get("phoneNumber"),
            devices=devices,
            sites=sites,
        )

    def _parse_device(
        self, data: dict[str, Any], site_map: dict[int, Site] | None = None
    ) -> DeviceState:
        """Parse device state from API response."""
        # Parse fire hazard status
        fhs_data = data.get("fireHazardStatus", {})
        efh_data = fhs_data.get("efhStatus", {})
        ufh_data = fhs_data.get("ufhStatus", {})
        hex_colors = fhs_data.get("hexColor", {})

        efh_status = HazardStatus(
            status=efh_data.get("status"),
            timestamp_utc=efh_data.get("timestampUtc"),
            level=efh_data.get("level"),
            message=efh_data.get("message", "No Hazards Detected"),
            hex_color=efh_data.get("hexColor", "#00FF00"),
        )

        ufh_status = HazardStatus(
            status=ufh_data.get("status"),
            timestamp_utc=ufh_data.get("timestampUtc"),
            level=ufh_data.get("level"),
            message=ufh_data.get("message", "No Hazards Detected"),
            hex_color=ufh_data.get("hexColor", "#00FF00"),
        )

        fire_hazard_status = FireHazardStatus(
            learning_mode=fhs_data.get("learningMode", False),
            message=fhs_data.get("message", "No Hazards Detected"),
            efh_status=efh_status,
            ufh_status=ufh_status,
            hex_color_light=hex_colors.get("light", "#00FF00"),
            hex_color_medium=hex_colors.get("medium", "#358C15"),
            hex_color_dark=hex_colors.get("dark", "#233016"),
        )

        # Parse group info
        group_data = data.get("group", {})

        # Get station_id for WebSocket - it's the serial number
        station_id = data.get("serialNumber", "")

        # Join site-level fields from the device's site.
        site_id = data.get("siteId", 0)
        site = (site_map or {}).get(site_id)

        return DeviceState(
            serial_number=data.get("serialNumber", ""),
            name=data.get("name", data.get("serialNumber", "")),
            device_type=data.get("type", "Unknown"),
            site_id=site_id,
            version=data.get("version"),
            wifi_mac_address=_reverse_mac(data.get("wifiMacAddress")),
            bluetooth_mac_address=_reverse_mac(data.get("bluetoothMacAddress")),
            soc_serial_number=data.get("socSerialNumber"),
            station_id=station_id,
            subscription_start_date=data.get("subscriptionStartDate"),
            is_fire=data.get("isFire", False),
            is_hvac_verified=data.get("isHvacVerified", False),
            has_frozen_pipe=data.get("hasFrozenPipe", False),
            is_owner=data.get("isOwner", False),
            is_power_quality_hazard=bool(site.is_power_quality_hazard)
            if site
            else False,
            site_name=site.display_name if site else None,
            fire_hazard_status=fire_hazard_status,
            group_name=group_data.get("name"),
            group_id=group_data.get("id"),
        )

    async def get_all_device_states(self) -> dict[str, DeviceState]:
        """Get the state of all devices."""
        user_data = await self.get_user_data()
        return {device.serial_number: device for device in user_data.devices}

    async def get_notifications(self) -> list[TingNotification]:
        """Get the account's recent notifications (alerts)."""
        if not self._user_id:
            await self._ensure_token()
        endpoint = API_NOTIFICATIONS_ENDPOINT.format(user_id=self._user_id)
        data = await self._request("GET", endpoint)
        if not isinstance(data, list):
            return []
        return [self._parse_notification(item) for item in data]

    @staticmethod
    def _parse_notification(data: dict[str, Any]) -> TingNotification:
        """Parse one notification from the API."""
        return TingNotification(
            id=data.get("id", ""),
            event_type=data.get("eventType", "unknown"),
            event_category=data.get("eventCategory"),
            title=data.get("title"),
            subtitle=data.get("subtitle"),
            message=data.get("message"),
            timestamp=_parse_aware_datetime(data.get("eventTimestampLocal")),
            sent_utc=_parse_aware_datetime(data.get("sentUtc")),
            serial_number=data.get("serialNumber"),
            site_id=data.get("siteId"),
            is_acknowledged=data.get("isAcknowledged", False),
            is_cleared=data.get("isCleared", False),
        )
