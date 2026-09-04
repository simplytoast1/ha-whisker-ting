"""WebSocket client for real-time Whisker Ting data.

Transport lifecycle lives here; all wire encoding/decoding lives in
``protocol.py``.

Two server behaviours dominate the design of this module, both learned
the hard way (see ``protocol.py`` for the wire-level details):

1. ``InitializeStreaming`` is answered with a *void* Completion — a
   success acknowledgement — and the voltage stream follows afterwards as
   separate server-to-client invocations on the SAME socket. The
   connection must therefore stay open after the acknowledgement; closing
   it there makes data delivery impossible.
2. The hub holds ONE subscription per station, and it is not implicitly
   released when a connection goes away. A leaked registration causes
   every later ``InitializeStreaming`` for that station to be
   acknowledged and then served nothing, indefinitely. So this client
   sends ``UnInitializeStreaming`` immediately before subscribing, and
   again on every teardown path (``disconnect``, plus the stale-data and
   first-data-grace recycles). The official app pairs the two calls the
   same way.

Historical note: the original client sent an unframed ``{1: [...]}`` map
instead of a length-prefixed flat array, which made the server drop every
connection ~70 ms after the first keepalive ping — a permanent reconnect
churn loop. That is fixed in ``protocol.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import TYPE_CHECKING

import aiohttp

from homeassistant.util import dt as dt_util

from . import protocol
from .const import SIGNALR_URL
from .protocol import SignalRProtocolError, VoltageData

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

_LOGGER = logging.getLogger(__name__)

# Re-exported for backward compatibility; VoltageData now lives in protocol.py.
__all__ = ["VoltageData", "WhiskerWebSocket", "WhiskerWebSocketManager"]

# How often the manager publishes the latest sample to Home Assistant by
# default. The stream arrives at ~4 Hz; publishing every sample would write
# ~345,000 recorder rows per voltage entity per day.
DEFAULT_PUBLISH_INTERVAL = 5.0


class WhiskerWebSocket:
    """WebSocket client for one station on the Whisker Ting SignalR hub."""

    # Consider data stale if no update in 30 seconds (normally ~4 Hz).
    # The official app uses serverTimeoutInMilliseconds = 20000.
    STALE_DATA_THRESHOLD = 30
    # Keepalive ping cadence (seconds), matching the official app's
    # keepAliveIntervalInMilliseconds = 3000 (chunk-GBDILMAT.js). Parity
    # with the reference client; it does NOT gate stream delivery.
    PING_INTERVAL = 3
    # A connection that has never produced data gets this long before the
    # stale loop recycles it. The recycle tears the subscription down
    # properly (UnInitializeStreaming) so the retry can re-register.
    FIRST_DATA_GRACE = 60

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        user_id: int,
        station_id: str,
        on_voltage_update: Callable[[str, VoltageData], None] | None = None,
        on_disconnect: Callable[[str, WhiskerWebSocket], None] | None = None,
    ) -> None:
        """Initialize the WebSocket client."""
        self._session = session
        self._api_key = api_key  # The api_key is used as the stream token
        self._user_id = user_id
        self._station_id = station_id
        self._on_voltage_update = on_voltage_update
        self._on_disconnect = on_disconnect
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._connected = False
        self._ping_task: asyncio.Task | None = None
        self._receive_task: asyncio.Task | None = None
        self._stale_check_task: asyncio.Task | None = None
        self._message_id = 0
        self._first_data_received = asyncio.Event()
        self._stream_rejected = asyncio.Event()
        self._last_data_time: datetime | None = None
        self._connect_time: datetime | None = None
        self._shutting_down = False

    @property
    def connected(self) -> bool:
        """Return True if connected."""
        return self._connected

    @property
    def stream_rejected(self) -> bool:
        """Return True if the server rejected the streaming subscription."""
        return self._stream_rejected.is_set()

    def _encode_invocation(self, method: str, args: list) -> bytes:
        """Encode a spec-framed SignalR invocation message."""
        self._message_id += 1
        return protocol.encode_invocation(str(self._message_id), method, args)

    async def connect(self) -> bool:
        """Connect to the SignalR hub and start the streaming subscription."""
        try:
            _LOGGER.debug("Connecting to SignalR hub: %s", SIGNALR_URL)

            self._ws = await self._session.ws_connect(
                SIGNALR_URL,
                headers={
                    "Origin": "ionic://localhost",
                    # The hub also authorizes at the HTTP-upgrade level via
                    # this header (matches the official app's traffic).
                    "x-wl-api-key": self._api_key,
                },
            )

            # Send protocol negotiation
            handshake = '{"protocol":"messagepack","version":1}\x1e'
            await self._ws.send_str(handshake)

            # Validate the handshake response
            msg = await self._ws.receive(timeout=10)
            if msg.type not in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT):
                raise SignalRProtocolError(  # noqa: TRY301 - connect() is the sole handler
                    f"unexpected handshake response type: {msg.type.name}"
                )
            handshake_data = (
                msg.data.decode("utf-8") if isinstance(msg.data, bytes) else msg.data
            )
            if not handshake_data.endswith("\x1e"):
                raise SignalRProtocolError(  # noqa: TRY301 - connect() is the sole handler
                    "unterminated SignalR handshake response"
                )
            handshake_result = json.loads(handshake_data[:-1])
            if handshake_result.get("error"):
                raise SignalRProtocolError(  # noqa: TRY301 - connect() is the sole handler
                    f"SignalR handshake failed: {handshake_result['error']}"
                )

            init_args = [
                {"StationId": self._station_id, "DataElement": "ComboBinaryData"},
                self._api_key,
                str(self._user_id),
            ]

            # Release any subscription the server still holds for this
            # station BEFORE subscribing. A stale registration (left by any
            # client that dropped without tearing down) makes the server
            # acknowledge a new InitializeStreaming and then never fan out
            # the stream to it. The official app always pairs these calls
            # (chunk-GBDILMAT.js: invokeStreamingMethod /
            # unInvokeStreamingMethod); no third-party client ever has.
            # SignalR processes invocations from one connection in order
            # (MaximumParallelInvocationsPerClient defaults to 1), so the
            # release is guaranteed to be handled before the subscribe.
            await self._ws.send_bytes(
                self._encode_invocation("UnInitializeStreaming", init_args)
            )

            # Subscribe to the device stream using api_key as the token
            init_msg = self._encode_invocation("InitializeStreaming", init_args)
            await self._ws.send_bytes(init_msg)

            self._connected = True
            self._connect_time = dt_util.utcnow()
            # _last_data_time intentionally stays None until real data
            # arrives, so freshness never reflects a silent subscription.

            # Start background tasks
            self._receive_task = asyncio.create_task(self._receive_loop())
            self._ping_task = asyncio.create_task(self._ping_loop())
            self._stale_check_task = asyncio.create_task(self._stale_data_check_loop())

            _LOGGER.info("Connected to SignalR hub for station %s", self._station_id)

        except asyncio.CancelledError:
            await self._close_ws()
            raise
        except Exception as err:  # noqa: BLE001 - connect spans network I/O, the
            # protocol handshake, and encoding; any failure must resolve to False.
            _LOGGER.error("Failed to connect to SignalR hub: %s", err)
            self._connected = False
            # Don't leak the socket when a post-upgrade step failed
            await self._close_ws()
            return False
        else:
            return True

    async def _send_uninitialize(self) -> None:
        """Best-effort teardown of this station's server-side subscription.

        Leaving a subscription registered blocks every later subscribe for
        the station (the server acknowledges them and streams nothing), so
        this must run before the socket goes away.
        """
        if not self._ws or self._ws.closed:
            return
        args = [
            {"StationId": self._station_id, "DataElement": "ComboBinaryData"},
            self._api_key,
            str(self._user_id),
        ]
        with contextlib.suppress(Exception):
            await self._ws.send_bytes(
                self._encode_invocation("UnInitializeStreaming", args)
            )

    async def _close_ws(self) -> None:
        """Close the underlying WebSocket if it is open (best effort)."""
        if self._ws and not self._ws.closed:
            with contextlib.suppress(Exception):
                await self._ws.close()

    async def disconnect(self) -> None:
        """Disconnect from the SignalR hub, releasing the subscription."""
        self._shutting_down = True
        self._connected = False

        # Release the server-side subscription first; a leaked registration
        # blocks every subsequent subscribe for this station.
        await self._send_uninitialize()

        for task in [self._ping_task, self._receive_task, self._stale_check_task]:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        self._ping_task = None
        self._receive_task = None
        self._stale_check_task = None

        if self._ws and not self._ws.closed:
            await self._ws.close()
            self._ws = None

        _LOGGER.debug("Disconnected from SignalR hub")

    async def wait_for_data(self, timeout: float = 5.0) -> bool:  # noqa: ASYNC109
        """Return True on first data, False on timeout or server rejection."""
        # `timeout` is this method's own public contract (used below via
        # asyncio.wait), not a passthrough to another timeout-aware call;
        # callers (coordinator, tests) rely on this signature.
        data_task = asyncio.ensure_future(self._first_data_received.wait())
        reject_task = asyncio.ensure_future(self._stream_rejected.wait())
        try:
            await asyncio.wait(
                {data_task, reject_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for task in (data_task, reject_task):
                if not task.done():
                    task.cancel()
        return self._first_data_received.is_set()

    def _handle_hub_message(self, message: list) -> None:
        """Dispatch one decoded SignalR hub message."""
        voltage_data = protocol.decode_voltage_update(message)
        if voltage_data is not None:
            self._last_data_time = dt_util.utcnow()
            if not self._first_data_received.is_set():
                self._first_data_received.set()
            if self._on_voltage_update:
                self._on_voltage_update(self._station_id, voltage_data)
            return

        if protocol.completion_message(message):
            error = protocol.completion_error(message)
            if error is None:
                # A Completion without an error is the NORMAL acknowledgement
                # that the blocking InitializeStreaming invocation returned.
                # On the wire Ting sends ResultKind 3 with a null result
                # ([3, {}, "1", 3, None]); ResultKind 2 (void) is equally
                # benign. Voltage arrives afterwards as separate
                # server-to-client invocations on this same socket, so the
                # connection must stay open. Treating this as a rejection
                # tore the socket down before the first sample could arrive
                # (regression in 3.0.0-3.0.3).
                _LOGGER.debug(
                    "InitializeStreaming acknowledged for station %s",
                    self._station_id,
                )
                return
            # Only ResultKind 1 carries an error — a real rejection.
            _LOGGER.warning(
                "Streaming subscription rejected for station %s: %s",
                self._station_id,
                error,
            )
            self._stream_rejected.set()
            self._connected = False  # receive loop exits and notifies
            return

        if message[0] == protocol.MSG_TYPE_CLOSE:
            error = protocol.close_error(message)
            _LOGGER.warning(
                "Server closed stream for station %s%s",
                self._station_id,
                f": {error}" if error else "",
            )
            self._connected = False  # receive loop exits and notifies
            return

        if message[0] == protocol.MSG_TYPE_PING:
            _LOGGER.debug("Received keepalive ping from server")
            return

        _LOGGER.debug("Unhandled hub message type %s", message[0])

    async def _receive_loop(self) -> None:
        """Receive messages from the WebSocket."""
        while self._connected and self._ws and not self._ws.closed:
            try:
                msg = await asyncio.wait_for(self._ws.receive(), timeout=30)

                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        messages = protocol.decode_hub_messages(msg.data)
                    except SignalRProtocolError as err:
                        _LOGGER.debug(
                            "Undecodable frame from station %s (%s): %s",
                            self._station_id,
                            err,
                            msg.data[:32].hex(),
                        )
                        continue
                    for message in messages:
                        self._handle_hub_message(message)

                elif msg.type == aiohttp.WSMsgType.TEXT:
                    _LOGGER.debug("Received text message: %s", msg.data)

                elif msg.type in (
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                ):
                    _LOGGER.warning("WebSocket closed or error: %s", msg.type)
                    self._connected = False
                    break

            except TimeoutError:
                _LOGGER.debug("WebSocket receive timeout, continuing...")
            except asyncio.CancelledError:
                break
            except Exception as err:  # noqa: BLE001 - background task must not
                # die silently on an unexpected error; log and stop cleanly.
                _LOGGER.error("Error in receive loop: %s", err)
                self._connected = False
                break

        # Notify manager that we disconnected (for reconnection). The
        # receive loop is the SOLE notifier — every other path (stale
        # check, rejection, server Close) only flips _connected / closes
        # the socket and lets this loop observe it, so the manager gets
        # exactly one notification per connection lifetime.
        if not self._shutting_down and self._on_disconnect:
            _LOGGER.warning(
                "WebSocket disconnected for station %s, triggering reconnect",
                self._station_id,
            )
            self._on_disconnect(self._station_id, self)

    async def _stale_data_check_loop(self) -> None:
        """Recycle the connection when the stream goes stale or stays silent."""
        while self._connected and not self._shutting_down:
            try:
                await asyncio.sleep(self.STALE_DATA_THRESHOLD)

                if not self._connected or self._shutting_down:
                    break

                now = dt_util.utcnow()
                if self._last_data_time is None:
                    # Never received data on this connection. Give it a
                    # grace period, then recycle — the subscription may be
                    # silently unauthorized, and that server-side state has
                    # been observed to clear on later attempts.
                    if (
                        self._connect_time is not None
                        and (now - self._connect_time).total_seconds()
                        > self.FIRST_DATA_GRACE
                    ):
                        _LOGGER.warning(
                            "No voltage data for station %s within %ds of "
                            "connecting, recycling connection",
                            self._station_id,
                            self.FIRST_DATA_GRACE,
                        )
                        # Close the socket instead of notifying directly:
                        # the receive loop wakes immediately on CLOSED and
                        # is the sole notifier (prevents double-notify).
                        self._connected = False
                        await self._send_uninitialize()
                        if self._ws and not self._ws.closed:
                            await self._ws.close()
                        break
                    continue

                time_since_update = (now - self._last_data_time).total_seconds()
                if time_since_update > self.STALE_DATA_THRESHOLD:
                    _LOGGER.error(
                        "WebSocket data stale for station %s (no update in "
                        "%.0f seconds), reconnecting",
                        self._station_id,
                        time_since_update,
                    )
                    # Close the socket instead of notifying directly: the
                    # receive loop wakes immediately on CLOSED and is the
                    # sole notifier (prevents double-notify).
                    self._connected = False
                    await self._send_uninitialize()
                    if self._ws and not self._ws.closed:
                        await self._ws.close()
                    break

            except asyncio.CancelledError:
                break
            except Exception as err:  # noqa: BLE001 - background task must not
                # die silently on an unexpected error; log and stop cleanly.
                _LOGGER.error("Error in stale data check: %s", err)
                break

    async def _ping_loop(self) -> None:
        """Send periodic spec-framed pings to keep the connection alive."""
        while self._connected and self._ws and not self._ws.closed:
            try:
                await asyncio.sleep(self.PING_INTERVAL)
                if self._connected and self._ws and not self._ws.closed:
                    await self._ws.send_bytes(protocol.encode_ping())
                    _LOGGER.debug("Sent ping")
            except asyncio.CancelledError:
                break
            except Exception as err:  # noqa: BLE001 - background task must not
                # die silently on an unexpected error; log and stop cleanly.
                _LOGGER.error("Error in ping loop: %s", err)
                break


class WhiskerWebSocketManager:
    """Manages WebSocket connections for multiple devices."""

    # Reconnect settings
    RECONNECT_MIN_DELAY = 5
    RECONNECT_MAX_DELAY = 300  # 5 minutes max
    RECONNECT_BACKOFF_FACTOR = 2
    # After this many consecutive genuine rejections (a Completion
    # carrying an error, ResultKind 1 — NOT the routine void
    # acknowledgement), back off hard. A real refusal is an account- or
    # station-level problem that retrying quickly cannot fix.
    REJECTION_SLOWDOWN_THRESHOLD = 3
    REJECTED_RECONNECT_DELAY = 1800  # 30 minutes

    def __init__(
        self,
        session: aiohttp.ClientSession,
        on_voltage_update: Callable[[str, VoltageData], None] | None = None,
        publish_interval: float = DEFAULT_PUBLISH_INTERVAL,
    ) -> None:
        """Initialize the manager."""
        self._session = session
        self._on_voltage_update = on_voltage_update
        self.publish_interval = publish_interval
        self._connections: dict[str, WhiskerWebSocket] = {}
        self._voltage_data: dict[str, VoltageData] = {}
        self._last_update_time: dict[str, datetime] = {}  # For staleness checks
        self._last_publish_time: dict[str, datetime] = {}  # For write throttling
        self._credentials: dict[str, dict] = {}  # Store credentials for reconnect
        self._reconnect_tasks: dict[str, asyncio.Task] = {}
        self._reconnect_attempts: dict[str, int] = {}
        self._rejection_counts: dict[str, int] = {}
        self._teardown_tasks: set[asyncio.Task] = set()
        self._shutting_down = False

    def get_voltage_data(self, station_id: str) -> VoltageData | None:
        """Get the latest voltage data for a station."""
        return self._voltage_data.get(station_id)

    def is_data_fresh(
        self, station_id: str, max_age: float = WhiskerWebSocket.STALE_DATA_THRESHOLD
    ) -> bool:
        """Return True if recent voltage data has been received for a station."""
        last = self._last_update_time.get(station_id)
        if last is None:
            return False
        return (dt_util.utcnow() - last).total_seconds() <= max_age

    def _handle_voltage_update(self, station_id: str, data: VoltageData) -> None:
        """Handle a voltage update from a WebSocket connection.

        Every sample updates the in-memory reading and freshness clock;
        the coordinator callback is throttled to ``publish_interval`` so a
        ~4 Hz stream doesn't fan a state write to every entity per sample.
        The first sample after (re)connect always publishes immediately.
        """
        self._voltage_data[station_id] = data
        now = dt_util.utcnow()
        self._last_update_time[station_id] = now
        # Reset reconnect attempts on successful data (not on mere connect —
        # a connect that never yields data must keep escalating its backoff)
        self._reconnect_attempts[station_id] = 0
        self._rejection_counts[station_id] = 0

        last_publish = self._last_publish_time.get(station_id)
        if (
            last_publish is not None
            and (now - last_publish).total_seconds() < self.publish_interval
        ):
            return
        self._last_publish_time[station_id] = now
        _LOGGER.debug(
            "Voltage update for %s: %.2fV (hi: %.2fV, lo: %.2fV)",
            station_id,
            data.voltage,
            data.voltage_hi,
            data.voltage_lo,
        )
        if self._on_voltage_update:
            self._on_voltage_update(station_id, data)

    def _teardown(self, ws: WhiskerWebSocket) -> None:
        """Schedule full teardown of a connection instance (idempotent).

        disconnect() sets the instance's _shutting_down flag (so it can
        never notify again), cancels its ping/receive/stale tasks, and
        closes its socket — nothing can be orphaned with live tasks.
        """
        task = asyncio.create_task(ws.disconnect())
        self._teardown_tasks.add(task)
        task.add_done_callback(self._teardown_tasks.discard)

    def _handle_disconnect(self, station_id: str, ws: WhiskerWebSocket) -> None:
        """Handle a WebSocket disconnect notification (identity-aware)."""
        # Always tear the reporting instance down, even when shutting down
        # or when it is a stale notification from an already-replaced
        # connection — this is what guarantees no socket/task leaks.
        self._teardown(ws)

        if self._shutting_down:
            return
        if self._connections.get(station_id) is not ws:
            # Late notification from a connection that has already been
            # replaced (or removed by disconnect_device): do not touch the
            # current connection and do not schedule another reconnect.
            return

        del self._connections[station_id]
        # Force the next sample after reconnect to publish immediately
        self._last_publish_time.pop(station_id, None)
        if ws.stream_rejected:
            self._rejection_counts[station_id] = (
                self._rejection_counts.get(station_id, 0) + 1
            )

        # Schedule reconnection
        if (
            station_id not in self._reconnect_tasks
            or self._reconnect_tasks[station_id].done()
        ):
            self._reconnect_tasks[station_id] = asyncio.create_task(
                self._reconnect_with_backoff(station_id)
            )

    async def _reconnect_with_backoff(self, station_id: str) -> None:
        """Reconnect to a station with capped exponential backoff.

        Never gives up: the server-side streaming-authorization state has
        been observed to clear after hours, so retries continue at
        RECONNECT_MAX_DELAY intervals indefinitely.
        """
        if station_id not in self._credentials:
            _LOGGER.error(
                "No credentials stored for station %s, cannot reconnect", station_id
            )
            return

        creds = self._credentials[station_id]
        attempts = self._reconnect_attempts.get(station_id, 0)

        # Calculate delay with exponential backoff
        delay = min(
            self.RECONNECT_MIN_DELAY * (self.RECONNECT_BACKOFF_FACTOR**attempts),
            self.RECONNECT_MAX_DELAY,
        )
        # A repeatedly and genuinely refused subscription retries slowly;
        # only error-carrying Completions count, so a healthy stream can
        # never trip this.
        if (
            self._rejection_counts.get(station_id, 0)
            >= self.REJECTION_SLOWDOWN_THRESHOLD
        ):
            delay = max(delay, self.REJECTED_RECONNECT_DELAY)

        _LOGGER.info(
            "Reconnecting to station %s in %.0f seconds (attempt %d)",
            station_id,
            delay,
            attempts + 1,
        )

        await asyncio.sleep(delay)

        if self._shutting_down:
            return

        self._reconnect_attempts[station_id] = attempts + 1

        # Create new connection
        ws = WhiskerWebSocket(
            session=self._session,
            api_key=creds["api_key"],
            user_id=creds["user_id"],
            station_id=station_id,
            on_voltage_update=self._handle_voltage_update,
            on_disconnect=self._handle_disconnect,
        )

        if await ws.connect():
            self._connections[station_id] = ws
            _LOGGER.info("Reconnected to station %s", station_id)
        else:
            _LOGGER.warning(
                "Reconnection failed for station %s, will retry", station_id
            )
            # Schedule another reconnect attempt
            if not self._shutting_down:
                self._reconnect_tasks[station_id] = asyncio.create_task(
                    self._reconnect_with_backoff(station_id)
                )

    async def connect_device(
        self,
        api_key: str,
        user_id: int,
        station_id: str,
    ) -> bool:
        """Connect to a device's WebSocket stream."""
        if station_id in self._connections:
            _LOGGER.debug("Already connected to station %s", station_id)
            return True

        # Store credentials for reconnection
        self._credentials[station_id] = {
            "api_key": api_key,
            "user_id": user_id,
        }
        self._reconnect_attempts[station_id] = 0

        ws = WhiskerWebSocket(
            session=self._session,
            api_key=api_key,
            user_id=user_id,
            station_id=station_id,
            on_voltage_update=self._handle_voltage_update,
            on_disconnect=self._handle_disconnect,
        )

        if await ws.connect():
            self._connections[station_id] = ws
            return True
        return False

    async def disconnect_all(self) -> None:
        """Disconnect all WebSocket connections."""
        self._shutting_down = True

        # Cancel any pending reconnect tasks
        for task in self._reconnect_tasks.values():
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._reconnect_tasks.clear()

        # Disconnect all connections
        for station_id, ws in list(self._connections.items()):
            await ws.disconnect()
            del self._connections[station_id]

        # Await any in-flight instance teardowns so unload leaves nothing
        # running.
        for task in list(self._teardown_tasks):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._teardown_tasks.clear()

    async def disconnect_device(self, station_id: str) -> None:
        """Disconnect a specific device."""
        # Cancel any pending reconnect
        if station_id in self._reconnect_tasks:
            task = self._reconnect_tasks[station_id]
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            del self._reconnect_tasks[station_id]

        # Pop before awaiting so a concurrent late disconnect notification
        # sees the connection as already replaced and cannot double-handle.
        ws = self._connections.pop(station_id, None)
        self._last_publish_time.pop(station_id, None)
        if ws:
            await ws.disconnect()

    async def wait_for_data(self, station_id: str, timeout: float = 5.0) -> bool:  # noqa: ASYNC109
        """Wait for first voltage data from a specific station.

        Returns True if data was received, False on timeout, rejection, or
        no connection. Re-resolves the connection each slice so a
        connection recycled mid-wait doesn't consume the whole timeout.
        """
        # `timeout` is this method's own deadline contract; the per-slice
        # waits below re-resolve the live connection object.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return False
            ws = self._connections.get(station_id)
            if ws is None:
                await asyncio.sleep(min(0.5, remaining))
                continue
            if await ws.wait_for_data(timeout=min(2.0, remaining)):
                return True
            if ws.stream_rejected:
                return False
