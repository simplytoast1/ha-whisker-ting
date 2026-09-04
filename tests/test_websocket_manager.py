"""Manager lifecycle tests: throttle, identity-aware disconnect, backoff.

These cover the field-verified requirements: publish throttling, the
single-notifier/identity-aware disconnect handling that prevents a late
notification from tearing down a healthy replacement connection, the
never-give-up capped backoff, and the ping/stale/close runtime paths.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import aiohttp

from custom_components.whisker_ting import protocol
from custom_components.whisker_ting.websocket import (
    VoltageData,
    WhiskerWebSocket,
    WhiskerWebSocketManager,
)
from homeassistant.util import dt as dt_util

from .test_websocket import _HANDSHAKE_OK, _make, _Msg, error_completion_frame


def _sample(v=120.0):
    return VoltageData(
        timestamp=dt_util.utcnow(),
        voltage=v,
        voltage_hi=v + 2,
        voltage_lo=v - 2,
        average_peaks_max=1.0,
    )


# ---------------------------------------------------------------------------
# Publish throttle
# ---------------------------------------------------------------------------


async def test_publish_throttle_first_sample_immediate_then_throttled():
    published = []
    manager = WhiskerWebSocketManager(
        session=MagicMock(),
        on_voltage_update=lambda sid, d: published.append(d.voltage),
        publish_interval=3600.0,  # nothing but the first sample may publish
    )
    manager._handle_voltage_update("TG-0001", _sample(120.0))
    manager._handle_voltage_update("TG-0001", _sample(121.0))
    manager._handle_voltage_update("TG-0001", _sample(122.0))
    assert published == [120.0]  # first publishes immediately, rest throttled
    # ...but the in-memory reading and freshness always track the latest
    assert manager.get_voltage_data("TG-0001").voltage == 122.0
    assert manager.is_data_fresh("TG-0001") is True


async def test_publish_interval_zero_publishes_every_sample():
    published = []
    manager = WhiskerWebSocketManager(
        session=MagicMock(),
        on_voltage_update=lambda sid, d: published.append(d.voltage),
        publish_interval=0.0,
    )
    manager._handle_voltage_update("TG-0001", _sample(120.0))
    manager._handle_voltage_update("TG-0001", _sample(121.0))
    assert published == [120.0, 121.0]


async def test_data_resets_reconnect_attempts():
    manager = WhiskerWebSocketManager(session=MagicMock())
    manager._reconnect_attempts["TG-0001"] = 7
    manager._handle_voltage_update("TG-0001", _sample())
    assert manager._reconnect_attempts["TG-0001"] == 0


# ---------------------------------------------------------------------------
# Identity-aware disconnect handling
# ---------------------------------------------------------------------------


def _fake_conn():
    ws = MagicMock(spec=WhiskerWebSocket)
    ws.disconnect = AsyncMock()
    return ws


async def test_late_disconnect_from_replaced_connection_is_ignored():
    """A stale notification must not tear down the healthy replacement."""
    manager = WhiskerWebSocketManager(session=MagicMock())
    manager.RECONNECT_MIN_DELAY = 0
    old, new = _fake_conn(), _fake_conn()
    manager._connections["TG-0001"] = new

    manager._handle_disconnect("TG-0001", old)  # late notify from old conn
    await asyncio.sleep(0)

    # The healthy replacement stays registered; no reconnect scheduled
    assert manager._connections["TG-0001"] is new
    assert "TG-0001" not in manager._reconnect_tasks
    # ...and the reporting instance was torn down regardless
    for task in list(manager._teardown_tasks):
        await task
    old.disconnect.assert_awaited()
    new.disconnect.assert_not_awaited()


async def test_current_disconnect_schedules_reconnect_and_teardown():
    manager = WhiskerWebSocketManager(session=MagicMock())
    current = _fake_conn()
    manager._connections["TG-0001"] = current
    manager._credentials["TG-0001"] = {"api_key": "k", "user_id": 1}
    # Keep the backoff sleeping so we can observe the scheduled task
    manager._reconnect_attempts["TG-0001"] = 3

    manager._handle_disconnect("TG-0001", current)

    assert "TG-0001" not in manager._connections
    assert "TG-0001" in manager._reconnect_tasks
    for task in list(manager._teardown_tasks):
        await task
    current.disconnect.assert_awaited()
    # Cancel the pending backoff task to end the test cleanly
    manager._reconnect_tasks["TG-0001"].cancel()


async def test_disconnect_all_awaits_teardowns():
    manager = WhiskerWebSocketManager(session=MagicMock())
    conn = _fake_conn()
    manager._connections["TG-0001"] = conn
    stray = _fake_conn()
    manager._teardown(stray)

    await manager.disconnect_all()

    conn.disconnect.assert_awaited()
    stray.disconnect.assert_awaited()
    assert not manager._connections
    assert not manager._teardown_tasks


# ---------------------------------------------------------------------------
# Never-give-up capped backoff
# ---------------------------------------------------------------------------


async def test_backoff_caps_and_never_gives_up(monkeypatch):
    """High attempt counts must keep retrying at the capped delay."""
    manager = WhiskerWebSocketManager(session=MagicMock())
    manager._credentials["TG-0001"] = {"api_key": "k", "user_id": 1}
    manager._reconnect_attempts["TG-0001"] = 50  # way past any give-up bound

    delays = []

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    connected = []

    class _FakeSocket:
        def __init__(self, **kwargs):
            connected.append(kwargs["station_id"])

        async def connect(self):
            return True

    monkeypatch.setattr(
        "custom_components.whisker_ting.websocket.WhiskerWebSocket", _FakeSocket
    )

    await manager._reconnect_with_backoff("TG-0001")

    assert delays == [manager.RECONNECT_MAX_DELAY]  # capped, not given up
    assert connected == ["TG-0001"]
    assert isinstance(manager._connections["TG-0001"], _FakeSocket)


# ---------------------------------------------------------------------------
# Runtime paths: ping loop, server Close, stale/grace recycle
# ---------------------------------------------------------------------------


async def test_ping_loop_sends_spec_framed_ping(monkeypatch):
    monkeypatch.setattr(WhiskerWebSocket, "PING_INTERVAL", 0.01)
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    session, ws = _make([handshake])
    client = WhiskerWebSocket(
        session=session, api_key="k", user_id=1, station_id="TG-0001"
    )
    assert await client.connect() is True
    await asyncio.sleep(0.05)
    await client.disconnect()
    # sent_bytes[0] is InitializeStreaming; pings follow, spec-framed
    assert b"\x02\x91\x06" in ws.sent_bytes[1:]


async def test_server_close_message_triggers_single_disconnect_notify():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    close_frame = protocol.frame_messagepack([protocol.MSG_TYPE_CLOSE, "bye", False])
    session, _ws = _make([handshake, _Msg(aiohttp.WSMsgType.BINARY, close_frame)])
    notifies = []
    client = WhiskerWebSocket(
        session=session,
        api_key="k",
        user_id=1,
        station_id="TG-0001",
        on_disconnect=lambda sid, ws: notifies.append(sid),
    )
    assert await client.connect() is True
    await asyncio.sleep(0.05)
    assert client.connected is False
    assert notifies == ["TG-0001"]
    await client.disconnect()


async def test_rejection_tears_connection_down_with_single_notify():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    session, _ws = _make(
        [handshake, _Msg(aiohttp.WSMsgType.BINARY, error_completion_frame())]
    )
    notifies = []
    client = WhiskerWebSocket(
        session=session,
        api_key="k",
        user_id=1,
        station_id="TG-0001",
        on_disconnect=lambda sid, ws: notifies.append(sid),
    )
    assert await client.connect() is True
    assert await client.wait_for_data(timeout=1.0) is False
    await asyncio.sleep(0.05)
    assert client.stream_rejected is True
    assert client.connected is False
    assert notifies == ["TG-0001"]
    await client.disconnect()


async def test_grace_recycle_closes_socket_and_notifies_once(monkeypatch):
    """A silent subscription recycles via socket close: exactly one notify."""
    monkeypatch.setattr(WhiskerWebSocket, "STALE_DATA_THRESHOLD", 0.02)
    monkeypatch.setattr(WhiskerWebSocket, "FIRST_DATA_GRACE", 0.01)
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    session, ws = _make([handshake])  # never sends data

    # When the stale loop closes the socket, the parked receive() must
    # observe CLOSED (mirrors aiohttp behavior).
    orig_close = ws.close
    closed_event = asyncio.Event()

    async def close_and_wake():
        await orig_close()
        closed_event.set()

    ws.close = close_and_wake

    async def receive(timeout=None):  # noqa: ASYNC109 - mirrors mocked signature
        if ws._frames:
            return ws._frames.pop(0)
        await closed_event.wait()
        return _Msg(aiohttp.WSMsgType.CLOSED, None)

    ws.receive = receive

    notifies = []
    client = WhiskerWebSocket(
        session=session,
        api_key="k",
        user_id=1,
        station_id="TG-0001",
        on_disconnect=lambda sid, w: notifies.append(sid),
    )
    assert await client.connect() is True
    await asyncio.sleep(0.2)
    assert ws.closed is True
    assert notifies == ["TG-0001"]  # exactly one notification
    await client.disconnect()


async def test_repeated_rejections_slow_the_backoff(monkeypatch):
    """Three consecutive rejections widen the retry to the slow cadence."""
    manager = WhiskerWebSocketManager(session=MagicMock())
    manager._credentials["TG-0001"] = {"api_key": "k", "user_id": 1}

    for _ in range(manager.REJECTION_SLOWDOWN_THRESHOLD):
        rejected = _fake_conn()
        rejected.stream_rejected = True
        manager._connections["TG-0001"] = rejected
        manager._handle_disconnect("TG-0001", rejected)
        task = manager._reconnect_tasks.pop("TG-0001")
        task.cancel()
        for t in list(manager._teardown_tasks):
            await t

    delays = []

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    class _FakeSocket:
        def __init__(self, **kwargs):
            pass

        async def connect(self):
            return True

    monkeypatch.setattr(
        "custom_components.whisker_ting.websocket.WhiskerWebSocket", _FakeSocket
    )
    await manager._reconnect_with_backoff("TG-0001")
    assert delays == [manager.REJECTED_RECONNECT_DELAY]

    # ...and received data resets the slowdown
    manager._handle_voltage_update("TG-0001", _sample())
    assert manager._rejection_counts["TG-0001"] == 0


async def test_ping_cadence_matches_the_app():
    """The 3 s keepalive is load-bearing, not cosmetic.

    With a 15 s cadence the hub acknowledges the subscription but never
    streams; at 3 s (the official app's keepAliveIntervalInMilliseconds)
    voltage flows at 4 Hz. Verified by simultaneous A/B against the live
    hub on 2026-08-05.
    """
    assert WhiskerWebSocket.PING_INTERVAL == 3
