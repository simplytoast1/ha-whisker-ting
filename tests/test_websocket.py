"""WebSocket transport tests: framing, decode, auth header, rejection."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import msgpack
import pytest

from custom_components.whisker_ting import protocol
from custom_components.whisker_ting.websocket import WhiskerWebSocket


def _framed(payload) -> bytes:
    body = msgpack.packb(payload, use_bin_type=True)
    return protocol.encode_varint(len(body)) + body


def voltage_frame(v=120.5, peaks=5.0, hi=121.0, lo=119.0) -> bytes:
    """A server voltage invocation, framed the way the real hub sends it."""
    return _framed(
        [
            1,
            {},
            None,
            "updateComboBinaryData",
            [
                {
                    "Voltage": v,
                    "AveragePeaksMax": peaks,
                    "VoltageHi": hi,
                    "VoltageLo": lo,
                }
            ],
            [],
        ]
    )


def completion_frame() -> bytes:
    """The Completion Ting actually sends for InitializeStreaming.

    Captured from the live hub on 2026-08-05:
    ``07 95 03 80 a1 31 03 c0`` = ``[3, {}, "1", 3, None]`` — ResultKind 3
    (non-void) with a null result. It is a success acknowledgement; the
    stream follows on the same socket.
    """
    return _framed([3, {}, "1", 3, None])


def void_completion_frame() -> bytes:
    """A ResultKind 2 (void) Completion — also benign, also not a rejection."""
    return _framed([3, {}, "1", 2, None])


def error_completion_frame(error="not authorized") -> bytes:
    """A ResultKind 1 Completion — a real subscription rejection."""
    return _framed([3, {}, "1", 1, error])


class _Msg:
    def __init__(self, type_, data):
        self.type = type_
        self.data = data


class _FakeWS:
    def __init__(self, frames):
        self._frames = list(frames)
        self.closed = False
        self.sent_bytes = []

    async def send_str(self, _data):
        return

    async def send_bytes(self, data):
        self.sent_bytes.append(data)

    async def close(self):
        self.closed = True

    async def receive(self, timeout=None):  # noqa: ASYNC109 - mirrors aiohttp's
        # ClientWebSocketResponse.receive(timeout=...) signature being mocked.
        if self._frames:
            return self._frames.pop(0)
        await asyncio.sleep(3600)
        return None


def _make(frames):
    ws = _FakeWS(frames)
    session = MagicMock()
    session.ws_connect = AsyncMock(return_value=ws)
    return session, ws


def _client(session, **kwargs):
    defaults = {
        "session": session,
        "api_key": "k",
        "user_id": 1,
        "station_id": "TG-0001",
        "on_voltage_update": lambda sid, data: None,
    }
    defaults.update(kwargs)
    return WhiskerWebSocket(**defaults)


_HANDSHAKE_OK = "{}\x1e"


async def test_connect_sends_api_key_header():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    session, _ws = _make([handshake, _Msg(aiohttp.WSMsgType.BINARY, voltage_frame())])
    client = _client(session, api_key="secret-key", user_id=12345)
    assert await client.connect() is True
    headers = session.ws_connect.call_args.kwargs["headers"]
    assert headers["x-wl-api-key"] == "secret-key"
    await client.disconnect()


async def test_connect_sends_spec_framed_invocation_and_ping():
    """Regression for the reconnect-churn root cause.

    The legacy client sent an unframed ``{1: [...]}`` MessagePack map for
    InitializeStreaming and the keepalive ping; the server dropped every
    such connection (~70 ms after the first ping). Outgoing messages must
    be length-prefixed flat arrays.
    """
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    session, ws = _make([handshake])
    client = _client(session, api_key="secret", user_id=42)
    assert await client.connect() is True

    # Two invocations are sent on connect: the subscription release
    # followed by the subscribe (see
    # test_connect_releases_stale_subscription_before_subscribing).
    assert len(ws.sent_bytes) == 2
    (body,) = list(protocol.iter_binary_frames(ws.sent_bytes[1]))
    message = msgpack.unpackb(body, raw=False, strict_map_key=False)
    assert isinstance(message, list)  # flat array, not a map
    assert len(message) == 6  # six fields incl. trailing stream IDs
    assert message[0] == protocol.MSG_TYPE_INVOCATION
    assert message[3] == "InitializeStreaming"
    assert message[4][0] == {"StationId": "TG-0001", "DataElement": "ComboBinaryData"}
    assert message[4][1] == "secret"
    assert message[4][2] == "42"
    assert message[5] == []

    assert protocol.encode_ping() == b"\x02\x91\x06"
    await client.disconnect()


async def test_connect_rejects_failed_handshake():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, '{"error":"nope"}\x1e')
    session, _ws = _make([handshake])
    client = _client(session)
    assert await client.connect() is False


async def test_decode_voltage():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    frame = _Msg(aiohttp.WSMsgType.BINARY, voltage_frame())
    session, _ws = _make([handshake, frame])
    seen = []
    client = _client(
        session, on_voltage_update=lambda sid, data: seen.append((sid, data))
    )
    assert await client.connect() is True
    assert await client.wait_for_data(timeout=1.0) is True
    await client.disconnect()
    assert seen
    assert seen[0][0] == "TG-0001"
    assert seen[0][1].voltage == 120.5
    assert seen[0][1].voltage_hi == 121.0
    assert seen[0][1].voltage_lo == 119.0
    assert seen[0][1].average_peaks_max == 5.0


async def test_decode_voltage_multiple_messages_per_ws_frame():
    """One WebSocket frame can carry several concatenated hub messages."""
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    combined = _framed([6]) + voltage_frame(v=118.75)
    session, _ws = _make([handshake, _Msg(aiohttp.WSMsgType.BINARY, combined)])
    seen = []
    client = _client(session, on_voltage_update=lambda sid, data: seen.append(data))
    assert await client.connect() is True
    assert await client.wait_for_data(timeout=1.0) is True
    await client.disconnect()
    assert seen[0].voltage == 118.75


async def test_undecodable_frame_does_not_kill_connection():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    garbage = _Msg(aiohttp.WSMsgType.BINARY, b"\xff\xfe\xfd")
    good = _Msg(aiohttp.WSMsgType.BINARY, voltage_frame(v=122.0))
    session, _ws = _make([handshake, garbage, good])
    seen = []
    client = _client(session, on_voltage_update=lambda sid, data: seen.append(data))
    assert await client.connect() is True
    assert await client.wait_for_data(timeout=1.0) is True
    await client.disconnect()
    assert seen[0].voltage == 122.0


@pytest.mark.parametrize(
    "ack_frame",
    [completion_frame, void_completion_frame],
    ids=["resultkind3_null", "resultkind2_void"],
)
async def test_error_free_completion_keeps_connection_open(ack_frame):
    """Regression (3.0.0-3.0.3): an error-free ack must not tear the socket down.

    The voltage stream arrives AFTER this acknowledgement on the same
    connection; hanging up on it made data delivery impossible. Both
    ResultKind 3-with-null (what Ting actually sends) and ResultKind 2
    (void) must be treated as success. Deploying adamjthompson/whisker_ting
    v1.1.0 against the live hub on 2026-08-05 showed the opposite handling
    give up on all four station-id candidates in 1.8 s.
    """
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    ack = _Msg(aiohttp.WSMsgType.BINARY, ack_frame())
    good = _Msg(aiohttp.WSMsgType.BINARY, voltage_frame(v=121.5))
    session, _ws = _make([handshake, ack, good])
    seen = []
    client = _client(session, on_voltage_update=lambda sid, d: seen.append(d))
    assert await client.connect() is True
    assert await client.wait_for_data(timeout=1.0) is True
    assert client.connected is True
    assert client.stream_rejected is False
    assert seen[0].voltage == 121.5
    await client.disconnect()


async def test_rejection_fast_fail():
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    rej = _Msg(aiohttp.WSMsgType.BINARY, error_completion_frame())
    session, _ws = _make([handshake, rej])
    client = _client(session)
    assert await client.connect() is True
    assert await client.wait_for_data(timeout=2.0) is False
    assert client.stream_rejected is True
    await client.disconnect()


async def test_connect_releases_stale_subscription_before_subscribing():
    """UnInitializeStreaming must precede InitializeStreaming.

    A subscription the server still holds for the station makes it
    acknowledge a new InitializeStreaming and then never stream to it.
    Verified live: subscribe-only got 0 samples in 90 s; releasing first
    delivered voltage in ~4 s under identical conditions.
    """
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    ack = _Msg(aiohttp.WSMsgType.BINARY, completion_frame())
    session, ws = _make([handshake, ack])
    client = _client(session, api_key="secret", user_id=42)
    assert await client.connect() is True

    targets = []
    for raw in ws.sent_bytes:
        for body in protocol.iter_binary_frames(raw):
            m = msgpack.unpackb(body, raw=False, strict_map_key=False)
            if isinstance(m, list) and len(m) >= 4 and isinstance(m[3], str):
                targets.append(m[3])
    assert targets[:2] == ["UnInitializeStreaming", "InitializeStreaming"]
    await client.disconnect()


async def test_disconnect_releases_the_subscription():
    """Dropping without teardown leaks a registration that blocks retries."""
    handshake = _Msg(aiohttp.WSMsgType.TEXT, _HANDSHAKE_OK)
    ack = _Msg(aiohttp.WSMsgType.BINARY, completion_frame())
    session, ws = _make([handshake, ack])
    client = _client(session)
    assert await client.connect() is True
    before = len(ws.sent_bytes)
    await client.disconnect()

    targets = []
    for raw in ws.sent_bytes[before:]:
        for body in protocol.iter_binary_frames(raw):
            m = msgpack.unpackb(body, raw=False, strict_map_key=False)
            if isinstance(m, list) and len(m) >= 4 and isinstance(m[3], str):
                targets.append(m[3])
    assert "UnInitializeStreaming" in targets
