"""SignalR MessagePack wire protocol for the Whisker Ting hub.

This module is the single source of truth for bytes on the wire. Every
message sent to (or parsed from) ``wss://signalr.api.wskr.io/dataHub``
goes through here.

Why this exists: the original integration encoded outgoing hub messages as
a bare ``{1: [...]}`` MessagePack map with no length prefix. ASP.NET Core
SignalR requires every binary hub message to be a **flat array** prefixed
with a 7-bit VarInt byte length. The malformed constant-byte ping killed
the connection ~70 ms after it was sent, every 15 seconds, for every user;
whether the malformed ``InitializeStreaming`` accidentally still produced
a usable subscription depended on the byte length of each account's
credentials (see simplytoast1/ha-whisker-ting#1 for the field diagnosis).

Consolidated from three independent fixes:
- fourmajor/ha-whisker-ting (Stu Chuang Matthews, MIT): VarInt framing,
  six-field Invocation encoding, framed Ping, hub-message decoding, and
  named-field voltage decode.
- adamjthompson/whisker_ting (Adam Thompson, MIT): nested binary-blob
  payload search and tolerant per-field decoding, informed by a Charles
  Proxy capture of the official Ting app.
- The debugging in simplytoast1/ha-whisker-ting#1 (calasanzio's
  ping-timing capture, mbedworth's credential analysis, marccatalano's
  server-response writeup).

Two further behaviours of Ting's hub, established empirically against the
live service and cross-checked against the official app's bundle:

- ``InitializeStreaming`` is a blocking invocation, so the server answers
  it with a Completion. Observed on the wire (2026-08-05), that frame is
  ``07 95 03 80 a1 31 03 c0`` = ``[3, {}, "1", 3, None]`` — ResultKind 3
  (non-void) carrying a ``null`` result, NOT ResultKind 2 (void). Either
  way it is a SUCCESS acknowledgement: voltage arrives afterwards as
  separate server-to-client invocations. Only ``ResultKind 1`` carries an
  error. See :func:`completion_message` / :func:`completion_error`.
- The hub holds one subscription per station and does not release it
  implicitly when a connection drops. A leaked registration makes every
  later subscribe for that station return the same void acknowledgement
  and deliver nothing. Clients must call ``UnInitializeStreaming`` before
  subscribing and on teardown; the official app always pairs them
  (``invokeStreamingMethod`` / ``unInvokeStreamingMethod``).

Spec: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import math
from typing import TYPE_CHECKING, Any

import msgpack

if TYPE_CHECKING:
    from collections.abc import Iterable

# SignalR MessagePack hub message types
MSG_TYPE_INVOCATION = 1
MSG_TYPE_STREAM_ITEM = 2
MSG_TYPE_COMPLETION = 3
MSG_TYPE_STREAM_INVOCATION = 4
MSG_TYPE_CANCEL_INVOCATION = 5
MSG_TYPE_PING = 6
MSG_TYPE_CLOSE = 7

# SignalR limits the length prefix to 5 VarInt bytes (max 2 GB); we cap far
# lower because hub messages on this stream are tiny.
MAX_LENGTH_PREFIX_BYTES = 5
MAX_MESSAGE_SIZE = 1 << 27  # 128 MiB, defensive bound

# The hub invocation Ting's server sends for live voltage samples.
VOLTAGE_TARGET = "updatecombobinarydata"

# Plausibility bounds for a mains voltage reading; readings outside are
# discarded as decode artifacts (see the ~750 V misreads in
# simplytoast1/ha-whisker-ting#1).
VOLTAGE_MIN_ABS = 1.0
VOLTAGE_MAX_ABS = 1000.0


class SignalRProtocolError(Exception):
    """A SignalR transport payload violated the binary framing protocol."""


@dataclass
class VoltageData:
    """One decoded real-time voltage sample."""

    timestamp: datetime
    voltage: float
    voltage_hi: float
    voltage_lo: float
    average_peaks_max: float


def encode_varint(value: int) -> bytes:
    """Encode a message length as a SignalR 7-bit VarInt."""
    if value < 0 or value > MAX_MESSAGE_SIZE:
        raise SignalRProtocolError(
            f"message length must be between 0 and {MAX_MESSAGE_SIZE}"
        )
    encoded = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            part |= 0x80
        encoded.append(part)
        if not value:
            return bytes(encoded)


def frame_messagepack(payload: Any) -> bytes:
    """MessagePack-encode and length-prefix one SignalR hub message."""
    body = msgpack.packb(payload, use_bin_type=True)
    return encode_varint(len(body)) + body


def encode_invocation(
    invocation_id: str | None,
    target: str,
    arguments: list[Any],
) -> bytes:
    """Encode a SignalR Invocation message.

    SignalR MessagePack v1 requires six fields — including the trailing
    stream-IDs array — even when the invocation carries no client streams.
    """
    return frame_messagepack(
        [
            MSG_TYPE_INVOCATION,
            {},  # headers
            invocation_id,
            target,
            arguments,
            [],  # stream IDs
        ]
    )


def encode_ping() -> bytes:
    """Encode a SignalR Ping message (a length-prefixed flat array [6])."""
    return frame_messagepack([MSG_TYPE_PING])


def iter_binary_frames(data: bytes) -> Iterable[bytes]:
    """Yield MessagePack bodies from one SignalR binary transport payload.

    A single WebSocket frame may carry several concatenated hub messages,
    each preceded by its own VarInt length prefix.
    """
    offset = 0
    total = len(data)
    while offset < total:
        length = 0
        shift = 0
        for _ in range(MAX_LENGTH_PREFIX_BYTES):
            if offset >= total:
                raise SignalRProtocolError("incomplete SignalR length prefix")
            part = data[offset]
            offset += 1
            length |= (part & 0x7F) << shift
            if not part & 0x80:
                break
            shift += 7
        else:
            raise SignalRProtocolError("SignalR length prefix exceeds five bytes")

        end = offset + length
        if length <= 0 or end > total:
            raise SignalRProtocolError(
                f"incomplete SignalR frame: declared={length}, "
                f"available={total - offset}"
            )
        yield data[offset:end]
        offset = end


def decode_hub_messages(data: bytes) -> list[list[Any]]:
    """Decode every SignalR MessagePack hub message in a transport payload."""
    messages: list[list[Any]] = []
    for frame in iter_binary_frames(data):
        try:
            message = msgpack.unpackb(
                frame,
                raw=False,
                strict_map_key=False,
                timestamp=3,  # decode msgpack Timestamp ext as datetime
            )
        except (ValueError, msgpack.UnpackException) as err:
            raise SignalRProtocolError(f"invalid MessagePack payload: {err}") from err
        if not isinstance(message, list) or not message:
            raise SignalRProtocolError("SignalR hub message must be a non-empty array")
        messages.append(message)
    return messages


def _find_voltage_payload(obj: Any, depth: int = 0) -> dict | None:
    """Find the ComboBinaryData dict inside decoded invocation arguments.

    The arguments list can carry the payload dict directly, or a raw
    ``bytes`` value that is itself a nested MessagePack-encoded blob
    (hence "Combo *Binary* Data"), so bytes values are unpacked and
    searched recursively.
    """
    if depth > 4:
        return None
    if isinstance(obj, dict):
        if "Voltage" in obj:
            return obj
        for item in obj.values():
            found = _find_voltage_payload(item, depth + 1)
            if found is not None:
                return found
        return None
    if isinstance(obj, (bytes, bytearray)):
        try:
            nested = msgpack.unpackb(
                bytes(obj), raw=False, strict_map_key=False, timestamp=3
            )
        except (ValueError, msgpack.UnpackException):
            return None
        return _find_voltage_payload(nested, depth + 1)
    if isinstance(obj, (list, tuple)):
        for item in obj:
            found = _find_voltage_payload(item, depth + 1)
            if found is not None:
                return found
    return None


def decode_voltage_update(message: list[Any]) -> VoltageData | None:
    """Decode Ting's updateComboBinaryData client invocation.

    Reads named fields from the payload dict rather than scanning bytes for
    float64 markers — a raw scan can misread unrelated fields (target name,
    headers, timestamp, counters) as voltage readings, producing spurious
    ~200-750 V spikes. ``Voltage`` is required; the remaining fields fall
    back to safe defaults so a partial payload still yields a reading.
    """
    if (
        len(message) < 5
        or message[0] != MSG_TYPE_INVOCATION
        or not isinstance(message[3], str)
        or message[3].casefold() != VOLTAGE_TARGET
    ):
        return None

    payload = _find_voltage_payload(message[4])
    if payload is None:
        return None

    try:
        voltage = _finite_float(payload["Voltage"])
    except (KeyError, TypeError, ValueError):
        return None

    if not VOLTAGE_MIN_ABS <= abs(voltage) <= VOLTAGE_MAX_ABS:
        return None

    def _field(key: str, default: float) -> float:
        try:
            return _finite_float(payload[key])
        except (KeyError, TypeError, ValueError):
            return default

    return VoltageData(
        timestamp=_decode_timestamp(payload.get("DataTimeUtc")),
        voltage=voltage,
        voltage_hi=_field("VoltageHi", voltage),
        voltage_lo=_field("VoltageLo", voltage),
        average_peaks_max=_field("AveragePeaksMax", 0.0),
    )


def completion_message(message: list[Any]) -> bool:
    """Return True if the hub message is a Completion (message type 3).

    A Completion acknowledges a blocking invocation. Ting sends one for
    every ``InitializeStreaming`` call and the voltage stream follows on
    the same connection afterwards, so a Completion is NOT by itself a
    failure. The observed frame is ResultKind 3 (non-void) with a
    ``null`` result; ResultKind 2 (void) is equally benign. Only
    ``ResultKind 1`` carries an error and means the subscription was
    refused. Callers must use :func:`completion_error` to tell them apart
    before treating a Completion as a failure.
    """
    return bool(message) and message[0] == MSG_TYPE_COMPLETION


def completion_error(message: list[Any]) -> str | None:
    """Return the error text from a Completion message, if present.

    Completion layout: [3, headers, invocationId, resultKind, result?]
    where resultKind 1 = error (result is the error string),
    2 = void, 3 = non-void result.
    """
    if len(message) >= 5 and message[0] == MSG_TYPE_COMPLETION and message[3] == 1:
        return str(message[4])
    return None


def close_error(message: list[Any]) -> str | None:
    """Return the error text from a Close message, if present."""
    if len(message) >= 2 and message[0] == MSG_TYPE_CLOSE and message[1]:
        return str(message[1])
    return None


def _finite_float(value: Any) -> float:
    """Convert a numeric value to a finite float."""
    if isinstance(value, bool):  # bools are ints; never a voltage
        raise ValueError("boolean is not a voltage value")  # noqa: TRY004 - callers catch ValueError uniformly
    converted = float(value)
    if not math.isfinite(converted):
        raise ValueError("value is not finite")
    return converted


def _decode_timestamp(value: Any) -> datetime:
    """Normalize MessagePack, ISO-8601, or missing timestamps to aware UTC."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, msgpack.Timestamp):
        return value.to_datetime().astimezone(UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        else:
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
    return datetime.now(UTC)
