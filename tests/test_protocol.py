"""Tests for the SignalR MessagePack wire protocol layer."""

from datetime import UTC, datetime

import msgpack
import pytest

from custom_components.whisker_ting import protocol


def _framed(payload) -> bytes:
    body = msgpack.packb(payload, use_bin_type=True)
    return protocol.encode_varint(len(body)) + body


def _voltage_message(payload_dict, target="updateComboBinaryData"):
    return [1, {}, None, target, [payload_dict], []]


# ---------------------------------------------------------------------------
# VarInt framing
# ---------------------------------------------------------------------------


def test_encode_varint_single_byte():
    assert protocol.encode_varint(0) == b"\x00"
    assert protocol.encode_varint(0x7F) == b"\x7f"


def test_encode_varint_multi_byte():
    assert protocol.encode_varint(0x80) == b"\x80\x01"
    assert protocol.encode_varint(300) == b"\xac\x02"


def test_encode_varint_rejects_negative_and_oversize():
    with pytest.raises(protocol.SignalRProtocolError):
        protocol.encode_varint(-1)
    with pytest.raises(protocol.SignalRProtocolError):
        protocol.encode_varint(protocol.MAX_MESSAGE_SIZE + 1)


def test_iter_binary_frames_roundtrip_multiple_messages():
    one = msgpack.packb([6])
    two = msgpack.packb([3, {}, "1", 2, None])
    payload = (
        protocol.encode_varint(len(one)) + one + protocol.encode_varint(len(two)) + two
    )
    assert list(protocol.iter_binary_frames(payload)) == [one, two]


def test_iter_binary_frames_incomplete_frame_raises():
    with pytest.raises(protocol.SignalRProtocolError):
        list(protocol.iter_binary_frames(b"\x05\x91"))  # declares 5, has 1


def test_iter_binary_frames_truncated_prefix_raises():
    with pytest.raises(protocol.SignalRProtocolError):
        list(protocol.iter_binary_frames(b"\x80"))  # continuation bit, no more bytes


def test_decode_hub_messages_rejects_non_array():
    frame = msgpack.packb({1: [6]}, use_bin_type=True)
    payload = protocol.encode_varint(len(frame)) + frame
    with pytest.raises(protocol.SignalRProtocolError):
        protocol.decode_hub_messages(payload)


# ---------------------------------------------------------------------------
# Outgoing messages (the framing whose absence caused the reconnect churn)
# ---------------------------------------------------------------------------


def test_encode_ping_golden_bytes():
    # Length-prefixed flat array [6]: varint(2) + 0x91 0x06
    assert protocol.encode_ping() == b"\x02\x91\x06"


def test_encode_invocation_is_framed_six_field_array():
    raw = protocol.encode_invocation("1", "InitializeStreaming", ["arg"])
    frames = list(protocol.iter_binary_frames(raw))
    assert len(frames) == 1
    message = msgpack.unpackb(frames[0], raw=False, strict_map_key=False)
    assert message == [1, {}, "1", "InitializeStreaming", ["arg"], []]


def test_encode_invocation_never_bare_map():
    """Regression: the legacy encoding was an unframed {1: [...]} map."""
    raw = protocol.encode_invocation("7", "InitializeStreaming", [])
    # First byte must be a VarInt length, and the body must be an array
    # (msgpack array markers are 0x9X / 0xdc / 0xdd, never a fixmap 0x8X).
    body = next(iter(protocol.iter_binary_frames(raw)))
    assert body[0] & 0xF0 in (0x90, 0xD0) or body[0] in (0xDC, 0xDD)


# ---------------------------------------------------------------------------
# Voltage decoding (named fields — never positional, never raw byte scans)
# ---------------------------------------------------------------------------


def test_decode_voltage_update_named_fields():
    ts = datetime(2026, 7, 27, 12, 0, 0, tzinfo=UTC)
    message = _voltage_message(
        {
            "DataTimeUtc": ts,
            "Voltage": 120.25,
            "VoltageHi": 124.66,
            "VoltageLo": 114.91,
            "AveragePeaksMax": 8.0,
        }
    )
    update = protocol.decode_voltage_update(message)
    assert update == protocol.VoltageData(
        timestamp=ts,
        voltage=120.25,
        voltage_hi=124.66,
        voltage_lo=114.91,
        average_peaks_max=8.0,
    )


def test_decode_voltage_update_key_order_independent():
    """Field order on the wire must not matter (positional decode regression)."""
    message = _voltage_message(
        {
            "VoltageLo": 114.91,
            "AveragePeaksMax": 8.0,
            "Voltage": 120.25,
            "VoltageHi": 124.66,
        }
    )
    update = protocol.decode_voltage_update(message)
    assert update.voltage == 120.25
    assert update.voltage_hi == 124.66
    assert update.voltage_lo == 114.91
    assert update.average_peaks_max == 8.0


def test_decode_voltage_update_integer_peaks():
    """An integral AveragePeaksMax must decode, not be dropped."""
    message = _voltage_message(
        {"Voltage": 120.0, "VoltageHi": 124.0, "VoltageLo": 115.0, "AveragePeaksMax": 8}
    )
    update = protocol.decode_voltage_update(message)
    assert update.average_peaks_max == 8.0


def test_decode_voltage_update_nested_binary_blob():
    """The payload dict may arrive as a nested MessagePack bytes blob."""
    blob = msgpack.packb(
        {
            "Voltage": 119.5,
            "VoltageHi": 123.0,
            "VoltageLo": 116.0,
            "AveragePeaksMax": 4.0,
        },
        use_bin_type=True,
    )
    message = [1, {}, None, "updateComboBinaryData", [blob], []]
    update = protocol.decode_voltage_update(message)
    assert update is not None
    assert update.voltage == 119.5
    assert update.voltage_lo == 116.0


def test_decode_voltage_update_missing_optional_fields_default():
    message = _voltage_message({"Voltage": 121.0})
    update = protocol.decode_voltage_update(message)
    assert update.voltage == 121.0
    assert update.voltage_hi == 121.0
    assert update.voltage_lo == 121.0
    assert update.average_peaks_max == 0.0


def test_decode_voltage_update_missing_voltage_returns_none():
    message = _voltage_message({"VoltageHi": 124.0, "VoltageLo": 115.0})
    assert protocol.decode_voltage_update(message) is None


@pytest.mark.parametrize("bad", [0, 0.5, 1500.0, float("nan"), float("inf"), True])
def test_decode_voltage_update_rejects_implausible_voltage(bad):
    message = _voltage_message(
        {"Voltage": bad, "VoltageHi": 124.0, "VoltageLo": 115.0, "AveragePeaksMax": 1}
    )
    assert protocol.decode_voltage_update(message) is None


def test_decode_voltage_update_wrong_target_returns_none():
    message = _voltage_message({"Voltage": 120.0}, target="someOtherMethod")
    assert protocol.decode_voltage_update(message) is None


def test_decode_voltage_update_target_case_insensitive():
    message = _voltage_message({"Voltage": 120.0}, target="UpdateComboBinaryData")
    assert protocol.decode_voltage_update(message) is not None


def test_decode_voltage_update_non_invocation_returns_none():
    assert protocol.decode_voltage_update([6]) is None
    assert protocol.decode_voltage_update([3, {}, "1", 2, None]) is None


def test_decode_voltage_update_via_hub_messages_msgpack_timestamp():
    ts = datetime(2026, 8, 1, 3, 4, 5, tzinfo=UTC)
    frame = _framed(
        [
            1,
            {},
            None,
            "updateComboBinaryData",
            [
                {
                    "DataTimeUtc": msgpack.Timestamp.from_datetime(ts),
                    "Voltage": 120.25,
                    "VoltageHi": 124.66,
                    "VoltageLo": 114.91,
                    "AveragePeaksMax": 8.0,
                }
            ],
            [],
        ]
    )
    (message,) = protocol.decode_hub_messages(frame)
    update = protocol.decode_voltage_update(message)
    assert update.timestamp == ts


def test_decode_timestamp_variants():
    iso = protocol._decode_timestamp("2026-08-01T03:04:05Z")
    assert iso == datetime(2026, 8, 1, 3, 4, 5, tzinfo=UTC)
    naive = protocol._decode_timestamp(datetime(2026, 8, 1, 3, 4, 5))  # noqa: DTZ001 - naive on purpose
    assert naive.tzinfo == UTC
    fallback = protocol._decode_timestamp(None)
    assert fallback.tzinfo is not None
    garbage = protocol._decode_timestamp("not-a-date")
    assert garbage.tzinfo is not None


# ---------------------------------------------------------------------------
# Completion / Close semantics
# ---------------------------------------------------------------------------


def test_completion_message_detection():
    assert protocol.completion_message([3, {}, "1", 2, None]) is True
    assert protocol.completion_message([1, {}, "1", "x", [], []]) is False
    assert protocol.completion_message([]) is False


def test_completion_error_extraction():
    error = protocol.completion_error([3, {}, "1", 1, "server exploded"])
    assert error == "server exploded"
    assert protocol.completion_error([3, {}, "1", 2, None]) is None
    assert protocol.completion_error([3, {}, "1", 3, 42]) is None


def test_close_error_extraction():
    assert protocol.close_error([7, "going away"]) == "going away"
    assert protocol.close_error([7, None]) is None
    assert protocol.close_error([6]) is None
