"""Tests for dsquic.transport_parameters."""

from dsquic.buffer import encode_varint
from dsquic.transport_parameters import (
    TransportParameters,
    decode_transport_parameters,
)


def test_roundtrip() -> None:
    parameters = TransportParameters(
        initial_source_connection_id=b"\x01\x02\x03\x04",
        max_idle_timeout_ms=30_000,
        initial_max_data=1_000_000,
        initial_max_stream_data_bidi_local=262_144,
        initial_max_streams_bidi=8,
        max_datagram_frame_size=65535,
    )
    decoded = decode_transport_parameters(parameters.encode())
    assert decoded.initial_source_connection_id == b"\x01\x02\x03\x04"
    assert decoded.max_idle_timeout_ms == 30_000
    assert decoded.initial_max_data == 1_000_000
    assert decoded.initial_max_stream_data_bidi_local == 262_144
    assert decoded.initial_max_streams_bidi == 8
    assert decoded.max_datagram_frame_size == 65535


def test_defaults_applied_when_absent() -> None:
    decoded = decode_transport_parameters(b"")
    assert decoded.ack_delay_exponent == 3  # §18.2
    assert decoded.max_ack_delay_ms == 25
    assert decoded.active_connection_id_limit == 2
    assert decoded.max_datagram_frame_size is None


def test_original_destination_connection_id_roundtrip() -> None:
    parameters = TransportParameters(original_destination_connection_id=b"\xaa" * 8)
    decoded = decode_transport_parameters(parameters.encode())
    assert decoded.original_destination_connection_id == b"\xaa" * 8


def test_unknown_and_greased_parameters_ignored() -> None:
    # §18.1: reserved parameters of the form 31N+27 must be ignored.
    greased = encode_varint(31 * 7 + 27) + encode_varint(2) + b"\xff\xff"
    unknown = encode_varint(0x7FFF) + encode_varint(1) + b"\x01"
    decoded = decode_transport_parameters(
        TransportParameters(initial_max_data=42).encode() + greased + unknown
    )
    assert decoded.initial_max_data == 42
