"""Tests for dsquic.packet."""

import pytest

from dsquic.buffer import BufferReadError
from dsquic.packet import (
    QUIC_V1,
    HeaderParseError,
    LongHeaderTemplate,
    PacketType,
    UnsupportedVersion,
    build_long_header,
    decode_packet_number,
    encode_packet_number,
    parse_long_header,
    parse_short_header,
)

CLIENT_DCID = bytes.fromhex("8394c8f03e515708")
SERVER_SCID = bytes.fromhex("f067a5502a4262b5")

CLIENT_INITIAL_HEADER = bytes.fromhex("c300000001088394c8f03e5157080000449e00000002")
SERVER_INITIAL_HEADER = bytes.fromhex("c1000000010008f067a5502a4262b50040750001")


def test_build_client_initial_header() -> None:
    template = LongHeaderTemplate(
        packet_type=PacketType.INITIAL,
        version=QUIC_V1,
        destination_cid=CLIENT_DCID,
        source_cid=b"",
    )
    header = build_long_header(
        template, payload_length=1178, packet_number=2, packet_number_length=4
    )
    assert header == CLIENT_INITIAL_HEADER


def test_build_server_initial_header() -> None:
    template = LongHeaderTemplate(
        packet_type=PacketType.INITIAL,
        version=QUIC_V1,
        destination_cid=b"",
        source_cid=SERVER_SCID,
    )
    header = build_long_header(
        template, payload_length=115, packet_number=1, packet_number_length=2
    )
    assert header == SERVER_INITIAL_HEADER


def test_parse_client_initial_header() -> None:
    header = parse_long_header(CLIENT_INITIAL_HEADER)
    assert header.packet_type is PacketType.INITIAL
    assert header.version == QUIC_V1
    assert header.destination_cid == CLIENT_DCID
    assert header.source_cid == b""
    assert header.token == b""
    assert header.length == 1182
    assert header.pn_offset == 18


def test_parse_server_initial_header() -> None:
    header = parse_long_header(SERVER_INITIAL_HEADER)
    assert header.packet_type is PacketType.INITIAL
    assert header.destination_cid == b""
    assert header.source_cid == SERVER_SCID
    assert header.length == 117
    assert header.pn_offset == 18


def test_long_header_roundtrip_handshake() -> None:
    template = LongHeaderTemplate(
        packet_type=PacketType.HANDSHAKE,
        version=QUIC_V1,
        destination_cid=bytes(20),
        source_cid=b"\x01\x02",
    )
    built = build_long_header(
        template, payload_length=100, packet_number=0x1234, packet_number_length=2
    )
    header = parse_long_header(built)
    assert header.packet_type is PacketType.HANDSHAKE
    assert header.destination_cid == bytes(20)
    assert header.source_cid == b"\x01\x02"
    assert header.length == 102
    assert header.pn_offset == len(built) - 2


def test_parse_rejects_short_header_as_long() -> None:
    with pytest.raises(HeaderParseError, match="not a long header"):
        parse_long_header(b"\x40" + bytes(20))


def test_parse_rejects_zero_fixed_bit() -> None:
    with pytest.raises(HeaderParseError, match="fixed bit"):
        parse_long_header(b"\x80" + bytes(20))


def test_parse_rejects_version_negotiation() -> None:
    with pytest.raises(HeaderParseError, match="version negotiation"):
        parse_long_header(b"\xc3" + bytes(4) + bytes(20))


QUIC_V2 = 0x6B3343CF  # RFC 9369
GREASE_VERSION = 0x1A2A3A4A  # RFC 9000 §15 reserved pattern 0x?a?a?a?a


@pytest.mark.parametrize("version", [QUIC_V2, GREASE_VERSION])
def test_parse_raises_unsupported_version_before_type_bits(version: int) -> None:
    data = b"\xf0" + version.to_bytes(4, "big") + b"\x01\xaa" + b"\x00"
    with pytest.raises(UnsupportedVersion) as excinfo:
        parse_long_header(data)
    assert excinfo.value.version == version


def test_parse_rejects_retry() -> None:
    data = bytes([0x80 | 0x40 | (PacketType.RETRY.value << 4)]) + QUIC_V1.to_bytes(4, "big")
    with pytest.raises(HeaderParseError, match="Retry"):
        parse_long_header(data + b"\x00\x00")


def test_parse_rejects_oversized_cid() -> None:
    data = b"\xc3" + QUIC_V1.to_bytes(4, "big") + b"\x15" + bytes(21) + b"\x00"
    with pytest.raises(HeaderParseError, match="longer than 20"):
        parse_long_header(data)


def test_parse_truncated_header() -> None:
    with pytest.raises(BufferReadError):
        parse_long_header(CLIENT_INITIAL_HEADER[:10])


def test_parse_short_header() -> None:
    header = parse_short_header(b"\x41" + SERVER_SCID + b"\x00\x01", cid_length=8)
    assert header.destination_cid == SERVER_SCID
    assert header.pn_offset == 9


def test_parse_short_header_rejects_long() -> None:
    with pytest.raises(HeaderParseError, match="not a short header"):
        parse_short_header(CLIENT_INITIAL_HEADER, cid_length=8)


def test_encode_packet_number_rfc9000_a2() -> None:
    assert encode_packet_number(0xAC5C02, largest_acked=0xABE8B3) == b"\x5c\x02"
    assert encode_packet_number(0xACE8FE, largest_acked=0xABE8B3) == b"\xac\xe8\xfe"


def test_encode_packet_number_first_packet() -> None:
    assert encode_packet_number(0, largest_acked=None) == b"\x00"


def test_decode_packet_number_rfc9000_a3() -> None:
    assert decode_packet_number(0xA82F30EA, 0x9B32, pn_nbits=16) == 0xA82F9B32


def test_decode_packet_number_first_packet() -> None:
    assert decode_packet_number(-1, 0, pn_nbits=8) == 0


def test_packet_number_roundtrip_across_wrap() -> None:
    largest = 0xFF
    truncated = encode_packet_number(0x100, largest_acked=largest)
    decoded = decode_packet_number(largest, int.from_bytes(truncated, "big"), 8 * len(truncated))
    assert decoded == 0x100
