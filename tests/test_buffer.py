"""Tests for dsquic.buffer."""

import pytest

from dsquic.buffer import VARINT_MAX, Buffer, BufferReadError, encode_varint

APPENDIX_A1_VECTORS = [
    (b"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 151_288_809_941_952_652),
    (b"\x9d\x7f\x3e\x7d", 494_878_333),
    (b"\x7b\xbd", 15_293),
    (b"\x25", 37),
]

VARINT_BOUNDARIES = [
    0,
    0x3F,
    0x40,
    0x3FFF,
    0x4000,
    0x3FFF_FFFF,
    0x4000_0000,
    VARINT_MAX,
]


@pytest.mark.parametrize(("wire", "value"), APPENDIX_A1_VECTORS)
def test_varint_decode_appendix_a1(wire: bytes, value: int) -> None:
    buf = Buffer(wire)
    assert buf.pull_varint() == value
    assert buf.is_empty


def test_varint_decode_accepts_non_shortest_form() -> None:
    assert Buffer(b"\x40\x25").pull_varint() == 37


@pytest.mark.parametrize("value", VARINT_BOUNDARIES)
def test_varint_roundtrip(value: int) -> None:
    buf = Buffer(encode_varint(value))
    assert buf.pull_varint() == value
    assert buf.is_empty


@pytest.mark.parametrize(
    ("value", "length"),
    [
        (0, 1),
        (0x3F, 1),
        (0x40, 2),
        (0x3FFF, 2),
        (0x4000, 4),
        (0x3FFF_FFFF, 4),
        (0x4000_0000, 8),
        (VARINT_MAX, 8),
    ],
)
def test_varint_encode_uses_shortest_form(value: int, length: int) -> None:
    assert len(encode_varint(value)) == length


@pytest.mark.parametrize("value", [-1, VARINT_MAX + 1])
def test_varint_encode_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        encode_varint(value)


def test_varint_decode_truncated() -> None:
    with pytest.raises(BufferReadError):
        Buffer(b"\xc2\x19\x7c").pull_varint()


def test_pull_fixed_width_integers() -> None:
    buf = Buffer(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a")
    assert buf.pull_uint8() == 0x01
    assert buf.pull_uint16() == 0x0203
    assert buf.pull_uint24() == 0x040506
    assert buf.pull_uint32() == 0x0708090A
    assert buf.is_empty


def test_pull_bytes_advances_position() -> None:
    buf = Buffer(b"abcdef")
    assert buf.pull_bytes(2) == b"ab"
    assert buf.position == 2
    assert buf.remaining == 4
    assert buf.pull_bytes(0) == b""
    assert buf.position == 2


def test_pull_bytes_past_end() -> None:
    buf = Buffer(b"ab")
    with pytest.raises(BufferReadError):
        buf.pull_bytes(3)
    assert buf.position == 0


def test_pull_bytes_negative_length() -> None:
    with pytest.raises(ValueError, match="negative"):
        Buffer(b"ab").pull_bytes(-1)


def test_empty_buffer() -> None:
    buf = Buffer(b"")
    assert buf.is_empty
    assert buf.remaining == 0
    with pytest.raises(BufferReadError):
        buf.pull_uint8()
