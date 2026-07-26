"""Variable-length integer encoding and the sequential byte reader.

RFC 9000 §16 and Appendix A.1.

The two most significant bits of a varint's first byte encode its total
length (0b00: 1 byte, 0b01: 2, 0b10: 4, 0b11: 8); the remaining bits
encode the value, big-endian. Encoders emit the shortest form; decoders
accept any of the four forms.
"""

VARINT_MAX = 2**62 - 1

_MAX_IN_1_BYTE = 0x3F
_MAX_IN_2_BYTES = 0x3FFF
_MAX_IN_4_BYTES = 0x3FFF_FFFF


class BufferReadError(Exception):
    """A read ran past the end of the buffer."""


def encode_varint(value: int) -> bytes:
    """Encode value in the shortest varint form (RFC 9000 §16)."""
    if not 0 <= value <= VARINT_MAX:
        raise ValueError(f"varint out of range: {value}")
    if value <= _MAX_IN_1_BYTE:
        return value.to_bytes(1, "big")
    if value <= _MAX_IN_2_BYTES:
        return (value | 0x4000).to_bytes(2, "big")
    if value <= _MAX_IN_4_BYTES:
        return (value | 0x8000_0000).to_bytes(4, "big")
    return (value | 0xC000_0000_0000_0000).to_bytes(8, "big")


class Buffer:
    """Sequential reader over immutable bytes.

    Parsers pull fixed-width integers, varints, and byte runs; any read
    past the end of the data raises BufferReadError.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    @property
    def position(self) -> int:
        return self._position

    @property
    def remaining(self) -> int:
        return len(self._data) - self._position

    @property
    def is_empty(self) -> bool:
        return self._position == len(self._data)

    def pull_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError(f"negative length: {length}")
        if length > self.remaining:
            raise BufferReadError(f"cannot pull {length} bytes, {self.remaining} remaining")
        start = self._position
        self._position += length
        return self._data[start : self._position]

    def pull_uint8(self) -> int:
        return self.pull_bytes(1)[0]

    def pull_uint16(self) -> int:
        return int.from_bytes(self.pull_bytes(2), "big")

    def pull_uint32(self) -> int:
        return int.from_bytes(self.pull_bytes(4), "big")

    def pull_varint(self) -> int:
        """Decode a varint (RFC 9000 §16); any of the four lengths is accepted."""
        first = self.pull_uint8()
        length = 1 << (first >> 6)
        value = first & 0x3F
        for byte in self.pull_bytes(length - 1):
            value = (value << 8) | byte
        return value
