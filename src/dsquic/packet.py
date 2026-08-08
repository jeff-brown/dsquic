"""Packet formats: long and short headers, packet types, packet numbers.

RFC 9000 §17 (Packet Formats), §12 (Packets and Frames), and §17.1 with
Appendix A.2/A.3 (packet number encoding and decoding).

Parsing stops at the Packet Number field: the packet number length lives
in the two low bits of the first byte, which are protected, so the field
cannot be read until header protection is removed (RFC 9001 §5.4).
Headers therefore expose ``pn_offset`` and protection.py finishes the
job. Version Negotiation and Retry parsing are not yet implemented and
raise HeaderParseError.

Version handling follows RFC 8999: only the first bit, version, and
connection IDs are read version-independently; versions other than v1
raise UnsupportedVersion before any version-specific field (such as the
type bits, which RFC 9369 remaps for v2) is interpreted. The fixed bit
is required to be set; RFC 9287 (greasing the QUIC bit) is not yet
supported.
"""

import enum
import os
from dataclasses import dataclass

from dsquic.buffer import Buffer, BufferReadError, encode_varint

HEADER_FORM_LONG = 0x80
FIXED_BIT = 0x40
QUIC_V1 = 0x00000001
VERSION_NEGOTIATION = 0x00000000  # §17.2.1: not a version, a packet type
SUPPORTED_VERSIONS = [QUIC_V1]
MAX_CID_LENGTH = 20  # RFC 9000 §17.2
MAX_PACKET_NUMBER = 2**62 - 1
# §6.1: never answer a smaller datagram, so the reply cannot amplify.
MIN_VERSION_NEGOTIATION_DATAGRAM = 1200
VERSION_END = 5  # first byte plus the 32-bit version (§17.2)


class PacketType(enum.Enum):
    """Long header packet types (RFC 9000 §17.2, Table 5)."""

    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3


class HeaderParseError(Exception):
    """The packet header is malformed or unsupported."""


class UnsupportedVersion(HeaderParseError):
    """The version is not one this implementation speaks.

    Only the version-independent prefix (RFC 8999 §5.1: first bit,
    version, connection IDs) was read; type bits and later fields are
    version-specific and were not interpreted. A server catches this to
    send Version Negotiation (RFC 9000 §6); greased versions
    (0x?a?a?a?a, RFC 9000 §15) arrive here too.
    """

    def __init__(self, version: int) -> None:
        super().__init__(f"unsupported version 0x{version:08x}")
        self.version = version


@dataclass(frozen=True)
class LongHeader:
    """The unprotected fields of a long header packet (RFC 9000 §17.2).

    ``length`` is the Length field: packet number plus protected payload.
    ``pn_offset`` is where the Packet Number field starts, for
    protection.py.
    """

    packet_type: PacketType
    version: int
    destination_cid: bytes
    source_cid: bytes
    token: bytes
    length: int
    pn_offset: int


@dataclass(frozen=True)
class Retry:
    """A Retry packet (§17.2.5).

    It carries no packet number, no length, and no payload: the token
    and the integrity tag are the whole content. The tag is checked
    against the original destination connection ID by the caller, which
    is the only party that knows it.
    """

    version: int
    destination_cid: bytes
    source_cid: bytes
    token: bytes


@dataclass(frozen=True)
class ShortHeader:
    """The unprotected fields of a 1-RTT packet (RFC 9000 §17.3).

    The destination CID length is not encoded on the wire; the caller
    supplies it from connection context.
    """

    destination_cid: bytes
    pn_offset: int


def parse_long_header(data: bytes) -> LongHeader:
    """Parse a long header up to the Packet Number field (RFC 9000 §17.2)."""
    buf = Buffer(data)
    first = buf.pull_uint8()
    if not first & HEADER_FORM_LONG:
        raise HeaderParseError("not a long header")
    if not first & FIXED_BIT:
        raise HeaderParseError("fixed bit is zero")
    version = buf.pull_uint32()
    if version == 0:
        raise HeaderParseError("version negotiation parsing not implemented")
    destination_cid = buf.pull_bytes(buf.pull_uint8())
    source_cid = buf.pull_bytes(buf.pull_uint8())
    if len(destination_cid) > MAX_CID_LENGTH or len(source_cid) > MAX_CID_LENGTH:
        raise HeaderParseError("connection ID longer than 20 bytes")
    if version != QUIC_V1:
        # RFC 8999 §5.1: nothing beyond this point is version independent.
        # The type bits are remapped by QUICv2 (RFC 9369 §3.2), so they are
        # not interpreted for a version this implementation does not speak.
        raise UnsupportedVersion(version)
    packet_type = PacketType((first & 0x30) >> 4)
    if packet_type is PacketType.RETRY:
        raise HeaderParseError("a Retry packet has no Length field; use parse_retry")
    token = b""
    if packet_type is PacketType.INITIAL:
        token = buf.pull_bytes(buf.pull_varint())
    length = buf.pull_varint()
    return LongHeader(
        packet_type=packet_type,
        version=version,
        destination_cid=destination_cid,
        source_cid=source_cid,
        token=token,
        length=length,
        pn_offset=buf.position,
    )


def build_version_negotiation(destination_cid: bytes, source_cid: bytes) -> bytes:
    """A Version Negotiation packet listing the versions we speak.

    RFC 9000 §17.2.1. The version field is zero and there is no length or
    packet number: the body is just a list of versions. The high bit must
    be set; the remaining seven bits of the first byte are arbitrary and
    the peer ignores them.

    Callers pass the connection IDs already swapped, per §17.2.1: the
    answer's Destination CID is the source of the packet being answered.
    """
    first = os.urandom(1)[0] | HEADER_FORM_LONG
    return (
        bytes([first])
        + VERSION_NEGOTIATION.to_bytes(4, "big")
        + bytes([len(destination_cid)])
        + destination_cid
        + bytes([len(source_cid)])
        + source_cid
        + b"".join(version.to_bytes(4, "big") for version in SUPPORTED_VERSIONS)
    )


@dataclass(frozen=True)
class VersionNegotiation:
    """A parsed Version Negotiation packet (§17.2.1)."""

    destination_cid: bytes
    source_cid: bytes
    versions: list[int]


def is_version_negotiation(data: bytes) -> bool:
    """Whether a datagram begins with a Version Negotiation packet.

    Checked before ordinary header parsing, because the packet carries
    no Length or Packet Number field and cannot be read as one
    (§17.2.1).
    """
    if len(data) < VERSION_END or not data[0] & HEADER_FORM_LONG:
        return False
    return int.from_bytes(data[1:VERSION_END], "big") == VERSION_NEGOTIATION


def parse_version_negotiation(data: bytes) -> VersionNegotiation:
    """Parse a Version Negotiation packet (§17.2.1)."""
    buf = Buffer(data[5:])
    destination_cid = buf.pull_bytes(buf.pull_uint8())
    source_cid = buf.pull_bytes(buf.pull_uint8())
    versions: list[int] = []
    while not buf.is_empty:
        versions.append(buf.pull_uint32())
    return VersionNegotiation(
        destination_cid=destination_cid, source_cid=source_cid, versions=versions
    )


def version_negotiation_response(datagram: bytes) -> bytes | None:
    """The Version Negotiation packet a datagram deserves, if any (§6.1).

    Stateless: a server answers any packet that might start a connection
    but names a version it does not speak, without creating connection
    state. Returns None when no answer is owed, which covers short
    headers, versions we do speak, Version Negotiation packets themselves
    (answering one would loop), and datagrams below 1200 bytes, which
    §6.1 forbids answering so the packet cannot be used for
    amplification.
    """
    if len(datagram) < MIN_VERSION_NEGOTIATION_DATAGRAM:
        return None
    if not datagram[0] & HEADER_FORM_LONG:
        return None
    version = int.from_bytes(datagram[1:5], "big")
    if version == VERSION_NEGOTIATION or version in SUPPORTED_VERSIONS:
        return None
    buf = Buffer(datagram[5:])
    try:
        # RFC 8999 §5.1: the connection IDs are version independent.
        peer_destination = buf.pull_bytes(buf.pull_uint8())
        peer_source = buf.pull_bytes(buf.pull_uint8())
    except BufferReadError:
        return None
    if len(peer_destination) > MAX_CID_LENGTH or len(peer_source) > MAX_CID_LENGTH:
        return None
    return build_version_negotiation(destination_cid=peer_source, source_cid=peer_destination)


def destination_connection_id(data: bytes, cid_length: int) -> bytes | None:
    """Read a datagram's Destination Connection ID for routing.

    RFC 8999 §5.1: the header form bit, the version, and the connection
    IDs are the only version-independent fields, which is exactly what a
    demultiplexer needs and no more. Short headers do not carry a length,
    so ``cid_length`` supplies the one this endpoint issues. Returns None
    if the datagram is too short to route.

    Exposed for the transport layer to route on (design.md §4.7); the
    routing itself is I/O and lives in endpoints/.
    """
    if not data:
        return None
    if data[0] & HEADER_FORM_LONG:
        offset = 1 + 4  # first byte, version
        if len(data) <= offset:
            return None
        length = data[offset]
        if length > MAX_CID_LENGTH or len(data) < offset + 1 + length:
            return None
        return data[offset + 1 : offset + 1 + length]
    if len(data) < 1 + cid_length:
        return None
    return data[1 : 1 + cid_length]


def parse_short_header(data: bytes, cid_length: int) -> ShortHeader:
    """Parse a 1-RTT header up to the Packet Number field (RFC 9000 §17.3)."""
    buf = Buffer(data)
    first = buf.pull_uint8()
    if first & HEADER_FORM_LONG:
        raise HeaderParseError("not a short header")
    if not first & FIXED_BIT:
        raise HeaderParseError("fixed bit is zero")
    destination_cid = buf.pull_bytes(cid_length)
    return ShortHeader(destination_cid=destination_cid, pn_offset=buf.position)


@dataclass(frozen=True)
class LongHeaderTemplate:
    """The fields of a long header that are constant across packets.

    RFC 9000 §17.2. A sender keeps one per packet number space and
    varies only the payload length and packet number per packet.
    """

    packet_type: PacketType
    version: int
    destination_cid: bytes
    source_cid: bytes
    token: bytes = b""


def build_long_header(
    template: LongHeaderTemplate,
    payload_length: int,
    packet_number: int,
    packet_number_length: int,
) -> bytes:
    """Serialize a long header ending with the truncated packet number.

    RFC 9000 §17.2. ``payload_length`` is the protected payload size
    (plaintext plus AEAD tag); the Length field adds the packet number
    length to it. The packet number is truncated to
    ``packet_number_length`` bytes, which is also encoded in the two low
    bits of the first byte.
    """
    first = HEADER_FORM_LONG | FIXED_BIT | (template.packet_type.value << 4)
    first |= packet_number_length - 1
    header = bytearray([first])
    header += template.version.to_bytes(4, "big")
    header += bytes([len(template.destination_cid)]) + template.destination_cid
    header += bytes([len(template.source_cid)]) + template.source_cid
    if template.packet_type is PacketType.INITIAL:
        header += encode_varint(len(template.token)) + template.token
    header += encode_varint(packet_number_length + payload_length)
    header += packet_number.to_bytes(8, "big")[-packet_number_length:]
    return bytes(header)


def encode_packet_number(full_pn: int, largest_acked: int | None) -> bytes:
    """Truncate a packet number to the shortest safe encoding.

    RFC 9000 §17.1 and Appendix A.2: the encoding must cover a range at
    least twice the number of contiguous unacknowledged packets.
    """
    num_unacked = full_pn + 1 if largest_acked is None else full_pn - largest_acked
    num_bytes = min(4, max(1, (num_unacked.bit_length() + 1 + 7) // 8))
    return full_pn.to_bytes(8, "big")[-num_bytes:]


def decode_packet_number(largest_pn: int, truncated_pn: int, pn_nbits: int) -> int:
    """Recover a full packet number from its truncated form.

    RFC 9000 §17.1 and Appendix A.3. ``largest_pn`` is the largest
    packet number processed in this space, or -1 if none has been.
    """
    expected_pn = largest_pn + 1
    pn_win = 1 << pn_nbits
    pn_hwin = pn_win // 2
    pn_mask = pn_win - 1
    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
    if candidate_pn <= expected_pn - pn_hwin and candidate_pn < (1 << 62) - pn_win:
        return candidate_pn + pn_win
    if candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
        return candidate_pn - pn_win
    return candidate_pn
