"""Frame types: encoding, decoding, and per-frame semantics.

RFC 9000 §12.4 and §19, plus the DATAGRAM frames of RFC 9221.

One dataclass per frame type, PADDING (0x00) through HANDSHAKE_DONE
(0x1e) and DATAGRAM (0x30/0x31), each with an ``encode`` method;
``parse_frames`` decodes a packet payload. Contiguous PADDING bytes
parse as one Padding frame. Frame types must use the shortest varint
form (§12.4); longer encodings and unknown frame types raise
FrameParseError, which the connection maps to FRAME_ENCODING_ERROR.

ACK ranges are carried as inclusive (low, high) packet number pairs in
wire order: highest range first, descending (§19.3.1).
"""

from collections.abc import Callable
from dataclasses import dataclass

from dsquic.buffer import Buffer, encode_varint

PADDING_TYPE = 0x00
PING_TYPE = 0x01
ACK_TYPE = 0x02
ACK_ECN_TYPE = 0x03
RESET_STREAM_TYPE = 0x04
STOP_SENDING_TYPE = 0x05
CRYPTO_TYPE = 0x06
NEW_TOKEN_TYPE = 0x07
STREAM_TYPE_BASE = 0x08  # 0x08-0x0f; low bits: OFF 0x04, LEN 0x02, FIN 0x01
STREAM_OFF_BIT = 0x04
STREAM_LEN_BIT = 0x02
STREAM_FIN_BIT = 0x01
MAX_DATA_TYPE = 0x10
MAX_STREAM_DATA_TYPE = 0x11
MAX_STREAMS_BIDI_TYPE = 0x12
MAX_STREAMS_UNI_TYPE = 0x13
DATA_BLOCKED_TYPE = 0x14
STREAM_DATA_BLOCKED_TYPE = 0x15
STREAMS_BLOCKED_BIDI_TYPE = 0x16
STREAMS_BLOCKED_UNI_TYPE = 0x17
NEW_CONNECTION_ID_TYPE = 0x18
RETIRE_CONNECTION_ID_TYPE = 0x19
PATH_CHALLENGE_TYPE = 0x1A
PATH_RESPONSE_TYPE = 0x1B
CONNECTION_CLOSE_TRANSPORT_TYPE = 0x1C
CONNECTION_CLOSE_APP_TYPE = 0x1D
HANDSHAKE_DONE_TYPE = 0x1E
DATAGRAM_TYPE = 0x30  # RFC 9221; 0x31 carries an explicit length
DATAGRAM_LEN_TYPE = 0x31


class FrameParseError(Exception):
    """A frame is malformed; maps to FRAME_ENCODING_ERROR (RFC 9000 §12.4)."""


@dataclass(frozen=True)
class Padding:
    """§19.1. Contiguous padding bytes parse as one frame."""

    length: int

    def encode(self) -> bytes:
        return bytes(self.length)


@dataclass(frozen=True)
class Ping:
    """§19.2."""

    def encode(self) -> bytes:
        return bytes([PING_TYPE])


@dataclass(frozen=True)
class EcnCounts:
    """§19.3.2."""

    ect0: int
    ect1: int
    ce: int


@dataclass(frozen=True)
class Ack:
    """§19.3. ``ranges`` are inclusive (low, high) pairs, highest first."""

    largest: int
    delay: int
    ranges: list[tuple[int, int]]
    ecn: EcnCounts | None = None

    def encode(self) -> bytes:
        first_low, first_high = self.ranges[0]
        if first_high != self.largest:
            raise ValueError("first range must end at the largest acknowledged")
        out = bytearray(encode_varint(ACK_ECN_TYPE if self.ecn else ACK_TYPE))
        out += encode_varint(self.largest)
        out += encode_varint(self.delay)
        out += encode_varint(len(self.ranges) - 1)
        out += encode_varint(first_high - first_low)
        previous_low = first_low
        for low, high in self.ranges[1:]:
            out += encode_varint(previous_low - high - 2)  # §19.3.1 Gap
            out += encode_varint(high - low)
            previous_low = low
        if self.ecn:
            out += encode_varint(self.ecn.ect0)
            out += encode_varint(self.ecn.ect1)
            out += encode_varint(self.ecn.ce)
        return bytes(out)


@dataclass(frozen=True)
class ResetStream:
    """§19.4."""

    stream_id: int
    error_code: int
    final_size: int

    def encode(self) -> bytes:
        return (
            encode_varint(RESET_STREAM_TYPE)
            + encode_varint(self.stream_id)
            + encode_varint(self.error_code)
            + encode_varint(self.final_size)
        )


@dataclass(frozen=True)
class StopSending:
    """§19.5."""

    stream_id: int
    error_code: int

    def encode(self) -> bytes:
        return (
            encode_varint(STOP_SENDING_TYPE)
            + encode_varint(self.stream_id)
            + encode_varint(self.error_code)
        )


@dataclass(frozen=True)
class Crypto:
    """§19.6. One ordered byte stream per encryption level, no stream ID."""

    offset: int
    data: bytes

    def encode(self) -> bytes:
        return (
            encode_varint(CRYPTO_TYPE)
            + encode_varint(self.offset)
            + encode_varint(len(self.data))
            + self.data
        )


@dataclass(frozen=True)
class NewToken:
    """§19.7."""

    token: bytes

    def encode(self) -> bytes:
        return encode_varint(NEW_TOKEN_TYPE) + encode_varint(len(self.token)) + self.token


@dataclass(frozen=True)
class Stream:
    """§19.8. Always encoded with an explicit length (LEN bit set)."""

    stream_id: int
    offset: int
    data: bytes
    fin: bool = False

    def encode(self) -> bytes:
        frame_type = STREAM_TYPE_BASE | STREAM_LEN_BIT
        if self.offset:
            frame_type |= STREAM_OFF_BIT
        if self.fin:
            frame_type |= STREAM_FIN_BIT
        out = bytearray(encode_varint(frame_type))
        out += encode_varint(self.stream_id)
        if self.offset:
            out += encode_varint(self.offset)
        out += encode_varint(len(self.data))
        out += self.data
        return bytes(out)


@dataclass(frozen=True)
class MaxData:
    """§19.9."""

    maximum: int

    def encode(self) -> bytes:
        return encode_varint(MAX_DATA_TYPE) + encode_varint(self.maximum)


@dataclass(frozen=True)
class MaxStreamData:
    """§19.10."""

    stream_id: int
    maximum: int

    def encode(self) -> bytes:
        return (
            encode_varint(MAX_STREAM_DATA_TYPE)
            + encode_varint(self.stream_id)
            + encode_varint(self.maximum)
        )


@dataclass(frozen=True)
class MaxStreams:
    """§19.11."""

    maximum: int
    bidirectional: bool

    def encode(self) -> bytes:
        frame_type = MAX_STREAMS_BIDI_TYPE if self.bidirectional else MAX_STREAMS_UNI_TYPE
        return encode_varint(frame_type) + encode_varint(self.maximum)


@dataclass(frozen=True)
class DataBlocked:
    """§19.12."""

    limit: int

    def encode(self) -> bytes:
        return encode_varint(DATA_BLOCKED_TYPE) + encode_varint(self.limit)


@dataclass(frozen=True)
class StreamDataBlocked:
    """§19.13."""

    stream_id: int
    limit: int

    def encode(self) -> bytes:
        return (
            encode_varint(STREAM_DATA_BLOCKED_TYPE)
            + encode_varint(self.stream_id)
            + encode_varint(self.limit)
        )


@dataclass(frozen=True)
class StreamsBlocked:
    """§19.14."""

    limit: int
    bidirectional: bool

    def encode(self) -> bytes:
        frame_type = STREAMS_BLOCKED_BIDI_TYPE if self.bidirectional else STREAMS_BLOCKED_UNI_TYPE
        return encode_varint(frame_type) + encode_varint(self.limit)


@dataclass(frozen=True)
class NewConnectionId:
    """§19.15."""

    sequence: int
    retire_prior_to: int
    connection_id: bytes
    reset_token: bytes

    def encode(self) -> bytes:
        return (
            encode_varint(NEW_CONNECTION_ID_TYPE)
            + encode_varint(self.sequence)
            + encode_varint(self.retire_prior_to)
            + bytes([len(self.connection_id)])
            + self.connection_id
            + self.reset_token
        )


@dataclass(frozen=True)
class RetireConnectionId:
    """§19.16."""

    sequence: int

    def encode(self) -> bytes:
        return encode_varint(RETIRE_CONNECTION_ID_TYPE) + encode_varint(self.sequence)


@dataclass(frozen=True)
class PathChallenge:
    """§19.17."""

    data: bytes

    def encode(self) -> bytes:
        return encode_varint(PATH_CHALLENGE_TYPE) + self.data


@dataclass(frozen=True)
class PathResponse:
    """§19.18."""

    data: bytes

    def encode(self) -> bytes:
        return encode_varint(PATH_RESPONSE_TYPE) + self.data


@dataclass(frozen=True)
class ConnectionClose:
    """§19.19. ``frame_type`` None means the application variant (0x1d)."""

    error_code: int
    reason: bytes = b""
    frame_type: int | None = 0

    def encode(self) -> bytes:
        if self.frame_type is None:
            out = bytearray(encode_varint(CONNECTION_CLOSE_APP_TYPE))
            out += encode_varint(self.error_code)
        else:
            out = bytearray(encode_varint(CONNECTION_CLOSE_TRANSPORT_TYPE))
            out += encode_varint(self.error_code)
            out += encode_varint(self.frame_type)
        out += encode_varint(len(self.reason))
        out += self.reason
        return bytes(out)


@dataclass(frozen=True)
class HandshakeDone:
    """§19.20. Server to client only."""

    def encode(self) -> bytes:
        return encode_varint(HANDSHAKE_DONE_TYPE)


@dataclass(frozen=True)
class Datagram:
    """RFC 9221 §4. Always encoded with an explicit length (type 0x31)."""

    data: bytes

    def encode(self) -> bytes:
        return encode_varint(DATAGRAM_LEN_TYPE) + encode_varint(len(self.data)) + self.data


Frame = (
    Padding
    | Ping
    | Ack
    | ResetStream
    | StopSending
    | Crypto
    | NewToken
    | Stream
    | MaxData
    | MaxStreamData
    | MaxStreams
    | DataBlocked
    | StreamDataBlocked
    | StreamsBlocked
    | NewConnectionId
    | RetireConnectionId
    | PathChallenge
    | PathResponse
    | ConnectionClose
    | HandshakeDone
    | Datagram
)


def is_ack_eliciting(frame: Frame) -> bool:
    """§13.2: all frames elicit an ACK except ACK, PADDING, CONNECTION_CLOSE."""
    return not isinstance(frame, Ack | Padding | ConnectionClose)


def _parse_padding(buf: Buffer, _frame_type: int) -> Padding:
    length = 1
    while not buf.is_empty and buf.peek_uint8() == PADDING_TYPE:
        buf.pull_uint8()
        length += 1
    return Padding(length=length)


def _parse_ping(_buf: Buffer, _frame_type: int) -> Ping:
    return Ping()


def _parse_ack(buf: Buffer, frame_type: int) -> Ack:
    largest = buf.pull_varint()
    delay = buf.pull_varint()
    range_count = buf.pull_varint()
    first_range = buf.pull_varint()
    low = largest - first_range
    if low < 0:
        raise FrameParseError("ACK range extends below packet number 0")
    ranges = [(low, largest)]
    for _ in range(range_count):
        gap = buf.pull_varint()
        length = buf.pull_varint()
        high = low - gap - 2
        low = high - length
        if low < 0:
            raise FrameParseError("ACK range extends below packet number 0")
        ranges.append((low, high))
    ecn = None
    if frame_type == ACK_ECN_TYPE:
        ecn = EcnCounts(ect0=buf.pull_varint(), ect1=buf.pull_varint(), ce=buf.pull_varint())
    return Ack(largest=largest, delay=delay, ranges=ranges, ecn=ecn)


def _parse_reset_stream(buf: Buffer, _frame_type: int) -> ResetStream:
    return ResetStream(
        stream_id=buf.pull_varint(),
        error_code=buf.pull_varint(),
        final_size=buf.pull_varint(),
    )


def _parse_stop_sending(buf: Buffer, _frame_type: int) -> StopSending:
    return StopSending(stream_id=buf.pull_varint(), error_code=buf.pull_varint())


def _parse_crypto(buf: Buffer, _frame_type: int) -> Crypto:
    offset = buf.pull_varint()
    return Crypto(offset=offset, data=buf.pull_bytes(buf.pull_varint()))


def _parse_new_token(buf: Buffer, _frame_type: int) -> NewToken:
    return NewToken(token=buf.pull_bytes(buf.pull_varint()))


def _parse_stream(buf: Buffer, frame_type: int) -> Stream:
    stream_id = buf.pull_varint()
    offset = buf.pull_varint() if frame_type & STREAM_OFF_BIT else 0
    if frame_type & STREAM_LEN_BIT:
        data = buf.pull_bytes(buf.pull_varint())
    else:
        data = buf.pull_bytes(buf.remaining)
    fin = bool(frame_type & STREAM_FIN_BIT)
    return Stream(stream_id=stream_id, offset=offset, data=data, fin=fin)


def _parse_max_data(buf: Buffer, _frame_type: int) -> MaxData:
    return MaxData(maximum=buf.pull_varint())


def _parse_max_stream_data(buf: Buffer, _frame_type: int) -> MaxStreamData:
    return MaxStreamData(stream_id=buf.pull_varint(), maximum=buf.pull_varint())


def _parse_max_streams(buf: Buffer, frame_type: int) -> MaxStreams:
    return MaxStreams(maximum=buf.pull_varint(), bidirectional=frame_type == MAX_STREAMS_BIDI_TYPE)


def _parse_data_blocked(buf: Buffer, _frame_type: int) -> DataBlocked:
    return DataBlocked(limit=buf.pull_varint())


def _parse_stream_data_blocked(buf: Buffer, _frame_type: int) -> StreamDataBlocked:
    return StreamDataBlocked(stream_id=buf.pull_varint(), limit=buf.pull_varint())


def _parse_streams_blocked(buf: Buffer, frame_type: int) -> StreamsBlocked:
    bidirectional = frame_type == STREAMS_BLOCKED_BIDI_TYPE
    return StreamsBlocked(limit=buf.pull_varint(), bidirectional=bidirectional)


def _parse_new_connection_id(buf: Buffer, _frame_type: int) -> NewConnectionId:
    sequence = buf.pull_varint()
    retire_prior_to = buf.pull_varint()
    connection_id = buf.pull_bytes(buf.pull_uint8())
    return NewConnectionId(
        sequence=sequence,
        retire_prior_to=retire_prior_to,
        connection_id=connection_id,
        reset_token=buf.pull_bytes(16),
    )


def _parse_retire_connection_id(buf: Buffer, _frame_type: int) -> RetireConnectionId:
    return RetireConnectionId(sequence=buf.pull_varint())


def _parse_path_challenge(buf: Buffer, _frame_type: int) -> PathChallenge:
    return PathChallenge(data=buf.pull_bytes(8))


def _parse_path_response(buf: Buffer, _frame_type: int) -> PathResponse:
    return PathResponse(data=buf.pull_bytes(8))


def _parse_connection_close(buf: Buffer, frame_type: int) -> ConnectionClose:
    error_code = buf.pull_varint()
    closing_frame_type: int | None = None
    if frame_type == CONNECTION_CLOSE_TRANSPORT_TYPE:
        closing_frame_type = buf.pull_varint()
    reason = buf.pull_bytes(buf.pull_varint())
    return ConnectionClose(error_code=error_code, reason=reason, frame_type=closing_frame_type)


def _parse_handshake_done(_buf: Buffer, _frame_type: int) -> HandshakeDone:
    return HandshakeDone()


def _parse_datagram(buf: Buffer, frame_type: int) -> Datagram:
    if frame_type == DATAGRAM_LEN_TYPE:
        return Datagram(data=buf.pull_bytes(buf.pull_varint()))
    return Datagram(data=buf.pull_bytes(buf.remaining))


# The frame vocabulary as a table: every valid type value maps to its
# parser (§19; STREAM occupies eight values for its three flag bits).
_FRAME_PARSERS: dict[int, Callable[[Buffer, int], Frame]] = {
    PADDING_TYPE: _parse_padding,
    PING_TYPE: _parse_ping,
    ACK_TYPE: _parse_ack,
    ACK_ECN_TYPE: _parse_ack,
    RESET_STREAM_TYPE: _parse_reset_stream,
    STOP_SENDING_TYPE: _parse_stop_sending,
    CRYPTO_TYPE: _parse_crypto,
    NEW_TOKEN_TYPE: _parse_new_token,
    **{STREAM_TYPE_BASE | flags: _parse_stream for flags in range(8)},
    MAX_DATA_TYPE: _parse_max_data,
    MAX_STREAM_DATA_TYPE: _parse_max_stream_data,
    MAX_STREAMS_BIDI_TYPE: _parse_max_streams,
    MAX_STREAMS_UNI_TYPE: _parse_max_streams,
    DATA_BLOCKED_TYPE: _parse_data_blocked,
    STREAM_DATA_BLOCKED_TYPE: _parse_stream_data_blocked,
    STREAMS_BLOCKED_BIDI_TYPE: _parse_streams_blocked,
    STREAMS_BLOCKED_UNI_TYPE: _parse_streams_blocked,
    NEW_CONNECTION_ID_TYPE: _parse_new_connection_id,
    RETIRE_CONNECTION_ID_TYPE: _parse_retire_connection_id,
    PATH_CHALLENGE_TYPE: _parse_path_challenge,
    PATH_RESPONSE_TYPE: _parse_path_response,
    CONNECTION_CLOSE_TRANSPORT_TYPE: _parse_connection_close,
    CONNECTION_CLOSE_APP_TYPE: _parse_connection_close,
    HANDSHAKE_DONE_TYPE: _parse_handshake_done,
    DATAGRAM_TYPE: _parse_datagram,
    DATAGRAM_LEN_TYPE: _parse_datagram,
}


def parse_frames(payload: bytes) -> list[Frame]:
    """Parse a decrypted packet payload into frames (§12.4).

    An empty payload is an error (a packet must contain at least one
    frame); so are unknown frame types and non-shortest type encodings.
    Truncated frames surface as BufferReadError from the buffer.
    """
    if not payload:
        raise FrameParseError("packet payload contains no frames")
    buf = Buffer(payload)
    frames: list[Frame] = []
    while not buf.is_empty:
        start = buf.position
        frame_type = buf.pull_varint()
        if buf.position - start != len(encode_varint(frame_type)):
            raise FrameParseError(f"frame type 0x{frame_type:x} not in shortest varint form")
        parser = _FRAME_PARSERS.get(frame_type)
        if parser is None:
            raise FrameParseError(f"unknown frame type 0x{frame_type:x}")
        frames.append(parser(buf, frame_type))
    return frames
