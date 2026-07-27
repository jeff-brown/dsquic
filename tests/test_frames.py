"""Tests for dsquic.frames."""

import pytest

from dsquic.buffer import BufferReadError, encode_varint
from dsquic.frames import (
    Ack,
    ConnectionClose,
    Crypto,
    DataBlocked,
    Datagram,
    EcnCounts,
    Frame,
    FrameParseError,
    HandshakeDone,
    MaxData,
    MaxStreamData,
    MaxStreams,
    NewConnectionId,
    NewToken,
    Padding,
    PathChallenge,
    PathResponse,
    Ping,
    ResetStream,
    StopSending,
    Stream,
    StreamDataBlocked,
    StreamsBlocked,
    is_ack_eliciting,
    parse_frames,
)

ROUNDTRIP_FRAMES: list[Frame] = [
    Ping(),
    Ack(largest=10, delay=5, ranges=[(0, 10)]),
    Ack(largest=10, delay=0, ranges=[(10, 10), (5, 7), (0, 2)]),
    Ack(largest=3, delay=1, ranges=[(0, 3)], ecn=EcnCounts(ect0=1, ect1=2, ce=3)),
    ResetStream(stream_id=4, error_code=0x0107, final_size=1000),
    StopSending(stream_id=8, error_code=1),
    Crypto(offset=0, data=b"hello"),
    Crypto(offset=1200, data=b""),
    NewToken(token=b"\x01\x02\x03"),
    Stream(stream_id=0, offset=0, data=b"GET /index.html\r\n", fin=True),
    Stream(stream_id=4, offset=65536, data=b"body", fin=False),
    MaxData(maximum=2**20),
    MaxStreamData(stream_id=4, maximum=2**16),
    MaxStreams(maximum=100, bidirectional=True),
    MaxStreams(maximum=3, bidirectional=False),
    DataBlocked(limit=2**20),
    StreamDataBlocked(stream_id=4, limit=2**16),
    StreamsBlocked(limit=100, bidirectional=True),
    StreamsBlocked(limit=3, bidirectional=False),
    NewConnectionId(
        sequence=1, retire_prior_to=0, connection_id=b"\xaa" * 8, reset_token=b"\xbb" * 16
    ),
    PathChallenge(data=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
    PathResponse(data=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
    ConnectionClose(error_code=0x0A, frame_type=0x06, reason=b"tls alert"),
    ConnectionClose(error_code=42, frame_type=None, reason=b"app close"),
    HandshakeDone(),
    Datagram(data=b"tunnelled"),
]


@pytest.mark.parametrize("frame", ROUNDTRIP_FRAMES, ids=lambda f: type(f).__name__)
def test_frame_roundtrip(frame: Frame) -> None:
    assert parse_frames(frame.encode()) == [frame]


def test_multiple_frames_in_one_payload() -> None:
    frames: list[Frame] = [
        Ack(largest=1, delay=0, ranges=[(0, 1)]),
        Crypto(offset=0, data=b"x"),
        Ping(),
    ]
    payload = b"".join(frame.encode() for frame in frames)
    assert parse_frames(payload) == frames


def test_padding_coalesces() -> None:
    assert parse_frames(bytes(37)) == [Padding(length=37)]


def test_padding_then_other_frames() -> None:
    payload = bytes(5) + Ping().encode() + bytes(3)
    assert parse_frames(payload) == [Padding(length=5), Ping(), Padding(length=3)]


def test_ack_range_wire_format() -> None:
    # Acknowledging {0-2, 5-7, 10}: first range length 0 from largest 10,
    # then gap/length pairs working downward (RFC 9000 §19.3.1).
    ack = Ack(largest=10, delay=0, ranges=[(10, 10), (5, 7), (0, 2)])
    assert ack.encode() == bytes(
        [0x02, 10, 0, 2, 0, 1, 2, 1, 2]
    )  # type, largest, delay, count, first, gap, len, gap, len


def test_ack_first_range_must_match_largest() -> None:
    with pytest.raises(ValueError, match="largest"):
        Ack(largest=10, delay=0, ranges=[(0, 9)]).encode()


def test_ack_range_below_zero_rejected() -> None:
    # largest=1 with first range length 5 would reach below packet 0.
    payload = bytes([0x02, 1, 0, 0, 5])
    with pytest.raises(FrameParseError, match="below"):
        parse_frames(payload)


def test_stream_without_length_runs_to_end() -> None:
    # Type 0x08: no OFF, no LEN, no FIN; data is the rest of the payload.
    payload = bytes([0x08, 4]) + b"rest of packet"
    assert parse_frames(payload) == [Stream(stream_id=4, offset=0, data=b"rest of packet")]


def test_stream_flag_matrix() -> None:
    for offset in (0, 100):
        for fin in (False, True):
            frame = Stream(stream_id=8, offset=offset, data=b"d", fin=fin)
            assert parse_frames(frame.encode()) == [frame]


def test_datagram_without_length_runs_to_end() -> None:
    payload = bytes([0x30]) + b"whole datagram"
    assert parse_frames(payload) == [Datagram(data=b"whole datagram")]


def test_empty_payload_rejected() -> None:
    with pytest.raises(FrameParseError, match="no frames"):
        parse_frames(b"")


def test_unknown_frame_type_rejected() -> None:
    with pytest.raises(FrameParseError, match="unknown frame type"):
        parse_frames(bytes([0x21]))


def test_non_shortest_frame_type_rejected() -> None:
    # PING encoded as a two-byte varint (0x4001) instead of 0x01 (§12.4).
    with pytest.raises(FrameParseError, match="shortest"):
        parse_frames(b"\x40\x01")


def test_truncated_frame_raises_buffer_error() -> None:
    truncated = Crypto(offset=0, data=b"hello").encode()[:-2]
    with pytest.raises(BufferReadError):
        parse_frames(truncated)


def test_ack_eliciting_classification() -> None:
    assert not is_ack_eliciting(Ack(largest=0, delay=0, ranges=[(0, 0)]))
    assert not is_ack_eliciting(Padding(length=1))
    assert not is_ack_eliciting(ConnectionClose(error_code=0))
    assert is_ack_eliciting(Ping())
    assert is_ack_eliciting(Crypto(offset=0, data=b""))
    assert is_ack_eliciting(Stream(stream_id=0, offset=0, data=b""))
    assert is_ack_eliciting(HandshakeDone())
    assert is_ack_eliciting(Datagram(data=b""))


def test_large_values_use_varints() -> None:
    frame = MaxData(maximum=2**61)
    encoded = frame.encode()
    assert encoded == encode_varint(0x10) + encode_varint(2**61)
    assert parse_frames(encoded) == [frame]
