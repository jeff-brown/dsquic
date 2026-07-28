"""Tests for dsquic.streams."""

import pytest

from dsquic.frames import (
    FINAL_SIZE_ERROR,
    FLOW_CONTROL_ERROR,
    STREAM_LIMIT_ERROR,
    STREAM_STATE_ERROR,
    Stream,
)
from dsquic.streams import (
    FlowControlLimits,
    RangeSet,
    RecvState,
    RecvStream,
    SendState,
    SendStream,
    StreamError,
    StreamManager,
    is_bidirectional,
    is_client_initiated,
)

GENEROUS = FlowControlLimits(
    max_data=1_000_000,
    max_stream_data_bidi_local=100_000,
    max_stream_data_bidi_remote=100_000,
    max_stream_data_uni=100_000,
    max_streams_bidi=100,
    max_streams_uni=3,
)


def make_manager(is_client: bool = True, **overrides: int) -> StreamManager:
    local = GENEROUS
    peer = GENEROUS
    if overrides:
        peer = FlowControlLimits(**{**GENEROUS.__dict__, **overrides})
    return StreamManager(is_client=is_client, local=local, peer=peer)


class TestStreamIds:
    def test_type_bits(self) -> None:
        # §2.1, Table 1: 0 client-bidi, 1 server-bidi, 2 client-uni, 3 server-uni.
        assert is_client_initiated(0) and is_bidirectional(0)
        assert not is_client_initiated(1) and is_bidirectional(1)
        assert is_client_initiated(2) and not is_bidirectional(2)
        assert not is_client_initiated(3) and not is_bidirectional(3)

    def test_client_opens_0_4_8(self) -> None:
        manager = make_manager(is_client=True)
        assert [manager.open_bidi() for _ in range(3)] == [0, 4, 8]

    def test_server_opens_1_5_9(self) -> None:
        manager = make_manager(is_client=False)
        assert [manager.open_bidi() for _ in range(3)] == [1, 5, 9]


class TestRangeSet:
    def test_merges_adjacent_and_overlapping(self) -> None:
        ranges = RangeSet()
        ranges.add(0, 5)
        ranges.add(10, 15)
        ranges.add(5, 10)
        assert ranges.ranges == [(0, 15)]

    def test_contiguous_from(self) -> None:
        ranges = RangeSet()
        ranges.add(0, 5)
        ranges.add(7, 9)
        assert ranges.contiguous_from(0) == 5
        assert ranges.contiguous_from(5) == 5
        assert ranges.contiguous_from(7) == 9

    def test_covers(self) -> None:
        ranges = RangeSet()
        ranges.add(0, 10)
        assert ranges.covers(0, 10)
        assert not ranges.covers(0, 11)

    def test_empty_add_ignored(self) -> None:
        ranges = RangeSet()
        ranges.add(5, 5)
        assert ranges.ranges == []


class TestSendStream:
    def test_states_ready_send_datasent_datarecvd(self) -> None:
        stream = SendStream(0, max_stream_data=1000)
        states = [stream.state]
        stream.write(b"hello", fin=True)
        frame = stream.next_frame(max_bytes=3, connection_credit=1000)
        assert frame == Stream(stream_id=0, offset=0, data=b"hel", fin=False)
        states.append(stream.state)
        fin_frame = stream.next_frame(max_bytes=100, connection_credit=1000)
        assert fin_frame == Stream(stream_id=0, offset=3, data=b"lo", fin=True)
        states.append(stream.state)
        stream.on_frame_acked(frame)
        stream.on_frame_acked(fin_frame)
        states.append(stream.state)
        assert states == [
            SendState.READY,
            SendState.SEND,
            SendState.DATA_SENT,
            SendState.DATA_RECVD,
        ]

    def test_respects_stream_credit(self) -> None:
        stream = SendStream(0, max_stream_data=4)
        stream.write(b"abcdefgh")
        frame = stream.next_frame(max_bytes=100, connection_credit=100)
        assert frame is not None and frame.data == b"abcd"
        assert stream.next_frame(max_bytes=100, connection_credit=100) is None
        stream.on_max_stream_data(8)
        more = stream.next_frame(max_bytes=100, connection_credit=100)
        assert more is not None and more.data == b"efgh"

    def test_respects_connection_credit(self) -> None:
        stream = SendStream(0, max_stream_data=100)
        stream.write(b"abcdefgh")
        frame = stream.next_frame(max_bytes=100, connection_credit=2)
        assert frame is not None and frame.data == b"ab"

    def test_credit_never_shrinks(self) -> None:
        stream = SendStream(0, max_stream_data=10)
        stream.on_max_stream_data(5)
        assert stream.max_stream_data == 10

    def test_fin_only_frame(self) -> None:
        stream = SendStream(0, max_stream_data=100)
        stream.write(b"data")
        first = stream.next_frame(max_bytes=100, connection_credit=100)
        assert first is not None
        stream.write(b"", fin=True)
        fin_frame = stream.next_frame(max_bytes=100, connection_credit=100)
        assert fin_frame == Stream(stream_id=0, offset=4, data=b"", fin=True)

    def test_write_after_fin_rejected(self) -> None:
        stream = SendStream(0, max_stream_data=100)
        stream.write(b"x", fin=True)
        with pytest.raises(ValueError, match="fin"):
            stream.write(b"y")

    def test_duplicate_acks_tolerated(self) -> None:
        stream = SendStream(0, max_stream_data=100)
        stream.write(b"abc", fin=True)
        frame = stream.next_frame(max_bytes=100, connection_credit=100)
        assert frame is not None
        stream.on_frame_acked(frame)
        stream.on_frame_acked(frame)  # a retransmitted frame acked twice
        assert stream.state is SendState.DATA_RECVD


class TestRecvStream:
    def test_in_order_delivery(self) -> None:
        stream = RecvStream(0, max_stream_data=1000)
        stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"hello ", fin=False))
        assert stream.read() == b"hello "
        stream.on_stream_frame(Stream(stream_id=0, offset=6, data=b"world", fin=True))
        assert stream.read() == b"world"
        assert stream.state is RecvState.DATA_READ

    def test_out_of_order_reassembly(self) -> None:
        stream = RecvStream(0, max_stream_data=1000)
        stream.on_stream_frame(Stream(stream_id=0, offset=6, data=b"world", fin=True))
        states = [stream.state]
        assert stream.read() == b""
        stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"hello ", fin=False))
        states.append(stream.state)
        assert states == [RecvState.SIZE_KNOWN, RecvState.DATA_RECVD]
        assert stream.read() == b"hello world"
        assert stream.is_fully_read

    def test_overlapping_retransmission(self) -> None:
        stream = RecvStream(0, max_stream_data=1000)
        stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abcd", fin=False))
        stream.on_stream_frame(Stream(stream_id=0, offset=2, data=b"cdef", fin=False))
        assert stream.read() == b"abcdef"

    def test_flow_control_violation(self) -> None:
        stream = RecvStream(0, max_stream_data=4)
        with pytest.raises(StreamError) as excinfo:
            stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abcde", fin=False))
        assert excinfo.value.error_code == FLOW_CONTROL_ERROR

    def test_data_past_final_size(self) -> None:
        stream = RecvStream(0, max_stream_data=1000)
        stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abc", fin=True))
        with pytest.raises(StreamError) as excinfo:
            stream.on_stream_frame(Stream(stream_id=0, offset=3, data=b"d", fin=False))
        assert excinfo.value.error_code == FINAL_SIZE_ERROR

    def test_moving_final_size(self) -> None:
        stream = RecvStream(0, max_stream_data=1000)
        stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abc", fin=True))
        with pytest.raises(StreamError) as excinfo:
            stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"ab", fin=True))
        assert excinfo.value.error_code == FINAL_SIZE_ERROR

    def test_credit_update_after_half_window(self) -> None:
        stream = RecvStream(0, max_stream_data=10)
        assert stream.credit_update() is None
        stream.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abcdef", fin=False))
        stream.read()
        assert stream.credit_update() == 16
        assert stream.credit_update() is None  # advertisement now suffices


class TestStreamManager:
    def test_open_respects_peer_stream_limit(self) -> None:
        manager = make_manager(max_streams_bidi=1)
        manager.open_bidi()
        with pytest.raises(ValueError, match="limit"):
            manager.open_bidi()

    def test_peer_opens_stream_on_first_frame(self) -> None:
        manager = make_manager(is_client=False)
        recv = manager.on_stream_frame(Stream(stream_id=0, offset=0, data=b"hi", fin=True))
        assert recv.read() == b"hi"

    def test_peer_exceeding_our_stream_limit(self) -> None:
        local = FlowControlLimits(**{**GENEROUS.__dict__, "max_streams_bidi": 1})
        manager = StreamManager(is_client=False, local=local, peer=GENEROUS)
        manager.on_stream_frame(Stream(stream_id=0, offset=0, data=b"", fin=False))
        with pytest.raises(StreamError) as excinfo:
            manager.on_stream_frame(Stream(stream_id=4, offset=0, data=b"", fin=False))
        assert excinfo.value.error_code == STREAM_LIMIT_ERROR

    def test_frame_for_unopened_local_stream(self) -> None:
        manager = make_manager(is_client=True)
        with pytest.raises(StreamError) as excinfo:
            manager.on_stream_frame(Stream(stream_id=0, offset=0, data=b"x", fin=False))
        assert excinfo.value.error_code == STREAM_STATE_ERROR

    def test_connection_flow_control_enforced(self) -> None:
        local = FlowControlLimits(**{**GENEROUS.__dict__, "max_data": 10})
        manager = StreamManager(is_client=False, local=local, peer=GENEROUS)
        manager.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abcdef", fin=False))
        with pytest.raises(StreamError) as excinfo:
            manager.on_stream_frame(Stream(stream_id=4, offset=0, data=b"abcdef", fin=False))
        assert excinfo.value.error_code == FLOW_CONTROL_ERROR

    def test_connection_send_budget(self) -> None:
        manager = make_manager(max_data=5)
        stream_id = manager.open_bidi()
        manager.send_stream(stream_id).write(b"abcdefgh")
        frame = manager.next_frame(stream_id, max_bytes=100)
        assert frame is not None and frame.data == b"abcde"
        assert manager.next_frame(stream_id, max_bytes=100) is None
        manager.on_max_data(8)
        more = manager.next_frame(stream_id, max_bytes=100)
        assert more is not None and more.data == b"fgh"

    def test_max_data_update(self) -> None:
        local = FlowControlLimits(**{**GENEROUS.__dict__, "max_data": 10})
        manager = StreamManager(is_client=False, local=local, peer=GENEROUS)
        recv = manager.on_stream_frame(Stream(stream_id=0, offset=0, data=b"abcdef", fin=False))
        assert manager.max_data_update() is None  # received but not yet read
        recv.read()
        assert manager.max_data_update() == 16

    def test_uni_stream_from_peer_is_read_only(self) -> None:
        manager = make_manager(is_client=False)
        manager.on_stream_frame(Stream(stream_id=2, offset=0, data=b"u", fin=False))
        with pytest.raises(StreamError) as excinfo:
            manager.send_stream(2)
        assert excinfo.value.error_code == STREAM_STATE_ERROR
