"""Stream states, stream types, and flow control accounting.

RFC 9000 §2 (streams), §3 (stream states), §4 (flow control).

SendStream and RecvStream carry the §3.1/§3.2 state machines with the
spec's state names. StreamManager owns the connection-wide bookkeeping:
stream creation and ID sequencing (§2.1), stream-count limits (§4.6),
and connection-level flow control (§4.1), where received credit is
consumed by the highest received offset on each stream and sending
credit by total bytes sent.

The direction-dependent limit names follow §18.2 exactly, because they
are the classic confusion: ``initial_max_stream_data_bidi_local`` is
credit for streams the *sender of the parameter* opened, so each side
reads its sending credit from the other's mirrored field.

Retransmission needs no state here: a lost STREAM frame is resent
verbatim by the connection (same offset, same bytes), and acknowledgment
tracking tolerates overlap via RangeSet.
"""

import enum
from dataclasses import dataclass

from dsquic.frames import (
    FINAL_SIZE_ERROR,
    FLOW_CONTROL_ERROR,
    STREAM_LIMIT_ERROR,
    STREAM_STATE_ERROR,
    Stream,
)

STREAM_SERVER_INITIATED_BIT = 0x01  # §2.1, Table 1
STREAM_UNIDIRECTIONAL_BIT = 0x02


class StreamError(Exception):
    """A peer violated stream rules; carries the §20.1 error code."""

    def __init__(self, error_code: int, reason: str) -> None:
        super().__init__(reason)
        self.error_code = error_code


def is_client_initiated(stream_id: int) -> bool:
    return not stream_id & STREAM_SERVER_INITIATED_BIT


def is_bidirectional(stream_id: int) -> bool:
    return not stream_id & STREAM_UNIDIRECTIONAL_BIT


class RangeSet:
    """Merged, sorted, half-open [start, end) integer ranges.

    The bookkeeping shared by reassembly, acknowledgment tracking, and
    packet number records: add ranges in any order, query contiguous
    coverage.
    """

    def __init__(self) -> None:
        self._ranges: list[tuple[int, int]] = []

    def add(self, start: int, end: int) -> None:
        if start >= end:
            return
        merged: list[tuple[int, int]] = []
        for existing_start, existing_end in self._ranges:
            if existing_end < start or end < existing_start:
                merged.append((existing_start, existing_end))
            else:
                start = min(start, existing_start)
                end = max(end, existing_end)
        merged.append((start, end))
        merged.sort()
        self._ranges = merged

    @property
    def ranges(self) -> list[tuple[int, int]]:
        return list(self._ranges)

    def contiguous_from(self, start: int) -> int:
        """The end of unbroken coverage beginning at ``start``."""
        for existing_start, existing_end in self._ranges:
            if existing_start <= start < existing_end:
                return existing_end
        return start

    def covers(self, start: int, end: int) -> bool:
        return self.contiguous_from(start) >= end


class SendState(enum.Enum):
    """§3.1, Figure 2."""

    READY = enum.auto()
    SEND = enum.auto()
    DATA_SENT = enum.auto()
    DATA_RECVD = enum.auto()


class RecvState(enum.Enum):
    """§3.2, Figure 3."""

    RECV = enum.auto()
    SIZE_KNOWN = enum.auto()
    DATA_RECVD = enum.auto()
    DATA_READ = enum.auto()


class SendStream:
    """The sending half of one stream (§3.1). RESET_STREAM is out of the
    MVP; the reset states of Figure 2 arrive with it."""

    def __init__(self, stream_id: int, max_stream_data: int) -> None:
        self.stream_id = stream_id
        self.max_stream_data = max_stream_data  # peer's credit for us (§4.1)
        self.state = SendState.READY
        self._pending = bytearray()
        self._base_offset = 0  # stream offset of _pending[0]
        self._fin_queued = False
        self._fin_sent = False
        self._final_size: int | None = None
        self._acked = RangeSet()
        self._fin_acked = False

    def write(self, data: bytes, fin: bool = False) -> None:
        """Queue application data; ``fin`` closes the sending direction."""
        if self._fin_queued:
            raise ValueError("write after fin")
        self._pending += data
        if fin:
            self._fin_queued = True
            self._final_size = self._base_offset + len(self._pending)

    def next_frame(self, max_bytes: int, connection_credit: int) -> Stream | None:
        """Produce the next STREAM frame within all three budgets: frame
        size, stream credit (§4.1), and connection credit."""
        offset = self._base_offset
        budget = min(
            len(self._pending), max_bytes, self.max_stream_data - offset, connection_credit
        )
        budget = max(budget, 0)
        chunk = bytes(self._pending[:budget])
        fin_now = self._fin_queued and not self._fin_sent and budget == len(self._pending)
        if not chunk and not fin_now:
            return None
        del self._pending[:budget]
        self._base_offset += budget
        if fin_now:
            self._fin_sent = True
        # §3.1: Ready -> Send on the first frame; -> Data Sent with FIN.
        self.state = SendState.DATA_SENT if self._fin_sent else SendState.SEND
        return Stream(stream_id=self.stream_id, offset=offset, data=chunk, fin=fin_now)

    def on_max_stream_data(self, maximum: int) -> None:
        """§4.1: credit only ever increases; stale frames are ignored."""
        self.max_stream_data = max(self.max_stream_data, maximum)

    def on_frame_acked(self, frame: Stream) -> None:
        self._acked.add(frame.offset, frame.offset + len(frame.data))
        if frame.fin:
            self._fin_acked = True
        # §3.1: Data Sent -> Data Recvd once everything, FIN included, is acked.
        if (
            self._fin_acked
            and self._final_size is not None
            and self._acked.covers(0, self._final_size)
        ):
            self.state = SendState.DATA_RECVD

    def requeue(self, frame: Stream) -> None:
        """Put a lost frame's bytes back at the front of the queue (§13.3).

        The frame is resent at its original offset, so the queue base
        moves back; already-acked bytes may be resent, which is
        harmless (the receiver's RangeSet merges overlap).
        """
        if frame.data:
            self._pending[:0] = frame.data
            self._base_offset = min(self._base_offset, frame.offset)
        if frame.fin:
            self._fin_sent = False

    @property
    def has_pending(self) -> bool:
        return bool(self._pending) or (self._fin_queued and not self._fin_sent)


class RecvStream:
    """The receiving half of one stream (§3.2)."""

    def __init__(self, stream_id: int, max_stream_data: int) -> None:
        self.stream_id = stream_id
        self.max_stream_data = max_stream_data  # credit we advertised (§4.1)
        self._window = max_stream_data
        self.state = RecvState.RECV
        self._buffer = bytearray()
        self._received = RangeSet()
        self._read_offset = 0
        self.final_size: int | None = None
        self.highest_offset = 0

    def on_stream_frame(self, frame: Stream) -> None:
        end = frame.offset + len(frame.data)
        # §4.5: data past a known final size, or a moving final size, is fatal.
        if self.final_size is not None and (
            end > self.final_size or (frame.fin and end != self.final_size)
        ):
            raise StreamError(FINAL_SIZE_ERROR, f"stream {self.stream_id} final size violated")
        if frame.fin:
            if end < self.highest_offset:
                raise StreamError(FINAL_SIZE_ERROR, f"stream {self.stream_id} final size violated")
            self.final_size = end
        # §4.1: receiving beyond advertised credit is a connection error.
        if end > self.max_stream_data:
            raise StreamError(FLOW_CONTROL_ERROR, f"stream {self.stream_id} exceeded flow control")
        if len(self._buffer) < end:
            self._buffer.extend(bytes(end - len(self._buffer)))
        self._buffer[frame.offset : end] = frame.data
        self._received.add(frame.offset, end)
        self.highest_offset = max(self.highest_offset, end)
        # §3.2: Recv -> Size Known on FIN; -> Data Recvd when all bytes are in.
        if self.final_size is not None:
            self.state = RecvState.SIZE_KNOWN
            if self._received.covers(0, self.final_size):
                self.state = RecvState.DATA_RECVD

    def read(self) -> bytes:
        """Return contiguous in-order data; empty until more arrives."""
        readable_end = self._received.contiguous_from(self._read_offset)
        data = bytes(self._buffer[self._read_offset : readable_end])
        self._read_offset = readable_end
        if self.final_size is not None and self._read_offset == self.final_size:
            self.state = RecvState.DATA_READ  # §3.2: all data delivered
        return data

    def credit_update(self) -> int | None:
        """A new MAX_STREAM_DATA limit once half the window is consumed,
        or None while the current advertisement suffices (§4.2)."""
        if self.final_size is not None:
            return None  # no more data can arrive; no point extending credit
        if self.max_stream_data - self._read_offset >= self._window / 2:
            return None
        self.max_stream_data = self._read_offset + self._window
        return self.max_stream_data

    @property
    def is_fully_read(self) -> bool:
        return self.state is RecvState.DATA_READ

    @property
    def read_offset(self) -> int:
        """Bytes delivered to the application; consumed credit (§4.2)."""
        return self._read_offset


@dataclass(frozen=True)
class FlowControlLimits:
    """One side's advertised limits, named per §18.2 (initial_ dropped)."""

    max_data: int
    max_stream_data_bidi_local: int
    max_stream_data_bidi_remote: int
    max_stream_data_uni: int
    max_streams_bidi: int
    max_streams_uni: int


@dataclass
class _Half:
    send: SendStream | None = None
    recv: RecvStream | None = None


class StreamManager:
    """All streams of one connection plus the connection-level accounting.

    Sending credit consumed is total STREAM bytes sent (§4.1); receiving
    credit consumed is the sum of each stream's highest received offset.
    """

    def __init__(self, is_client: bool, local: FlowControlLimits, peer: FlowControlLimits) -> None:
        self._is_client = is_client
        self._local = local
        self._peer = peer
        self._streams: dict[int, _Half] = {}
        self._next_bidi_sequence = 0
        self.max_data = peer.max_data  # our sending allowance (§4.1)
        self.local_max_data = local.max_data  # what we advertised
        self._data_window = local.max_data
        self.data_sent = 0
        self.data_received = 0

    # --- opening and lookup ---------------------------------------------------

    def open_bidi(self) -> int:
        """Open the next locally-initiated bidirectional stream (§2.1)."""
        if self._next_bidi_sequence >= self._peer.max_streams_bidi:
            raise ValueError("peer's bidirectional stream limit reached")
        type_bits = 0 if self._is_client else STREAM_SERVER_INITIATED_BIT
        stream_id = (self._next_bidi_sequence << 2) | type_bits
        self._next_bidi_sequence += 1
        # §18.2: our sending credit on a stream we opened is the peer's
        # bidi_remote value; our receiving window is our own bidi_local.
        self._streams[stream_id] = _Half(
            send=SendStream(stream_id, self._peer.max_stream_data_bidi_remote),
            recv=RecvStream(stream_id, self._local.max_stream_data_bidi_local),
        )
        return stream_id

    def send_stream(self, stream_id: int) -> SendStream:
        half = self._streams[stream_id]
        if half.send is None:
            raise StreamError(STREAM_STATE_ERROR, f"stream {stream_id} is not writable")
        return half.send

    def recv_stream(self, stream_id: int) -> RecvStream:
        half = self._streams[stream_id]
        if half.recv is None:
            raise StreamError(STREAM_STATE_ERROR, f"stream {stream_id} is not readable")
        return half.recv

    def _create_peer_initiated(self, stream_id: int) -> _Half:
        local_initiated = is_client_initiated(stream_id) == self._is_client
        if local_initiated:
            # §19.8: STREAM for a locally-initiated stream never opened.
            raise StreamError(STREAM_STATE_ERROR, f"stream {stream_id} was never opened")
        sequence = stream_id >> 2
        if is_bidirectional(stream_id):
            if sequence >= self._local.max_streams_bidi:
                raise StreamError(STREAM_LIMIT_ERROR, f"stream {stream_id} exceeds stream limit")
            return _Half(
                send=SendStream(stream_id, self._peer.max_stream_data_bidi_local),
                recv=RecvStream(stream_id, self._local.max_stream_data_bidi_remote),
            )
        if sequence >= self._local.max_streams_uni:
            raise StreamError(STREAM_LIMIT_ERROR, f"stream {stream_id} exceeds stream limit")
        return _Half(send=None, recv=RecvStream(stream_id, self._local.max_stream_data_uni))

    # --- frame handling -------------------------------------------------------

    def on_stream_frame(self, frame: Stream) -> RecvStream:
        """Route an incoming STREAM frame, creating the stream if the peer
        just opened it, and charge connection-level flow control (§4.1)."""
        half = self._streams.get(frame.stream_id)
        if half is None:
            half = self._create_peer_initiated(frame.stream_id)
            self._streams[frame.stream_id] = half
        if half.recv is None:
            raise StreamError(STREAM_STATE_ERROR, f"stream {frame.stream_id} is send-only")
        before = half.recv.highest_offset
        half.recv.on_stream_frame(frame)
        self.data_received += half.recv.highest_offset - before
        if self.data_received > self.local_max_data:
            raise StreamError(FLOW_CONTROL_ERROR, "connection flow control exceeded")
        return half.recv

    def next_frame(self, stream_id: int, max_bytes: int) -> Stream | None:
        """Produce a STREAM frame within the connection send budget."""
        connection_credit = self.max_data - self.data_sent
        frame = self.send_stream(stream_id).next_frame(max_bytes, connection_credit)
        if frame is not None:
            self.data_sent += len(frame.data)
        return frame

    def writable_streams(self) -> list[int]:
        """Stream IDs with data or a FIN waiting to be sent."""
        return [
            stream_id
            for stream_id, half in self._streams.items()
            if half.send is not None and half.send.has_pending
        ]

    def on_max_data(self, maximum: int) -> None:
        self.max_data = max(self.max_data, maximum)

    def max_data_update(self) -> int | None:
        """A new MAX_DATA limit when half the connection window is consumed
        (§4.2), or None while the advertisement suffices."""
        consumed = sum(
            half.recv.read_offset for half in self._streams.values() if half.recv is not None
        )
        if self.local_max_data - consumed >= self._data_window / 2:
            return None
        self.local_max_data = consumed + self._data_window
        return self.local_max_data
