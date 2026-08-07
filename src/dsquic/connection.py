"""Connection state machine: the sans-IO composition root.

RFC 9000 §5 (connections), §7 (handshake), §8 (address validation),
§10 (termination), §12 (packets and frames), §13 (packetization and
reliability), §17.2 (coalesced packets); RFC 9001 §4 (TLS carriage) and
§4.9 (key discard).

A Connection consumes received datagrams and clock readings and produces
datagrams to send, timer deadlines, and application events. The caller
owns sockets and the clock; nothing here performs I/O. Sending is
transport-agnostic on purpose (design.md appendix, MASQUE nesting):
datagrams carry an opaque destination, so an inner connection can be
tunnelled through an outer one.

Packet numbers, ACK state, and CRYPTO reassembly exist once per packet
number space (Initial, Handshake, Application), keyed by
tls.EncryptionLevel.

Key update is implemented (RFC 9001 §6); Version Negotiation is answered
statelessly in packet.py, before any connection exists. Not in this MVP:
Retry, migration, stateless reset, NEW_CONNECTION_ID issuance, and
0-RTT. Received frames for those features are parsed and ignored where
the spec permits.
"""

import enum
import math
import os
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from cryptography.exceptions import InvalidTag

from dsquic import frames, qlog
from dsquic.buffer import BufferReadError
from dsquic.congestion import CongestionController
from dsquic.frames import (
    Ack,
    ConnectionClose,
    Crypto,
    Frame,
    FrameParseError,
    HandshakeDone,
    MaxData,
    MaxStreamData,
    MaxStreams,
    Ping,
    Stream,
    StreamsBlocked,
    is_ack_eliciting,
    parse_frames,
)
from dsquic.new_reno import NewReno
from dsquic.packet import (
    MAX_PACKET_NUMBER,
    QUIC_V1,
    HeaderParseError,
    LongHeaderTemplate,
    PacketType,
    UnsupportedVersion,
    build_long_header,
    encode_packet_number,
    parse_long_header,
    parse_short_header,
)
from dsquic.protection import (
    AEAD_TAG_LENGTH,
    KEY_PHASE_BIT,
    MAX_PN_LENGTH,
    SAMPLE_LENGTH,
    PacketKeys,
    UnprotectedHeader,
    decrypt_payload,
    derive_initial_secrets,
    derive_packet_keys,
    next_generation,
    protect,
    remove_header_protection,
)
from dsquic.qlog import QlogTrace
from dsquic.recovery import AckOfUnsentPacket, LossDetection, SentPacket
from dsquic.retry import RetryContext, is_retry, parse_retry
from dsquic.streams import (
    FlowControlLimits,
    RangeSet,
    RecvStream,
    StreamError,
    StreamLimitReached,
    StreamManager,
)
from dsquic.tls import (
    ClientConfig,
    Direction,
    EncryptionLevel,
    HandshakeComplete,
    SecretAvailable,
    SendData,
    ServerConfig,
    TlsAlert,
    TlsClient,
    TlsServer,
)
from dsquic.transport_parameters import TransportParameters, decode_transport_parameters

MIN_INITIAL_DATAGRAM = 1200  # §14.1: a client Initial datagram floor
DEFAULT_MAX_DATAGRAM_SIZE = 1200  # conservative default; per-connection config
CONNECTION_ID_LENGTH = 8
AMPLIFICATION_FACTOR = 3  # §8.1: server send limit before address validation
MAX_ACK_RANGES = 32  # bound the ACK frames we build
MAX_CRYPTO_BUFFER = 65536  # §7.5: a receiver may bound CRYPTO reassembly
MAX_STREAMS_LIMIT = 1 << 60  # §4.6: a larger count has no expressible stream ID
PROBE_PACKETS = 2  # §6.2.4: up to two datagrams per PTO
# RFC 9002 §7.7: bursts are limited to the initial congestion window,
# which is ten datagrams (B.1).
PACING_BURST_DATAGRAMS = 10

LEVEL_TO_PACKET_TYPE = {
    EncryptionLevel.INITIAL: PacketType.INITIAL,
    EncryptionLevel.HANDSHAKE: PacketType.HANDSHAKE,
}

# qlog packet type names (events §5.5).
_QLOG_PACKET_TYPE = {
    EncryptionLevel.INITIAL: "initial",
    EncryptionLevel.HANDSHAKE: "handshake",
    EncryptionLevel.ONE_RTT: "1RTT",
}


class ConnectionError_(Exception):
    """A transport error that closes the connection (§20.1)."""

    def __init__(self, error_code: int, reason: str, frame_type: int | None = 0) -> None:
        super().__init__(reason)
        self.error_code = error_code
        self.reason = reason
        self.frame_type = frame_type


class ConnectionState(enum.Enum):
    """§10: the lifecycle this MVP models."""

    HANDSHAKING = enum.auto()
    CONNECTED = enum.auto()
    CLOSING = enum.auto()
    DRAINING = enum.auto()
    TERMINATED = enum.auto()


@dataclass(frozen=True)
class OutgoingDatagram:
    """One datagram to send (design.md §4.7).

    ``destination`` is opaque to the core: a socket address for a plain
    endpoint, a tunnel handle for a nested connection. ``ecn`` is
    carried from day one; ``segment_size`` is a GSO hint.
    """

    data: bytes
    destination: object
    ecn: int = 0
    txtime: int | None = None
    segment_size: int | None = None


@dataclass(frozen=True)
class StreamDataReceived:
    stream_id: int
    data: bytes
    end_stream: bool


@dataclass(frozen=True)
class HandshakeCompleted:
    """RFC 9001 §4.1.1: the TLS handshake is complete, so 1-RTT packets
    may carry application data. This is the gate for sending requests,
    not confirmation: a client that waits for HANDSHAKE_DONE waits on a
    frame that can be lost."""

    alpn: str


@dataclass(frozen=True)
class HandshakeConfirmed:
    """RFC 9001 §4.1.2: confirmed at the server on completion, at the
    client on HANDSHAKE_DONE. Governs discarding Handshake keys (§4.9.2)
    and initiating a key update (§6.1), not application data."""

    alpn: str


@dataclass(frozen=True)
class ConnectionTerminated:
    error_code: int
    reason: str


ConnectionEvent = (
    StreamDataReceived | HandshakeCompleted | HandshakeConfirmed | ConnectionTerminated
)


@dataclass
class _Space:
    """One packet number space (§12.3)."""

    keys_send: PacketKeys | None = None
    keys_recv: PacketKeys | None = None
    next_packet_number: int = 0
    largest_received: int = -1
    received: RangeSet = field(default_factory=RangeSet)
    ack_eliciting_pending: bool = False
    crypto_offset_sent: int = 0
    crypto_pending: bytearray = field(default_factory=bytearray)
    # §13.3: lost CRYPTO frames, resent verbatim. Kept apart from
    # crypto_pending, whose first byte is at crypto_offset_sent.
    crypto_retransmit: list[Crypto] = field(default_factory=list[Crypto])
    # Receive-side CRYPTO reassembly (§19.6). Deliberately separate from
    # stream reassembly: CRYPTO has offsets but no stream ID, no flow
    # control, and one ordered byte stream per encryption level.
    crypto_received: RangeSet = field(default_factory=RangeSet)
    crypto_buffer: bytearray = field(default_factory=bytearray)
    crypto_read_offset: int = 0
    discarded: bool = False
    # Key update state (§6). Only 1-RTT keys rotate, so these stay at
    # their defaults in the Initial and Handshake spaces. The next
    # receive keys are derived in advance so that answering a peer's
    # update costs no more than an ordinary packet, which is what §6.3
    # asks for to avoid a timing signal on the key phase bit.
    key_phase: bool = False
    secret_send: bytes = b""
    secret_recv_next: bytes = b""
    keys_recv_next: PacketKeys | None = None
    keys_recv_previous: PacketKeys | None = None
    keys_recv_previous_expiry: float = 0.0
    # §6.5: the lowest packet number received in the current phase, or
    # None when nothing has arrived in it yet. Until something does,
    # every packet carrying the other phase bit belongs to the previous
    # phase, which is the state an endpoint is in right after starting
    # an update of its own.
    key_phase_first: int | None = 0
    key_phase_send_first: int = 0  # §6.1: gates the next update


def _short_header_first_byte(space: _Space, packet_number_length: int) -> int:
    """§17.3.1: header form, fixed bit, key phase, packet number length."""
    first = 0x40 | (packet_number_length - 1)
    if space.key_phase:
        first |= KEY_PHASE_BIT
    return first


@dataclass(frozen=True)
class ConnectionConfig:
    """Per-connection configuration; no module-level MTU constants
    (design.md appendix, MASQUE nesting constraint 2)."""

    max_datagram_size: int = DEFAULT_MAX_DATAGRAM_SIZE
    transport_parameters: TransportParameters = field(
        default_factory=lambda: TransportParameters(
            max_idle_timeout_ms=30_000,
            initial_max_data=1_048_576,
            initial_max_stream_data_bidi_local=262_144,
            initial_max_stream_data_bidi_remote=262_144,
            initial_max_stream_data_uni=262_144,
            initial_max_streams_bidi=16,
            initial_max_streams_uni=16,
        )
    )
    # §6.1: packets sent in a phase before starting the next one, or
    # None never to initiate. Whether to update is protocol; how often
    # is policy, so it is configured rather than decided here.
    key_update_interval: int | None = None
    # Set by a server that answered this connection's first Initial with
    # a Retry (§8.1.2); None on every other connection.
    retry: RetryContext | None = None
    keylog: Callable[[str], None] | None = None
    # Opens a trace, given the group ID, the role, and the reference
    # clock reading. A factory because a server learns the group ID from
    # the client's first Initial (§7.2).
    qlog: Callable[[bytes, bool, float], QlogTrace | None] | None = None


class Connection:
    """One QUIC connection, sans-IO (§5).

    Feed it ``datagram_received`` and ``handle_timer``; drain
    ``datagrams_to_send`` and ``take_events``. ``next_timer`` reports
    when the caller must come back.
    """

    def __init__(
        self,
        *,
        is_client: bool,
        client_config: ClientConfig | None = None,
        server_config: ServerConfig | None = None,
        config: ConnectionConfig | None = None,
        destination: object = None,
    ) -> None:
        self.is_client = is_client
        self.config = config if config is not None else ConnectionConfig()
        self.state = ConnectionState.HANDSHAKING
        self.destination = destination
        self.alpn = ""

        self.host_cid = os.urandom(CONNECTION_ID_LENGTH)
        self.peer_cid = os.urandom(CONNECTION_ID_LENGTH) if is_client else b""
        self._initial_dcid = self.peer_cid  # §7.3: fixes the Initial keys
        self._server_config = server_config

        # §17.2.5: the token a client attaches to later Initials, the
        # Retry's source CID, and, for a server that sent a Retry, the
        # original destination CID recovered from the token (§8.1.2).
        # Set before the parameters are built, which reads them.
        self._retry_token = b""
        self._retry_source_cid = self.config.retry.source_cid if self.config.retry else None
        self._original_dcid = (
            self.config.retry.original_destination_cid if self.config.retry else None
        )
        self._local_parameters = self._parameters_for(self._initial_dcid)
        self.peer_parameters: TransportParameters | None = None

        self.tls: TlsClient | TlsServer | None = None
        if is_client:
            if client_config is None:
                raise ValueError("client_config is required for a client connection")
            self.tls = TlsClient(
                replace(client_config, transport_parameters=self._local_parameters.encode()),
                keylog=self.config.keylog,
            )
        elif server_config is None:
            raise ValueError("server_config is required for a server connection")

        self._spaces = {level: _Space() for level in EncryptionLevel}
        controller: CongestionController = NewReno(self.config.max_datagram_size)
        self.recovery = LossDetection(controller, is_client=is_client)
        self.streams: StreamManager | None = None
        self._events: list[ConnectionEvent] = []
        self._pending: list[OutgoingDatagram] = []
        self._control_frames: list[Frame] = []
        # Probes owed per space after a PTO (§6.2.4). Counted per level
        # because a probe must go out at the level whose timer expired.
        self._probes_pending: dict[EncryptionLevel, int] = dict.fromkeys(EncryptionLevel, 0)
        self._handshake_done_pending = False
        # §17.2.5: a client attaches the Retry's token to every later
        # Initial and remembers the Retry's source CID, which §7.3 makes
        # the server echo. Empty until a Retry arrives.
        # Pacer state (§7.7): bytes of credit, when it was last filled,
        # and when it will next hold enough for a datagram.
        self._pacing_credit = 0.0
        self._pacing_updated: float | None = None
        self._pacing_deadline: float | None = None
        self._close_frame: ConnectionClose | None = None
        self._close_sent = False
        self._bytes_received = 0
        self._bytes_sent = 0
        self._address_validated = is_client
        self._idle_started: float | None = None
        self._qlog: QlogTrace | None = None
        self._closing_deadline: float | None = None
        self._peer_cid_confirmed = not is_client  # §7.2
        self._largest_time_received: dict[EncryptionLevel, float] = {}

        if is_client:
            self._install_initial_keys(self._initial_dcid)

    # --- key management (RFC 9001 §4.1, §4.9) --------------------------------

    def _install_initial_keys(self, dcid: bytes) -> None:
        secrets = derive_initial_secrets(dcid)
        space = self._spaces[EncryptionLevel.INITIAL]
        client_keys = derive_packet_keys(secrets.client)
        server_keys = derive_packet_keys(secrets.server)
        space.keys_send = client_keys if self.is_client else server_keys
        space.keys_recv = server_keys if self.is_client else client_keys

    def _on_secret(self, event: SecretAvailable) -> None:
        space = self._spaces[event.level]
        keys = derive_packet_keys(event.secret)
        ours = Direction.CLIENT if self.is_client else Direction.SERVER
        if event.direction is ours:
            space.keys_send = keys
            space.secret_send = event.secret
        else:
            space.keys_recv = keys
            if event.level is EncryptionLevel.ONE_RTT:
                space.secret_recv_next, space.keys_recv_next = next_generation(event.secret, keys)

    def _decrypt(
        self, space: _Space, level: EncryptionLevel, packet: bytes, pn_offset: int, now: float
    ) -> tuple[int, bytes] | None:
        """Unprotect one packet, or None if it does not authenticate.

        Header protection comes off first because its key is the same in
        every key generation (§6); the key phase and packet number it
        recovers are what select the packet protection keys.
        """
        assert space.keys_recv is not None
        try:
            unprotected = remove_header_protection(
                space.keys_recv.hp, packet, pn_offset, space.largest_received
            )
            keys, updating = self._receive_keys(space, level, unprotected, now)
            payload = decrypt_payload(keys, unprotected)
        except (InvalidTag, ValueError):
            return None
        if updating:
            # §6.2: only a packet that authenticates proves the peer
            # updated, so this follows the decryption rather than the key
            # selection. Rotating here, before the packet's frames are
            # handled, is what §6.2 requires: the acknowledgment for this
            # packet goes out in the new phase.
            self._rotate_keys(space, now)
        if level is EncryptionLevel.ONE_RTT:
            self._note_key_phase(space, unprotected)
        return unprotected.packet_number, payload

    def _note_key_phase(self, space: _Space, unprotected: UnprotectedHeader) -> None:
        """§6.5: record the lowest packet number seen in the current key
        phase, which is the boundary that sends earlier packets to the
        previous keys."""
        if unprotected.key_phase != space.key_phase:
            return
        if space.key_phase_first is None or unprotected.packet_number < space.key_phase_first:
            space.key_phase_first = unprotected.packet_number

    def _receive_keys(
        self, space: _Space, level: EncryptionLevel, unprotected: UnprotectedHeader, now: float
    ) -> tuple[PacketKeys, bool]:
        """Choose the keys for a received packet (§6.5).

        Returns the keys and whether using them would mean the peer has
        started a key update. Only 1-RTT keys rotate; every other level
        has exactly one key set. Within 1-RTT the key phase bit selects
        between generations, and when it differs from ours the packet
        number breaks the tie: below this phase's first packet number it
        is a reordered packet from the previous phase, above it the peer
        has updated.
        """
        assert space.keys_recv is not None
        if level is not EncryptionLevel.ONE_RTT or unprotected.key_phase == space.key_phase:
            return space.keys_recv, False
        if space.key_phase_first is None or unprotected.packet_number < space.key_phase_first:
            if space.keys_recv_previous is None or now > space.keys_recv_previous_expiry:
                # §6.5: old keys are gone, so the packet is undecryptable
                # rather than misdecrypted. Current keys will fail the
                # AEAD check, which is the drop this needs.
                return space.keys_recv, False
            return space.keys_recv_previous, False
        if space.keys_recv_next is None or not self.recovery.handshake_confirmed:
            # §6.1: the peer cannot legitimately update before the
            # handshake is confirmed, so do not follow it there.
            return space.keys_recv, False
        return space.keys_recv_next, True

    def _rotate_keys(self, space: _Space, now: float) -> None:
        """Advance both directions into the next key phase (§6.1).

        The two directions always move together, whether this endpoint
        started the update or is following the peer's.
        """
        assert space.keys_recv_next is not None
        assert space.keys_send is not None
        current_secret = space.secret_recv_next
        space.keys_recv_previous = space.keys_recv
        # §6.5: reordered packets from the old phase stay decryptable for
        # three PTOs, and no longer.
        space.keys_recv_previous_expiry = now + 3 * self.recovery.pto()
        space.keys_recv = space.keys_recv_next
        space.secret_recv_next, space.keys_recv_next = next_generation(
            current_secret, space.keys_recv
        )
        space.secret_send, space.keys_send = next_generation(space.secret_send, space.keys_send)
        space.key_phase = not space.key_phase
        space.key_phase_send_first = space.next_packet_number
        # Nothing has been received in the new phase yet, so packets
        # still in flight from the peer belong to the old one (§6.5).
        space.key_phase_first = None
        self._log(now, qlog.KEY_UPDATED, {"key_type": "1RTT", "key_phase": int(space.key_phase)})

    def _maybe_update_keys(self, now: float) -> None:
        """Start the next phase once the configured interval of packets
        has been sent in this one (§6.1).

        An update refused by §6.1's preconditions is simply retried on
        the next send.
        """
        interval = self.config.key_update_interval
        if interval is None:
            return
        space = self._spaces[EncryptionLevel.ONE_RTT]
        if space.next_packet_number - space.key_phase_send_first >= interval:
            self.initiate_key_update(now)

    def initiate_key_update(self, now: float) -> bool:
        """Start the next key phase, reporting whether it started (§6.1).

        §6.1 allows an update only after the handshake is confirmed and
        only once the peer has acknowledged a packet sent in the current
        phase, which stops an endpoint from updating faster than its
        peer can follow.
        """
        space = self._spaces[EncryptionLevel.ONE_RTT]
        if space.keys_recv_next is None or not self.recovery.handshake_confirmed:
            return False
        if self.recovery.largest_acked(EncryptionLevel.ONE_RTT) < space.key_phase_send_first:
            return False
        self._rotate_keys(space, now)
        return True

    def _discard_space(self, level: EncryptionLevel, now: float) -> None:
        """§4.9: drop a level's keys and its recovery state."""
        space = self._spaces[level]
        if space.discarded:
            return
        self._log(now, qlog.KEY_DISCARDED, {"key_type": _QLOG_PACKET_TYPE[level]})
        space.discarded = True
        space.keys_send = None
        space.keys_recv = None
        space.crypto_pending.clear()
        space.crypto_retransmit.clear()
        self.recovery.discard_space(level)

    # --- receive path ---------------------------------------------------------

    def datagram_received(self, data: bytes, now: float, source: object = None) -> None:
        """Process one received datagram (§12.2: coalesced packets).

        A transport error detected while processing does not propagate:
        per §10.2 it becomes a CONNECTION_CLOSE to the peer and a
        ConnectionTerminated event to the application.
        """
        try:
            self._datagram_received(data, now, source)
        except ConnectionError_ as exc:
            self.close(error_code=exc.error_code, reason=exc.reason, frame_type=exc.frame_type)
            self._log(
                now,
                qlog.CONNECTION_CLOSED,
                {"initiator": "local", "error_code": exc.error_code, "reason": exc.reason},
            )
            self._events.append(ConnectionTerminated(error_code=exc.error_code, reason=exc.reason))

    def _datagram_received(self, data: bytes, now: float, source: object) -> None:
        if self.state in (ConnectionState.TERMINATED, ConnectionState.DRAINING):
            return
        # §8.1: an Initial validates nothing by itself, but every received
        # byte grows the server's send budget. Validation itself happens
        # on the first Handshake packet, in _process_packet.
        self._bytes_received += len(data)
        if self.destination is None and source is not None:
            self.destination = source
        offset = 0
        while offset < len(data):
            consumed = self._process_packet(data[offset:], now)
            if consumed <= 0:
                break
            offset += consumed
        self._arm_idle_timer(now)

    def _locate_packet(
        self, data: bytes, now: float
    ) -> tuple[EncryptionLevel, int, bytes, int] | None:
        """Find one packet at the front of a datagram (§12.2).

        Returns its level, packet number offset, bytes, and where the
        next packet begins, or None when nothing further is parseable.
        Connection ID bookkeeping that depends only on the header
        happens here, before any key is involved.
        """
        if not data[0] & 0x80:
            # §17.3: a short header packet runs to the end of the datagram.
            pn_offset = parse_short_header(data, len(self.host_cid)).pn_offset
            return EncryptionLevel.ONE_RTT, pn_offset, data, len(data)
        if self.is_client and is_retry(data):
            self._handle_retry(data, now)
            return None
        long_header = parse_long_header(data)
        level = {
            PacketType.INITIAL: EncryptionLevel.INITIAL,
            PacketType.HANDSHAKE: EncryptionLevel.HANDSHAKE,
        }.get(long_header.packet_type)
        if level is None:
            return None  # 0-RTT: not supported, stop parsing this datagram
        if not self.is_client and level is EncryptionLevel.INITIAL:
            self._open_qlog(long_header.destination_cid, now)
            self._adopt_client_initial(long_header.destination_cid, long_header.source_cid)
        elif self.is_client and not self._peer_cid_confirmed:
            # §7.2: the client switches to the server's chosen source
            # connection ID from its first server packet.
            self.peer_cid = long_header.source_cid
            self._peer_cid_confirmed = True
        packet_end = long_header.pn_offset + long_header.length
        return level, long_header.pn_offset, data[:packet_end], packet_end

    def _handle_retry(self, data: bytes, now: float) -> None:
        """§17.2.5.2: start the handshake again with the server's token.

        At most one Retry is accepted per connection attempt, and none
        once the server has sent a packet the client could read: both
        would otherwise let an off-path attacker restart a handshake at
        will. A Retry whose integrity tag fails is discarded, which is
        the check that makes the token unforgeable (RFC 9001 §5.8).
        """
        if self._retry_token or self._peer_cid_confirmed:
            self._drop(now, qlog.DROP_UNSUPPORTED, len(data))
            return
        try:
            packet = parse_retry(data, self._initial_dcid)
        except (HeaderParseError, BufferReadError, UnsupportedVersion):
            self._drop(now, qlog.DROP_INVALID, len(data))
            return
        if not packet.token:
            self._drop(now, qlog.DROP_INVALID, len(data))  # §17.2.5.2: empty is invalid
            return
        self._retry_token = packet.token
        self._retry_source_cid = packet.source_cid
        self.peer_cid = packet.source_cid
        # RFC 9001 §5.2: Initial keys follow the Destination Connection
        # ID, which the Retry has just changed.
        self._install_initial_keys(packet.source_cid)
        # §17.2.5.3: packet numbers do not reset, so the first flight is
        # resent under new numbers. Its old packets can never be
        # acknowledged, since the server now holds different Initial keys.
        space = self._spaces[EncryptionLevel.INITIAL]
        for sent in self.recovery.restart_space(EncryptionLevel.INITIAL):
            for frame in sent.frames:
                if isinstance(frame, Crypto):
                    space.crypto_retransmit.append(frame)
        self._log(now, qlog.PACKET_RECEIVED, {"header": {"packet_type": "retry"}})

    # --- qlog ------------------------------------------------------------------

    def _open_qlog(self, group_id: bytes, now: float) -> None:
        """Start a trace, keyed by the original destination CID."""
        if self._qlog is not None or self.config.qlog is None:
            return
        self._qlog = self.config.qlog(group_id, self.is_client, now)
        self._log(now, qlog.CONNECTION_STARTED, {"dst_cid": group_id.hex()})

    def _log(self, now: float, name: str, data: dict[str, object]) -> None:
        """Record one qlog event, when the caller asked for a trace."""
        if self._qlog is not None:
            self._qlog.log(now, name, data)

    def _log_recovery_metrics(self, now: float) -> None:
        """Record congestion window, bytes in flight, and RTT (§7.2)."""
        controller = self.recovery.controller
        self._log(
            now,
            qlog.RECOVERY_METRICS_UPDATED,
            {
                "congestion_window": controller.congestion_window,
                "bytes_in_flight": controller.bytes_in_flight,
                "smoothed_rtt": self.recovery.rtt.smoothed * 1000,
                "rtt_variance": self.recovery.rtt.rttvar * 1000,
                "latest_rtt": self.recovery.rtt.latest * 1000,
                "pto_count": self.recovery.pto_count,
            },
        )

    def _drop(
        self,
        now: float,
        trigger: str,
        length: int,
        level: EncryptionLevel | None = None,
        packet_number: int | None = None,
    ) -> None:
        """Record a discarded packet and why (events §5.7)."""
        if self._qlog is None:
            return
        header: dict[str, object] = {}
        if level is not None:
            header["packet_type"] = _QLOG_PACKET_TYPE[level]
        if packet_number is not None:
            header["packet_number"] = packet_number
        data: dict[str, object] = {"trigger": trigger, "raw": {"length": length}}
        if header:
            data["header"] = header
        self._qlog.log(now, qlog.PACKET_DROPPED, data)

    def _process_packet(self, data: bytes, now: float) -> int:
        """Unprotect and handle one packet; returns bytes consumed."""
        try:
            located = self._locate_packet(data, now)
        except (HeaderParseError, BufferReadError, UnsupportedVersion):
            located = None
        if located is None:
            # §5.2: undecodable packets are discarded silently, and an
            # unsupported type ends the datagram, since without its
            # length the next packet cannot be found.
            self._drop(now, qlog.DROP_INVALID, len(data))
            return 0
        level, pn_offset, packet, packet_end = located

        space = self._spaces[level]
        if space.keys_recv is None or space.discarded:
            # No keys yet, or the space is retired: drop this packet and
            # keep parsing the datagram.
            self._drop(now, qlog.DROP_KEY_UNAVAILABLE, packet_end, level)
            return packet_end
        if level is EncryptionLevel.ONE_RTT and self.state is ConnectionState.HANDSHAKING:
            # RFC 9001 §5.7: 1-RTT packets are neither decrypted nor
            # processed before the handshake completes, and are not
            # acknowledged, since an acknowledgement asserts the frames
            # were handled. The peer retransmits.
            self._drop(now, qlog.DROP_GENERAL, packet_end, level)
            return packet_end
        decrypted = self._decrypt(space, level, packet, pn_offset, now)
        if decrypted is None:
            # §12.2: failed decryption is not fatal.
            self._drop(now, qlog.DROP_DECRYPTION_FAILURE, packet_end, level)
            return packet_end
        packet_number, payload = decrypted
        if space.received.covers(packet_number, packet_number + 1):
            self._drop(now, qlog.DROP_DUPLICATE, packet_end, level, packet_number)
            return packet_end
        # Logged in _handle_payload, once the frames it carries are parsed.
        received: dict[str, object] = {
            "header": {"packet_type": _QLOG_PACKET_TYPE[level], "packet_number": packet_number},
            "raw": {"length": packet_end},
        }
        space.received.add(packet_number, packet_number + 1)
        if packet_number > space.largest_received:
            space.largest_received = packet_number
            self._largest_time_received[level] = now
        if not self.is_client and level is EncryptionLevel.HANDSHAKE:
            # RFC 9001 §4.9.1: the server discards Initial keys on the
            # first Handshake packet it processes. RFC 9000 §8.1: that
            # packet also validates the client's address, since Handshake
            # keys prove the client processed the server's Initial.
            self._discard_space(EncryptionLevel.INITIAL, now)
            self._address_validated = True
        self._handle_payload(level, payload, now, received)
        return packet_end

    def _parameters_for(self, initial_dcid: bytes) -> TransportParameters:
        """Our transport parameters, including the §7.3 connection ID
        authentication fields.

        After a Retry the client's Initial names the connection ID the
        Retry chose, so the original one comes from the token instead;
        §7.3 has the server echo both.
        """
        parameters = replace(
            self.config.transport_parameters, initial_source_connection_id=self.host_cid
        )
        if self.is_client:
            return parameters
        original = self._original_dcid if self._original_dcid is not None else initial_dcid
        return replace(
            parameters,
            original_destination_connection_id=original,
            retry_source_connection_id=self._retry_source_cid,
        )

    def _adopt_client_initial(self, dcid: bytes, scid: bytes) -> None:
        """A server learns both connection IDs from the client's first
        Initial (§7.2) and only then can build its TLS state, since the
        transport parameters must echo the destination CID (§7.3)."""
        if self.tls is None:
            assert self._server_config is not None
            self._initial_dcid = dcid
            self._local_parameters = self._parameters_for(dcid)
            self.tls = TlsServer(
                replace(
                    self._server_config,
                    transport_parameters=self._local_parameters.encode(),
                ),
                keylog=self.config.keylog,
            )
            self._install_initial_keys(dcid)
        if not self.peer_cid:
            self.peer_cid = scid

    def _handle_payload(
        self, level: EncryptionLevel, payload: bytes, now: float, received: dict[str, object]
    ) -> None:
        try:
            parsed = parse_frames(payload)
        except (FrameParseError, BufferReadError) as exc:
            raise ConnectionError_(frames.FRAME_ENCODING_ERROR, str(exc)) from exc
        received["frames"] = [qlog.frame_detail(frame) for frame in parsed]
        self._log(now, qlog.PACKET_RECEIVED, received)
        space = self._spaces[level]
        for frame in parsed:
            if is_ack_eliciting(frame):
                space.ack_eliciting_pending = True
            self._handle_frame(level, frame, now)

    def _handle_frame(self, level: EncryptionLevel, frame: Frame, now: float) -> None:
        if isinstance(frame, Ack):
            self._handle_ack(level, frame, now)
        elif isinstance(frame, Crypto):
            self._handle_crypto(level, frame, now)
        elif isinstance(frame, Stream):
            self._handle_stream(frame)
        elif isinstance(frame, MaxData | MaxStreamData | MaxStreams):
            self._handle_limit(frame)
        elif isinstance(frame, HandshakeDone):
            # §7.3: the client confirms the handshake on HANDSHAKE_DONE.
            if not self.is_client:
                raise ConnectionError_(frames.PROTOCOL_VIOLATION, "client sent HANDSHAKE_DONE")
            self._confirm_handshake(now)
        elif isinstance(frame, ConnectionClose):
            self._on_connection_close(frame, now)
        # Frames for deferred features (NEW_CONNECTION_ID, PATH_CHALLENGE,
        # NEW_TOKEN, DATAGRAM, blocked frames) are accepted and ignored.

    def _handle_limit(self, frame: MaxData | MaxStreamData | MaxStreams) -> None:
        """A peer raising one of our sending allowances (§4.1, §4.6)."""
        if isinstance(frame, MaxStreams) and frame.maximum > MAX_STREAMS_LIMIT:
            # §4.6: a larger count has no stream ID expressible as a varint (§16).
            raise ConnectionError_(
                frames.FRAME_ENCODING_ERROR, f"MAX_STREAMS {frame.maximum} exceeds 2^60"
            )
        if self.streams is None:
            return
        if isinstance(frame, MaxData):
            self.streams.on_max_data(frame.maximum)
        elif isinstance(frame, MaxStreamData):
            self.streams.send_stream(frame.stream_id).on_max_stream_data(frame.maximum)
        else:
            self.streams.on_max_streams(frame.maximum, frame.bidirectional)

    def _handle_ack(self, level: EncryptionLevel, frame: Ack, now: float) -> None:
        exponent = (
            self.peer_parameters.ack_delay_exponent if self.peer_parameters is not None else 3
        )
        ack_delay = (frame.delay * (1 << exponent)) / 1_000_000
        try:
            outcome = self.recovery.on_ack_received(level, frame, ack_delay, now)
        except AckOfUnsentPacket as exc:
            raise ConnectionError_(frames.PROTOCOL_VIOLATION, str(exc)) from exc
        for packet in outcome.acked:
            for acked_frame in packet.frames:
                if isinstance(acked_frame, Stream) and self.streams is not None:
                    self.streams.send_stream(acked_frame.stream_id).on_frame_acked(acked_frame)
        for packet in outcome.lost:
            self._log(
                now,
                qlog.PACKET_LOST,
                {
                    "header": {
                        "packet_type": _QLOG_PACKET_TYPE[packet.level],
                        "packet_number": packet.packet_number,
                    }
                },
            )
            self._requeue_lost(packet)
        self._log_recovery_metrics(now)
        if self.is_client and level is EncryptionLevel.HANDSHAKE:
            # §4.9.1: the client discards Initial keys once it sends a
            # Handshake packet; acknowledgment proves it did.
            self._discard_space(EncryptionLevel.INITIAL, now)

    def _requeue_lost(self, packet: SentPacket) -> None:
        """§13.3: resend the frames of a lost packet, not the packet."""
        space = self._spaces[packet.level]
        for frame in packet.frames:
            if isinstance(frame, Crypto):
                space.crypto_retransmit.append(frame)
            elif isinstance(frame, Stream) and self.streams is not None:
                stream = self.streams.send_stream(frame.stream_id)
                stream.requeue(frame)
            elif isinstance(frame, HandshakeDone):
                # §13.3: retransmitted until acknowledged. The client
                # confirms the handshake on this frame alone (§4.1.2).
                self._handshake_done_pending = True
            elif isinstance(frame, MaxData) and self.streams is not None:
                # §13.3: the current limit is sent, not the lost one.
                self._queue_control(MaxData(maximum=self.streams.local_max_data))
            elif isinstance(frame, MaxStreamData) and self.streams is not None:
                recv = self.streams.recv_stream(frame.stream_id)
                self._queue_control(
                    MaxStreamData(stream_id=frame.stream_id, maximum=recv.max_stream_data)
                )
            elif isinstance(frame, MaxStreams) and self.streams is not None:
                current = (
                    self.streams.local_max_streams_bidi
                    if frame.bidirectional
                    else self.streams.local_max_streams_uni
                )
                self._queue_control(MaxStreams(maximum=current, bidirectional=frame.bidirectional))

    def _prepare_probe(self, level: EncryptionLevel) -> None:
        """§6.2.4: give a PTO probe something worth carrying.

        New data when there is any, otherwise the oldest unacknowledged
        packets, at most one per probe. A PTO sends up to two datagrams,
        so requeueing the whole outstanding flight would instead double
        it on every expiry; loss detection, not the PTO, is what
        retransmits the rest.
        """
        if level is EncryptionLevel.HANDSHAKE and not self.recovery.handshake_confirmed:
            self._resend_early_application_data()
        if self._has_pending_data(level):
            return
        for packet in self.recovery.unacked(level)[:PROBE_PACKETS]:
            self._requeue_lost(packet)

    def _resend_early_application_data(self) -> None:
        """Send unacknowledged 1-RTT data again alongside a Handshake probe.

        RFC 9001 §5.7: a peer that has not completed its handshake must
        not process 1-RTT packets, and may drop rather than buffer them.
        Nothing else would resend those packets, because RFC 9002 A.6
        arms no application PTO until the handshake is confirmed, and
        confirmation waits on a HANDSHAKE_DONE that can itself be lost.
        They ride in the probe's datagram, where §12.2 coalescing puts
        the CRYPTO the peer is waiting for ahead of them.
        """
        if self._has_pending_data(EncryptionLevel.ONE_RTT):
            return
        for packet in self.recovery.unacked(EncryptionLevel.ONE_RTT)[:PROBE_PACKETS]:
            self._requeue_lost(packet)

    def _has_pending_data(self, level: EncryptionLevel) -> bool:
        """Whether anything is already queued to send at a level."""
        space = self._spaces[level]
        if space.crypto_pending or space.crypto_retransmit:
            return True
        if level is not EncryptionLevel.ONE_RTT:
            return False
        if self._control_frames or self._handshake_done_pending:
            return True
        return self.streams is not None and bool(self.streams.writable_streams())

    def _handle_crypto(self, level: EncryptionLevel, frame: Crypto, now: float) -> None:
        """Reassemble the CRYPTO stream and feed TLS in order (§19.6).

        A handshake message can span several frames, and those frames can
        arrive out of order, overlap, or be retransmitted, so the offset
        decides placement. Only contiguous bytes reach TLS, which has no
        notion of gaps.
        """
        if self.tls is None:
            raise ConnectionError_(frames.PROTOCOL_VIOLATION, "CRYPTO frame before Initial")
        space = self._spaces[level]
        end = frame.offset + len(frame.data)
        if end > MAX_CRYPTO_BUFFER:
            raise ConnectionError_(
                frames.CRYPTO_BUFFER_EXCEEDED, f"CRYPTO offset {end} exceeds the buffer limit"
            )
        if len(space.crypto_buffer) < end:
            space.crypto_buffer.extend(bytes(end - len(space.crypto_buffer)))
        space.crypto_buffer[frame.offset : end] = frame.data
        space.crypto_received.add(frame.offset, end)

        readable_end = space.crypto_received.contiguous_from(space.crypto_read_offset)
        if readable_end == space.crypto_read_offset:
            return  # a gap remains; nothing new is deliverable
        ordered = bytes(space.crypto_buffer[space.crypto_read_offset : readable_end])
        space.crypto_read_offset = readable_end
        try:
            self.tls.receive(level, ordered)
        except TlsAlert as exc:
            raise ConnectionError_(frames.CRYPTO_ERROR_BASE + exc.alert, str(exc)) from exc
        self._drain_tls_events(now)

    def _handle_stream(self, frame: Stream) -> None:
        if self.streams is None:
            raise ConnectionError_(
                frames.PROTOCOL_VIOLATION, "STREAM frame before transport parameters"
            )
        try:
            recv = self.streams.on_stream_frame(frame)
        except StreamError as exc:
            raise ConnectionError_(exc.error_code, str(exc)) from exc
        # §13.3: stream data is retransmitted until acknowledged, so a
        # frame arrives more than once. The end of the stream is reported
        # once: the state machine reaches Data Read only once (§3.2).
        was_fully_read = recv.is_fully_read
        data = recv.read()
        if data or (recv.is_fully_read and not was_fully_read):
            self._events.append(
                StreamDataReceived(
                    stream_id=frame.stream_id,
                    data=data,
                    end_stream=recv.is_fully_read,
                )
            )
        self._maybe_extend_credit(recv)

    def _maybe_extend_credit(self, recv: RecvStream) -> None:
        assert self.streams is not None
        limit = recv.credit_update()
        if limit is not None:
            self._queue_control(MaxStreamData(stream_id=recv.stream_id, maximum=limit))
        connection_limit = self.streams.max_data_update()
        if connection_limit is not None:
            self._queue_control(MaxData(maximum=connection_limit))
        for bidirectional in (True, False):
            streams_limit = self.streams.max_streams_update(bidirectional)
            if streams_limit is not None:
                self._queue_control(MaxStreams(maximum=streams_limit, bidirectional=bidirectional))

    def _queue_control(self, frame: Frame) -> None:
        self._control_frames.append(frame)

    # --- TLS events -----------------------------------------------------------

    def _drain_tls_events(self, now: float) -> None:
        if self.tls is None:
            return
        for event in self.tls.take_events():
            if isinstance(event, SendData):
                self._spaces[event.level].crypto_pending += event.data
            elif isinstance(event, SecretAvailable):
                self._on_secret(event)
            else:
                self._on_handshake_complete(event, now)

    def _on_handshake_complete(self, event: HandshakeComplete, now: float) -> None:
        self.alpn = event.alpn
        self.peer_parameters = decode_transport_parameters(event.peer_transport_parameters)
        self._log(
            now,
            qlog.PARAMETERS_SET,
            {
                # events §5.3
                "initiator": "remote",
                "initial_max_data": self.peer_parameters.initial_max_data,
                "initial_max_streams_bidi": self.peer_parameters.initial_max_streams_bidi,
                "max_idle_timeout": self.peer_parameters.max_idle_timeout_ms,
            },
        )
        self._validate_peer_parameters()
        local = self._local_parameters
        peer = self.peer_parameters
        self.streams = StreamManager(
            is_client=self.is_client,
            local=FlowControlLimits(
                max_data=local.initial_max_data,
                max_stream_data_bidi_local=local.initial_max_stream_data_bidi_local,
                max_stream_data_bidi_remote=local.initial_max_stream_data_bidi_remote,
                max_stream_data_uni=local.initial_max_stream_data_uni,
                max_streams_bidi=local.initial_max_streams_bidi,
                max_streams_uni=local.initial_max_streams_uni,
            ),
            peer=FlowControlLimits(
                max_data=peer.initial_max_data,
                max_stream_data_bidi_local=peer.initial_max_stream_data_bidi_local,
                max_stream_data_bidi_remote=peer.initial_max_stream_data_bidi_remote,
                max_stream_data_uni=peer.initial_max_stream_data_uni,
                max_streams_bidi=peer.initial_max_streams_bidi,
                max_streams_uni=peer.initial_max_streams_uni,
            ),
        )
        self.state = ConnectionState.CONNECTED
        self._events.append(HandshakeCompleted(alpn=self.alpn))
        if not self.is_client:
            # §7.3: the server confirms immediately and tells the client.
            self._handshake_done_pending = True
            self._confirm_handshake(now)
        self._arm_idle_timer(now)

    def _validate_peer_parameters(self) -> None:
        """§7.3: the peer's connection IDs must match what we saw."""
        assert self.peer_parameters is not None
        expected = self.peer_cid
        actual = self.peer_parameters.initial_source_connection_id
        if actual is not None and actual != expected:
            raise ConnectionError_(
                frames.TRANSPORT_PARAMETER_ERROR, "initial_source_connection_id mismatch"
            )
        if self.is_client:
            original = self.peer_parameters.original_destination_connection_id
            if original is not None and original != self._initial_dcid:
                raise ConnectionError_(
                    frames.TRANSPORT_PARAMETER_ERROR,
                    "original_destination_connection_id mismatch",
                )
            # §7.3: after a Retry the server echoes the connection ID it
            # chose there, and a client that saw no Retry must see no
            # such parameter. Without both checks an attacker who can
            # inject a Retry could steer the client to itself.
            retry_source = self.peer_parameters.retry_source_connection_id
            if retry_source != self._retry_source_cid:
                raise ConnectionError_(
                    frames.TRANSPORT_PARAMETER_ERROR,
                    "retry_source_connection_id mismatch",
                )

    def _confirm_handshake(self, now: float) -> None:
        """§4.9.2: confirmation discards Handshake keys and enables the
        application-space PTO."""
        self.recovery.handshake_confirmed = True
        self._discard_space(EncryptionLevel.HANDSHAKE, now)
        if self.is_client:
            self._discard_space(EncryptionLevel.INITIAL, now)
        self._events.append(HandshakeConfirmed(alpn=self.alpn))

    # --- send path ------------------------------------------------------------

    def datagrams_to_send(self, now: float) -> list[OutgoingDatagram]:
        """Build everything sendable right now (§12.2, §13)."""
        if self.state in (ConnectionState.DRAINING, ConnectionState.TERMINATED):
            return []
        if self._close_frame is not None:
            return self._build_close_datagram(now)

        self._maybe_update_keys(now)
        datagrams: list[OutgoingDatagram] = []
        self._pacing_deadline = None
        while True:
            # §7.7: an acknowledgement is not paced, so a pacer-blocked
            # connection still answers with one before it stops.
            paced_out = self._pacing_blocked(now)
            in_flight = self.recovery.controller.bytes_in_flight
            datagram = self._build_datagram(now, ack_only=paced_out)
            if datagram is None:
                break
            datagrams.append(datagram)
            # §7.7 paces in-flight packets, so credit is spent on the
            # bytes the datagram put in flight. A datagram carrying only
            # an acknowledgement adds none and spends none.
            self._pacing_credit -= self.recovery.controller.bytes_in_flight - in_flight
        self._pending.extend(datagrams)
        result, self._pending = self._pending, []
        return result

    def _pacing_blocked(self, now: float) -> bool:
        """Whether the pacer is holding back in-flight data (§7.7).

        Sets the deadline at which credit covers another datagram.
        """
        allowance = self._pacing_allowance(now)
        needed = float(self.config.max_datagram_size)
        if allowance >= needed:
            return False
        if not self._in_flight_data_pending():
            return False
        rate = self.recovery.controller.pacing_rate(self.recovery.rtt.smoothed)
        if rate is None or rate <= 0:
            return False
        self._pacing_deadline = now + (needed - allowance) / rate
        return True

    def _pacing_allowance(self, now: float) -> float:
        """Bytes the pacer permits at ``now`` (§7.7).

        A leaky bucket filled at the controller's rate, capped at the
        burst limit. A controller that does not pace returns no rate and
        the allowance is unbounded.
        """
        rate = self.recovery.controller.pacing_rate(self.recovery.rtt.smoothed)
        if rate is None:
            return math.inf
        burst = float(PACING_BURST_DATAGRAMS * self.config.max_datagram_size)
        if self._pacing_updated is None:
            self._pacing_credit = burst
        else:
            elapsed = max(0.0, now - self._pacing_updated)
            self._pacing_credit = min(self._pacing_credit + elapsed * rate, burst)
        self._pacing_updated = now
        return self._pacing_credit

    def _in_flight_data_pending(self) -> bool:
        """Whether anything queued would make a packet count as in flight."""
        if any(self._probes_pending.values()):
            return True
        return any(self._has_pending_data(level) for level in EncryptionLevel)

    def _send_budget(self, ack_only: bool = False) -> int:
        """§8.1 anti-amplification plus the congestion window.

        RFC 9002 §2: a packet carrying only ACK frames is not in flight
        and not congestion controlled, so the window does not bound it.
        RFC 9002 §7.5: a PTO probe is exempt from the congestion window.
        Without that exemption a connection that loses an entire window
        deadlocks, because the window is only freed by acknowledgements
        and no packet can be sent to provoke one. Anti-amplification is
        not waived: it bounds what an unvalidated peer can make us send.
        """
        controller = self.recovery.controller
        budget = controller.congestion_window - controller.bytes_in_flight
        if ack_only:
            budget = self.config.max_datagram_size
        probes = sum(self._probes_pending.values())
        if probes:
            budget = max(budget, probes * self.config.max_datagram_size)
        if not self.is_client and not self._address_validated:
            budget = min(budget, AMPLIFICATION_FACTOR * self._bytes_received - self._bytes_sent)
        return budget

    def _build_datagram(self, now: float, ack_only: bool = False) -> OutgoingDatagram | None:
        """Coalesce one packet per level into a single datagram (§12.2).

        §14.1: a datagram carrying an Initial packet is expanded to at
        least 1200 bytes. The expansion is PADDING frames inside the
        Initial packet's payload, never bytes appended to the datagram:
        a packet with a short header runs to the end of the datagram, so
        trailing bytes would be read as part of it (or as a malformed
        packet) and fail authentication.

        ``ack_only`` restricts the datagram to acknowledgements, which
        RFC 9002 §7.7 exempts from pacing.
        """
        budget = self._send_budget(ack_only)
        if budget <= 0:
            return None
        size_limit = self.config.max_datagram_size
        payload = bytearray()
        for level in (EncryptionLevel.INITIAL, EncryptionLevel.HANDSHAKE, EncryptionLevel.ONE_RTT):
            space = self._spaces[level]
            if space.keys_send is None or space.discarded:
                continue
            room = size_limit - len(payload)
            # An Initial fills its datagram to the floor, so nothing is
            # coalesced after it; the remaining levels take the next one.
            pad_to = min(MIN_INITIAL_DATAGRAM, budget) if level is EncryptionLevel.INITIAL else 0
            packet = self._build_packet(level, room, now, pad_to, ack_only)
            if packet is None:
                continue
            payload += packet
            if self.is_client and level is EncryptionLevel.HANDSHAKE:
                # RFC 9001 §4.9.1: a client MUST discard Initial keys when
                # it first sends a Handshake packet, which abandons loss
                # recovery for that space. Keeping it alive strands the
                # connection: the server has already dropped its Initial
                # keys, so the client's last Initial packet can never be
                # acknowledged, its PTO stays the earliest of the three
                # spaces forever, and every probe goes to a level the
                # peer can no longer read while the Handshake flight sits
                # unsent.
                self._discard_space(EncryptionLevel.INITIAL, now)
            if pad_to:
                break
        if not payload:
            return None
        self._bytes_sent += len(payload)
        return OutgoingDatagram(data=bytes(payload), destination=self.destination)

    def _pending_frames(
        self, level: EncryptionLevel, room: int, ack_only: bool = False
    ) -> tuple[list[Frame], int]:
        """Choose frames for one packet; returns frames and payload length.

        ``ack_only`` stops after the ACK, leaving everything else queued.
        """
        space = self._spaces[level]
        chosen: list[Frame] = []
        used = 0

        ack = self._build_ack(level)
        if ack is not None:
            encoded = len(ack.encode())
            if encoded <= room - used:
                chosen.append(ack)
                used += encoded
                space.ack_eliciting_pending = False
        if ack_only:
            return chosen, used

        overhead = 16  # type, offset, length varints, generously bounded
        available = max(0, room - used - overhead)
        if space.crypto_retransmit and available:
            # §13.3: lost bytes go first, and keep the offset they were
            # sent with. A frame too big for what is left is split, which
            # CRYPTO allows because every frame carries its own offset.
            lost = space.crypto_retransmit[0]
            chunk = lost.data[:available]
            if len(chunk) < len(lost.data):
                space.crypto_retransmit[0] = Crypto(
                    offset=lost.offset + len(chunk), data=lost.data[len(chunk) :]
                )
            else:
                space.crypto_retransmit.pop(0)
            crypto = Crypto(offset=lost.offset, data=chunk)
            chosen.append(crypto)
            used += len(crypto.encode())
        elif space.crypto_pending:
            chunk = bytes(space.crypto_pending[:available])
            if chunk:
                del space.crypto_pending[:available]
                crypto = Crypto(offset=space.crypto_offset_sent, data=chunk)
                space.crypto_offset_sent += len(chunk)
                chosen.append(crypto)
                used += len(crypto.encode())

        if level is EncryptionLevel.ONE_RTT:
            application, application_used = self._application_frames(room - used)
            chosen.extend(application)
            used += application_used

        if self._probes_pending[level]:
            # §6.2.4: the probe must be ack-eliciting. Anything already
            # chosen that elicits an ACK serves.
            if not any(is_ack_eliciting(frame) for frame in chosen):
                filler = self._probe_filler(level, room - used)
                chosen.append(filler)
                used += len(filler.encode())
            self._probes_pending[level] -= 1
        return chosen, used

    def _probe_filler(self, level: EncryptionLevel, room: int) -> Frame:
        """§6.2.4: what a probe carries when nothing else is queued.

        A copy of the oldest unacknowledged CRYPTO frame, because RFC 9000
        §17.2.2 says the first packet a client sends includes a CRYPTO
        frame, and under loss a probe is the first packet the server
        receives. A PING only when no CRYPTO is outstanding.
        """
        for packet in self.recovery.unacked(level):
            for frame in packet.frames:
                if isinstance(frame, Crypto) and len(frame.encode()) <= room:
                    return frame
        return Ping()

    def _application_frames(self, room: int) -> tuple[list[Frame], int]:
        """Choose the frames only the application space carries.

        HANDSHAKE_DONE, the connection-level control frames, and stream
        data, in that order: control frames carry flow control credit,
        which the peer needs before more stream data is worth sending.
        """
        chosen: list[Frame] = []
        used = 0
        if self._handshake_done_pending:
            chosen.append(HandshakeDone())
            used += 1
            self._handshake_done_pending = False
        while self._control_frames and used < room:
            control = self._control_frames[0]
            encoded = len(control.encode())
            if encoded > room - used:
                break
            self._control_frames.pop(0)
            chosen.append(control)
            used += encoded
        if self.streams is not None:
            for stream_id in self.streams.writable_streams():
                stream_overhead = 24  # type, id, offset, length varints
                available = room - used - stream_overhead
                if available <= 0:
                    break
                stream_frame = self.streams.next_frame(stream_id, available)
                if stream_frame is not None:
                    chosen.append(stream_frame)
                    used += len(stream_frame.encode())
        return chosen, used

    def _build_packet(
        self,
        level: EncryptionLevel,
        room: int,
        now: float,
        pad_datagram_to: int = 0,
        ack_only: bool = False,
    ) -> bytes | None:
        """Build one protected packet for a level, or None if nothing to send.

        ``pad_datagram_to`` adds PADDING frames so the finished packet
        reaches that size, which is how §14.1 expansion is done.
        """
        space = self._spaces[level]
        assert space.keys_send is not None
        header_overhead = 64  # bounded: long header, CIDs, length, PN
        if room <= header_overhead + AEAD_TAG_LENGTH:
            return None
        chosen, _ = self._pending_frames(level, room - header_overhead - AEAD_TAG_LENGTH, ack_only)
        if not chosen:
            return None
        payload = b"".join(frame.encode() for frame in chosen)
        # RFC 9001 §5.4.2: the packet number field plus the protected
        # payload must be long enough to sample 16 bytes for header
        # protection, assuming a 4-byte packet number.
        minimum_payload = MAX_PN_LENGTH + SAMPLE_LENGTH - AEAD_TAG_LENGTH
        if len(payload) < minimum_payload:
            payload += bytes(minimum_payload - len(payload))

        packet_number = space.next_packet_number
        if packet_number > MAX_PACKET_NUMBER:
            raise ConnectionError_(frames.INTERNAL_ERROR, "packet number space exhausted")
        space.next_packet_number += 1
        pn_bytes = encode_packet_number(packet_number, None)
        pn_length = len(pn_bytes)

        if level is EncryptionLevel.ONE_RTT:
            header = bytes([_short_header_first_byte(space, pn_length)]) + self.peer_cid + pn_bytes
        else:
            template = LongHeaderTemplate(
                packet_type=LEVEL_TO_PACKET_TYPE[level],
                version=QUIC_V1,
                destination_cid=self.peer_cid,
                source_cid=self.host_cid,
                token=self._retry_token if level is EncryptionLevel.INITIAL else b"",
            )
            if pad_datagram_to:
                # The Length varint is the same width for the padded and
                # unpadded sizes here, so one trial build gives the
                # overhead exactly.
                trial = build_long_header(
                    template,
                    payload_length=pad_datagram_to,
                    packet_number=packet_number,
                    packet_number_length=pn_length,
                )
                padding = pad_datagram_to - len(trial) - len(payload) - AEAD_TAG_LENGTH
                if padding > 0:
                    payload += bytes(padding)  # PADDING frames (§19.1)
            header = build_long_header(
                template,
                payload_length=len(payload) + AEAD_TAG_LENGTH,
                packet_number=packet_number,
                packet_number_length=pn_length,
            )
        packet = protect(space.keys_send, header, payload, packet_number)

        ack_eliciting = any(is_ack_eliciting(frame) for frame in chosen)
        self._log(
            now,
            qlog.PACKET_SENT,
            {
                "header": {"packet_type": _QLOG_PACKET_TYPE[level], "packet_number": packet_number},
                "raw": {"length": len(packet)},
                "frames": [qlog.frame_detail(frame) for frame in chosen],
            },
        )
        self.recovery.on_packet_sent(
            SentPacket(
                level=level,
                packet_number=packet_number,
                time_sent=now,
                ack_eliciting=ack_eliciting,
                in_flight=ack_eliciting,
                size=len(packet),
                frames=chosen,
            )
        )
        return packet

    def _build_ack(self, level: EncryptionLevel) -> Ack | None:
        """§13.2: acknowledge what this space has received."""
        space = self._spaces[level]
        if not space.ack_eliciting_pending or space.largest_received < 0:
            return None
        ranges = [
            (start, end - 1) for start, end in reversed(space.received.ranges[-MAX_ACK_RANGES:])
        ]
        return Ack(largest=space.largest_received, delay=0, ranges=ranges)

    # --- termination (§10) ----------------------------------------------------

    def close(
        self,
        error_code: int = frames.NO_ERROR,
        reason: str = "",
        frame_type: int | None = None,
    ) -> None:
        """Begin an immediate close (§10.2).

        ``frame_type`` None sends the application variant (0x1d); an
        integer sends the transport variant (0x1c) naming the frame at
        fault, which is what a detected transport error uses.
        """
        if self.state in (ConnectionState.CLOSING, ConnectionState.DRAINING):
            return
        self._close_frame = ConnectionClose(
            error_code=error_code, reason=reason.encode("utf-8"), frame_type=frame_type
        )
        self.state = ConnectionState.CLOSING

    def _on_connection_close(self, frame: ConnectionClose, now: float) -> None:
        """§10.2.2: entering the draining state; no further packets are sent."""
        self.state = ConnectionState.DRAINING
        self._closing_deadline = now + 3 * self.recovery.pto()
        reason = frame.reason.decode("utf-8", "replace")
        self._log(
            now,
            qlog.CONNECTION_CLOSED,
            {"initiator": "remote", "error_code": frame.error_code, "reason": reason},
        )
        self._events.append(ConnectionTerminated(error_code=frame.error_code, reason=reason))

    def _build_close_datagram(self, now: float) -> list[OutgoingDatagram]:
        """§10.2.1: CONNECTION_CLOSE is sent at the highest ready level."""
        if self._close_sent or self._close_frame is None:
            return []
        for level in (EncryptionLevel.ONE_RTT, EncryptionLevel.HANDSHAKE, EncryptionLevel.INITIAL):
            space = self._spaces[level]
            if space.keys_send is None or space.discarded:
                continue
            payload = self._close_frame.encode()
            minimum_payload = MAX_PN_LENGTH + SAMPLE_LENGTH - AEAD_TAG_LENGTH
            if len(payload) < minimum_payload:
                payload += bytes(minimum_payload - len(payload))
            packet_number = space.next_packet_number
            space.next_packet_number += 1
            pn_bytes = encode_packet_number(packet_number, None)
            if level is EncryptionLevel.ONE_RTT:
                header = (
                    bytes([_short_header_first_byte(space, len(pn_bytes))])
                    + self.peer_cid
                    + pn_bytes
                )
            else:
                header = build_long_header(
                    LongHeaderTemplate(
                        packet_type=LEVEL_TO_PACKET_TYPE[level],
                        version=QUIC_V1,
                        token=self._retry_token if level is EncryptionLevel.INITIAL else b"",
                        destination_cid=self.peer_cid,
                        source_cid=self.host_cid,
                    ),
                    payload_length=len(payload) + AEAD_TAG_LENGTH,
                    packet_number=packet_number,
                    packet_number_length=len(pn_bytes),
                )
            packet = protect(space.keys_send, header, payload, packet_number)
            self._close_sent = True
            self._closing_deadline = now + 3 * self.recovery.pto()
            return [OutgoingDatagram(data=packet, destination=self.destination)]
        return []

    # --- timers ---------------------------------------------------------------

    def _arm_idle_timer(self, now: float) -> None:
        """§10.1: start the idle period. The deadline itself is computed
        on demand, because the floor it depends on moves."""
        self._idle_started = now

    @property
    def _idle_deadline(self) -> float | None:
        """§10.1: the negotiated minimum idle timeout, floored at three
        times the PTO.

        Derived on demand rather than stored, because the RTT estimate it
        depends on moves. The floor uses the unscaled PTO deliberately;
        see the design.md appendix.
        """
        if self._idle_started is None:
            return None  # the idle period starts at the first packet
        local_ms = self._local_parameters.max_idle_timeout_ms
        peer_ms = self.peer_parameters.max_idle_timeout_ms if self.peer_parameters else 0
        candidates = [value for value in (local_ms, peer_ms) if value > 0]
        if not candidates:
            return None
        timeout = min(candidates) / 1000
        return self._idle_started + max(timeout, 3 * self.recovery.pto())

    def next_timer(self) -> float | None:
        """When the caller must call handle_timer (design.md §4.7)."""
        if self.state in (ConnectionState.TERMINATED,):
            return None
        candidates = [
            deadline
            for deadline in (
                self._closing_deadline,
                self._idle_deadline if self.state is not ConnectionState.DRAINING else None,
                self.recovery.loss_detection_timeout()
                if self.state not in (ConnectionState.CLOSING, ConnectionState.DRAINING)
                else None,
                self._pacing_deadline,
            )
            if deadline is not None
        ]
        return min(candidates) if candidates else None

    def handle_timer(self, now: float) -> None:
        """Run whatever the clock has made due."""
        if self._closing_deadline is not None and now >= self._closing_deadline:
            self.state = ConnectionState.TERMINATED
            return
        if self.state in (ConnectionState.CLOSING, ConnectionState.DRAINING):
            return
        if self._idle_deadline is not None and now >= self._idle_deadline:
            self.state = ConnectionState.TERMINATED
            self._log(
                now,
                qlog.CONNECTION_CLOSED,
                {"initiator": "local", "trigger": "idle_timeout"},
            )
            self._events.append(ConnectionTerminated(frames.NO_ERROR, "idle timeout"))
            return
        timeout = self.recovery.loss_detection_timeout()
        if timeout is not None and now >= timeout:
            outcome = self.recovery.on_loss_detection_timeout(now)
            for packet in outcome.lost:
                self._requeue_lost(packet)
            if outcome.probe_level is not None:
                # §6.2.4: a PTO sends ack-eliciting data at that level.
                self._probes_pending[outcome.probe_level] += PROBE_PACKETS
                # Once per timeout: a probe is itself unacknowledged, so
                # requeueing per packet would compound.
                self._prepare_probe(outcome.probe_level)

    # --- application interface -------------------------------------------------

    def connect(self, now: float) -> None:
        """Client: start the handshake (§7)."""
        assert isinstance(self.tls, TlsClient)
        self._open_qlog(self._initial_dcid, now)
        self.tls.start()
        self._drain_tls_events(now)
        self._arm_idle_timer(now)

    def open_stream(self) -> int:
        """Open the next bidirectional stream, or raise if the peer's
        limit is reached (§4.6)."""
        if self.streams is None:
            raise RuntimeError("cannot open a stream before the handshake completes")
        try:
            return self.streams.open_bidi()
        except StreamLimitReached:
            # §4.6: an endpoint unable to open a stream SHOULD report it.
            self._queue_control(
                StreamsBlocked(limit=self.streams.max_streams_bidi, bidirectional=True)
            )
            raise

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        if self.streams is None:
            raise RuntimeError("cannot send stream data before the handshake completes")
        self.streams.send_stream(stream_id).write(data, fin=end_stream)

    def take_events(self) -> list[ConnectionEvent]:
        events, self._events = self._events, []
        return events

    def keys_discarded(self, level: EncryptionLevel) -> bool:
        """Whether a packet number space has been retired (RFC 9001 §4.9)."""
        return self._spaces[level].discarded

    def key_phase(self) -> bool:
        """The current 1-RTT key phase (RFC 9001 §6)."""
        return self._spaces[EncryptionLevel.ONE_RTT].key_phase
