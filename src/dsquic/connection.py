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

Not in this MVP: Retry, Version Negotiation, migration, key update,
stateless reset, NEW_CONNECTION_ID issuance, and 0-RTT. Received frames
for those features are parsed and ignored where the spec permits.
"""

import enum
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from dsquic import frames
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
    Ping,
    Stream,
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
    MAX_PN_LENGTH,
    SAMPLE_LENGTH,
    PacketKeys,
    derive_initial_secrets,
    derive_packet_keys,
    protect,
    unprotect,
)
from dsquic.recovery import AckOfUnsentPacket, LossDetection, SentPacket
from dsquic.streams import FlowControlLimits, RangeSet, RecvStream, StreamError, StreamManager
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

LEVEL_TO_PACKET_TYPE = {
    EncryptionLevel.INITIAL: PacketType.INITIAL,
    EncryptionLevel.HANDSHAKE: PacketType.HANDSHAKE,
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
class HandshakeConfirmed:
    alpn: str


@dataclass(frozen=True)
class ConnectionTerminated:
    error_code: int
    reason: str


ConnectionEvent = StreamDataReceived | HandshakeConfirmed | ConnectionTerminated


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
    discarded: bool = False


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
    keylog: Callable[[str], None] | None = None


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

        self._local_parameters = self._parameters_for(self._initial_dcid)
        self.peer_parameters: TransportParameters | None = None

        self.tls: TlsClient | TlsServer | None = None
        if is_client:
            if client_config is None:
                raise ValueError("client_config is required for a client connection")
            self.tls = TlsClient(
                ClientConfig(
                    **{
                        **client_config.__dict__,
                        "transport_parameters": self._local_parameters.encode(),
                    }
                ),
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
        self._handshake_done_pending = False
        self._close_frame: ConnectionClose | None = None
        self._close_sent = False
        self._bytes_received = 0
        self._bytes_sent = 0
        self._address_validated = is_client
        self._idle_deadline: float | None = None
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
        else:
            space.keys_recv = keys

    def _discard_space(self, level: EncryptionLevel) -> None:
        """§4.9: drop a level's keys and its recovery state."""
        space = self._spaces[level]
        if space.discarded:
            return
        space.discarded = True
        space.keys_send = None
        space.keys_recv = None
        space.crypto_pending.clear()
        self.recovery.discard_space(level)

    # --- receive path ---------------------------------------------------------

    def datagram_received(self, data: bytes, now: float, source: object = None) -> None:
        """Process one received datagram (§12.2: coalesced packets)."""
        if self.state in (ConnectionState.TERMINATED, ConnectionState.DRAINING):
            return
        self._bytes_received += len(data)
        if not self.is_client and not self._address_validated:
            # §8.1: a datagram containing a valid Initial validates nothing
            # by itself, but receiving any packet grows the send budget.
            self._address_validated = self.state is ConnectionState.CONNECTED
        if self.destination is None and source is not None:
            self.destination = source
        offset = 0
        while offset < len(data):
            consumed = self._process_packet(data[offset:], now)
            if consumed <= 0:
                break
            offset += consumed
        self._arm_idle_timer(now)

    def _process_packet(self, data: bytes, now: float) -> int:
        """Unprotect and handle one packet; returns bytes consumed."""
        try:
            if data[0] & 0x80:
                header = parse_long_header(data)
                level = {
                    PacketType.INITIAL: EncryptionLevel.INITIAL,
                    PacketType.HANDSHAKE: EncryptionLevel.HANDSHAKE,
                }.get(header.packet_type)
                if level is None:
                    return 0  # 0-RTT: not supported, stop parsing this datagram
                packet_end = header.pn_offset + header.length
                if not self.is_client and level is EncryptionLevel.INITIAL:
                    self._adopt_client_initial(header.destination_cid, header.source_cid)
                elif self.is_client and not self._peer_cid_confirmed:
                    # §7.2: the client switches to the server's chosen
                    # source connection ID from its first server packet.
                    self.peer_cid = header.source_cid
                    self._peer_cid_confirmed = True
                packet = data[:packet_end]
            else:
                short = parse_short_header(data, len(self.host_cid))
                level = EncryptionLevel.ONE_RTT
                header = None
                packet = data
                packet_end = len(data)
        except (HeaderParseError, BufferReadError, UnsupportedVersion):
            return 0  # §5.2: undecodable packets are discarded silently

        space = self._spaces[level]
        if space.keys_recv is None or space.discarded:
            return packet_end  # no keys yet: drop, keep parsing the datagram
        pn_offset = header.pn_offset if header is not None else short.pn_offset
        try:
            packet_number, payload = unprotect(
                space.keys_recv, packet, pn_offset, space.largest_received
            )
        except (InvalidTag, ValueError):
            return packet_end  # §12.2: failed decryption is not fatal
        if space.received.covers(packet_number, packet_number + 1):
            return packet_end  # already processed
        space.received.add(packet_number, packet_number + 1)
        if packet_number > space.largest_received:
            space.largest_received = packet_number
            self._largest_time_received[level] = now
        if not self.is_client and level is EncryptionLevel.HANDSHAKE:
            # §4.9.1: the server discards Initial keys on the first
            # successfully processed Handshake packet.
            self._discard_space(EncryptionLevel.INITIAL)
        self._handle_payload(level, payload, now)
        return packet_end

    def _parameters_for(self, initial_dcid: bytes) -> TransportParameters:
        """Our transport parameters, including the §7.3 connection ID
        authentication fields."""
        values = {
            **self.config.transport_parameters.__dict__,
            "initial_source_connection_id": self.host_cid,
        }
        if not self.is_client:
            values["original_destination_connection_id"] = initial_dcid
        return TransportParameters(**values)

    def _adopt_client_initial(self, dcid: bytes, scid: bytes) -> None:
        """A server learns both connection IDs from the client's first
        Initial (§7.2) and only then can build its TLS state, since the
        transport parameters must echo the destination CID (§7.3)."""
        if self.tls is None:
            assert self._server_config is not None
            self._initial_dcid = dcid
            self._local_parameters = self._parameters_for(dcid)
            self.tls = TlsServer(
                ServerConfig(
                    **{
                        **self._server_config.__dict__,
                        "transport_parameters": self._local_parameters.encode(),
                    }
                ),
                keylog=self.config.keylog,
            )
            self._install_initial_keys(dcid)
        if not self.peer_cid:
            self.peer_cid = scid

    def _handle_payload(self, level: EncryptionLevel, payload: bytes, now: float) -> None:
        try:
            parsed = parse_frames(payload)
        except (FrameParseError, BufferReadError) as exc:
            raise ConnectionError_(frames.FRAME_ENCODING_ERROR, str(exc)) from exc
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
        elif isinstance(frame, MaxData):
            if self.streams is not None:
                self.streams.on_max_data(frame.maximum)
        elif isinstance(frame, MaxStreamData):
            if self.streams is not None:
                self.streams.send_stream(frame.stream_id).on_max_stream_data(frame.maximum)
        elif isinstance(frame, HandshakeDone):
            # §7.3: the client confirms the handshake on HANDSHAKE_DONE.
            if not self.is_client:
                raise ConnectionError_(frames.PROTOCOL_VIOLATION, "client sent HANDSHAKE_DONE")
            self._confirm_handshake()
        elif isinstance(frame, ConnectionClose):
            self._on_connection_close(frame, now)
        # Frames for deferred features (NEW_CONNECTION_ID, PATH_CHALLENGE,
        # NEW_TOKEN, DATAGRAM, blocked frames) are accepted and ignored.

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
            self._requeue_lost(packet)
        if self.is_client and level is EncryptionLevel.HANDSHAKE:
            # §4.9.1: the client discards Initial keys once it sends a
            # Handshake packet; acknowledgment proves it did.
            self._discard_space(EncryptionLevel.INITIAL)

    def _requeue_lost(self, packet: SentPacket) -> None:
        """§13.3: resend the frames of a lost packet, not the packet."""
        space = self._spaces[packet.level]
        for frame in packet.frames:
            if isinstance(frame, Crypto):
                # Re-queue at the front: CRYPTO must stay ordered.
                space.crypto_pending[:0] = frame.data
                space.crypto_offset_sent = min(space.crypto_offset_sent, frame.offset)
            elif isinstance(frame, Stream) and self.streams is not None:
                stream = self.streams.send_stream(frame.stream_id)
                stream.requeue(frame)

    def _handle_crypto(self, level: EncryptionLevel, frame: Crypto, now: float) -> None:
        if self.tls is None:
            raise ConnectionError_(frames.PROTOCOL_VIOLATION, "CRYPTO frame before Initial")
        try:
            self.tls.receive(level, frame.data)
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
        data = recv.read()
        if data or recv.state.name in ("DATA_RECVD", "DATA_READ"):
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
            elif isinstance(event, HandshakeComplete):
                self._on_handshake_complete(event, now)

    def _on_handshake_complete(self, event: HandshakeComplete, now: float) -> None:
        self.alpn = event.alpn
        self.peer_parameters = decode_transport_parameters(event.peer_transport_parameters)
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
        if not self.is_client:
            # §7.3: the server confirms immediately and tells the client.
            self._handshake_done_pending = True
            self._confirm_handshake()
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

    def _confirm_handshake(self) -> None:
        """§4.9.2: confirmation discards Handshake keys and enables the
        application-space PTO."""
        self.recovery.handshake_confirmed = True
        self._discard_space(EncryptionLevel.HANDSHAKE)
        if self.is_client:
            self._discard_space(EncryptionLevel.INITIAL)
        self._events.append(HandshakeConfirmed(alpn=self.alpn))

    # --- send path ------------------------------------------------------------

    def datagrams_to_send(self, now: float) -> list[OutgoingDatagram]:
        """Build everything sendable right now (§12.2, §13)."""
        if self.state in (ConnectionState.DRAINING, ConnectionState.TERMINATED):
            return []
        if self._close_frame is not None:
            return self._build_close_datagram(now)

        datagrams: list[OutgoingDatagram] = []
        while True:
            datagram = self._build_datagram(now)
            if datagram is None:
                break
            datagrams.append(datagram)
        self._pending.extend(datagrams)
        result, self._pending = self._pending, []
        return result

    def _send_budget(self) -> int:
        """§8.1 anti-amplification plus the congestion window."""
        controller = self.recovery.controller
        budget = controller.congestion_window - controller.bytes_in_flight
        if not self.is_client and not self._address_validated:
            budget = min(budget, AMPLIFICATION_FACTOR * self._bytes_received - self._bytes_sent)
        return budget

    def _build_datagram(self, now: float) -> OutgoingDatagram | None:
        """Coalesce one packet per level into a single datagram (§12.2)."""
        if self._send_budget() <= 0:
            return None
        size_limit = self.config.max_datagram_size
        payload = bytearray()
        needs_padding = False
        for level in (EncryptionLevel.INITIAL, EncryptionLevel.HANDSHAKE, EncryptionLevel.ONE_RTT):
            space = self._spaces[level]
            if space.keys_send is None or space.discarded:
                continue
            room = size_limit - len(payload)
            packet = self._build_packet(level, room, now)
            if packet is None:
                continue
            payload += packet
            if level is EncryptionLevel.INITIAL and self.is_client:
                needs_padding = True
        if not payload:
            return None
        if needs_padding and len(payload) < MIN_INITIAL_DATAGRAM:
            # §14.1: a datagram containing a client Initial is padded to
            # at least 1200 bytes, proving path capacity.
            payload += bytes(MIN_INITIAL_DATAGRAM - len(payload))
        self._bytes_sent += len(payload)
        return OutgoingDatagram(data=bytes(payload), destination=self.destination)

    def _pending_frames(self, level: EncryptionLevel, room: int) -> tuple[list[Frame], int]:
        """Choose frames for one packet; returns frames and payload length."""
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

        if space.crypto_pending:
            overhead = 16  # type, offset, length varints, generously bounded
            available = max(0, room - used - overhead)
            chunk = bytes(space.crypto_pending[:available])
            if chunk:
                del space.crypto_pending[:available]
                crypto = Crypto(offset=space.crypto_offset_sent, data=chunk)
                space.crypto_offset_sent += len(chunk)
                chosen.append(crypto)
                used += len(crypto.encode())

        if level is EncryptionLevel.ONE_RTT:
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

    def _build_packet(self, level: EncryptionLevel, room: int, now: float) -> bytes | None:
        """Build one protected packet for a level, or None if nothing to send."""
        space = self._spaces[level]
        assert space.keys_send is not None
        header_overhead = 64  # bounded: long header, CIDs, length, PN
        if room <= header_overhead + AEAD_TAG_LENGTH:
            return None
        chosen, _ = self._pending_frames(level, room - header_overhead - AEAD_TAG_LENGTH)
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
            first = 0x40 | (pn_length - 1)
            header = bytes([first]) + self.peer_cid + pn_bytes
        else:
            template = LongHeaderTemplate(
                packet_type=LEVEL_TO_PACKET_TYPE[level],
                version=QUIC_V1,
                destination_cid=self.peer_cid,
                source_cid=self.host_cid,
            )
            header = build_long_header(
                template,
                payload_length=len(payload) + AEAD_TAG_LENGTH,
                packet_number=packet_number,
                packet_number_length=pn_length,
            )
        packet = protect(space.keys_send, header, payload, packet_number)

        ack_eliciting = any(is_ack_eliciting(frame) for frame in chosen)
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

    def close(self, error_code: int = frames.NO_ERROR, reason: str = "") -> None:
        """Begin an immediate close (§10.2)."""
        if self.state in (ConnectionState.CLOSING, ConnectionState.DRAINING):
            return
        self._close_frame = ConnectionClose(
            error_code=error_code, reason=reason.encode("utf-8"), frame_type=None
        )
        self.state = ConnectionState.CLOSING

    def _on_connection_close(self, frame: ConnectionClose, now: float) -> None:
        """§10.2.2: entering the draining state; no further packets are sent."""
        self.state = ConnectionState.DRAINING
        self._closing_deadline = now + 3 * self._pto_estimate()
        self._events.append(
            ConnectionTerminated(
                error_code=frame.error_code, reason=frame.reason.decode("utf-8", "replace")
            )
        )

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
                header = bytes([0x40 | (len(pn_bytes) - 1)]) + self.peer_cid + pn_bytes
            else:
                header = build_long_header(
                    LongHeaderTemplate(
                        packet_type=LEVEL_TO_PACKET_TYPE[level],
                        version=QUIC_V1,
                        destination_cid=self.peer_cid,
                        source_cid=self.host_cid,
                    ),
                    payload_length=len(payload) + AEAD_TAG_LENGTH,
                    packet_number=packet_number,
                    packet_number_length=len(pn_bytes),
                )
            packet = protect(space.keys_send, header, payload, packet_number)
            self._close_sent = True
            self._closing_deadline = now + 3 * self._pto_estimate()
            return [OutgoingDatagram(data=packet, destination=self.destination)]
        return []

    def _pto_estimate(self) -> float:
        return self.recovery.rtt.smoothed + 4 * self.recovery.rtt.rttvar

    # --- timers ---------------------------------------------------------------

    def _arm_idle_timer(self, now: float) -> None:
        """§10.1: idle timeout from the negotiated minimum, floored at 3 PTO."""
        local_ms = self._local_parameters.max_idle_timeout_ms
        peer_ms = self.peer_parameters.max_idle_timeout_ms if self.peer_parameters else 0
        candidates = [value for value in (local_ms, peer_ms) if value > 0]
        if not candidates:
            self._idle_deadline = None
            return
        timeout = min(candidates) / 1000
        self._idle_deadline = now + max(timeout, 3 * self._pto_estimate())

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
            self._events.append(ConnectionTerminated(frames.NO_ERROR, "idle timeout"))
            return
        timeout = self.recovery.loss_detection_timeout()
        if timeout is not None and now >= timeout:
            outcome = self.recovery.on_loss_detection_timeout(now)
            for packet in outcome.lost:
                self._requeue_lost(packet)
            if outcome.probe_level is not None:
                # §6.2.4: a PTO sends new ack-eliciting data, a PING if
                # nothing else is pending.
                self._control_frames.append(Ping())

    # --- application interface -------------------------------------------------

    def connect(self, now: float) -> None:
        """Client: start the handshake (§7)."""
        assert isinstance(self.tls, TlsClient)
        self.tls.start()
        self._drain_tls_events(now)
        self._arm_idle_timer(now)

    def open_stream(self) -> int:
        if self.streams is None:
            raise RuntimeError("cannot open a stream before the handshake completes")
        return self.streams.open_bidi()

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        if self.streams is None:
            raise RuntimeError("cannot send stream data before the handshake completes")
        self.streams.send_stream(stream_id).write(data, fin=end_stream)

    def take_events(self) -> list[ConnectionEvent]:
        events, self._events = self._events, []
        return events
