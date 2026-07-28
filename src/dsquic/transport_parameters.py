"""Transport parameters: the connection's negotiated configuration.

RFC 9000 §7.4 and §18. Carried in the TLS quic_transport_parameters
extension (RFC 9001 §8.2), encoded as a sequence of varint id/length/value
triples.

Unknown and reserved parameters (the 31N+27 grease pattern, §18.1) are
ignored on parse, never rejected. Only the parameters this MVP acts on
are surfaced; the rest are accepted and dropped.
"""

from dataclasses import dataclass

from dsquic.buffer import Buffer, encode_varint

ORIGINAL_DESTINATION_CONNECTION_ID = 0x00
MAX_IDLE_TIMEOUT = 0x01
STATELESS_RESET_TOKEN = 0x02
MAX_UDP_PAYLOAD_SIZE = 0x03
INITIAL_MAX_DATA = 0x04
INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05
INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06
INITIAL_MAX_STREAM_DATA_UNI = 0x07
INITIAL_MAX_STREAMS_BIDI = 0x08
INITIAL_MAX_STREAMS_UNI = 0x09
ACK_DELAY_EXPONENT = 0x0A
MAX_ACK_DELAY = 0x0B
DISABLE_ACTIVE_MIGRATION = 0x0C
ACTIVE_CONNECTION_ID_LIMIT = 0x0E
INITIAL_SOURCE_CONNECTION_ID = 0x0F
RETRY_SOURCE_CONNECTION_ID = 0x10
MAX_DATAGRAM_FRAME_SIZE = 0x20  # RFC 9221 §3

DEFAULT_ACK_DELAY_EXPONENT = 3  # §18.2
DEFAULT_MAX_ACK_DELAY_MS = 25


@dataclass(frozen=True)
class TransportParameters:
    """The parameters this implementation reads or writes (§18.2)."""

    original_destination_connection_id: bytes | None = None
    initial_source_connection_id: bytes | None = None
    max_idle_timeout_ms: int = 0
    max_udp_payload_size: int = 65527
    initial_max_data: int = 0
    initial_max_stream_data_bidi_local: int = 0
    initial_max_stream_data_bidi_remote: int = 0
    initial_max_stream_data_uni: int = 0
    initial_max_streams_bidi: int = 0
    initial_max_streams_uni: int = 0
    ack_delay_exponent: int = DEFAULT_ACK_DELAY_EXPONENT
    max_ack_delay_ms: int = DEFAULT_MAX_ACK_DELAY_MS
    active_connection_id_limit: int = 2
    max_datagram_frame_size: int | None = None

    def encode(self) -> bytes:
        out = bytearray()

        def put(parameter_id: int, value: bytes) -> None:
            out.extend(encode_varint(parameter_id) + encode_varint(len(value)) + value)

        def put_int(parameter_id: int, value: int) -> None:
            put(parameter_id, encode_varint(value))

        if self.original_destination_connection_id is not None:
            put(ORIGINAL_DESTINATION_CONNECTION_ID, self.original_destination_connection_id)
        if self.initial_source_connection_id is not None:
            put(INITIAL_SOURCE_CONNECTION_ID, self.initial_source_connection_id)
        put_int(MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms)
        put_int(MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size)
        put_int(INITIAL_MAX_DATA, self.initial_max_data)
        put_int(INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, self.initial_max_stream_data_bidi_local)
        put_int(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, self.initial_max_stream_data_bidi_remote)
        put_int(INITIAL_MAX_STREAM_DATA_UNI, self.initial_max_stream_data_uni)
        put_int(INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi)
        put_int(INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni)
        put_int(ACK_DELAY_EXPONENT, self.ack_delay_exponent)
        put_int(MAX_ACK_DELAY, self.max_ack_delay_ms)
        put_int(ACTIVE_CONNECTION_ID_LIMIT, self.active_connection_id_limit)
        if self.max_datagram_frame_size is not None:
            put_int(MAX_DATAGRAM_FRAME_SIZE, self.max_datagram_frame_size)
        return bytes(out)


def decode_transport_parameters(data: bytes) -> TransportParameters:
    """Parse the extension body; unknown parameters are ignored (§18.1)."""
    buf = Buffer(data)
    values: dict[int, bytes] = {}
    while not buf.is_empty:
        parameter_id = buf.pull_varint()
        values[parameter_id] = buf.pull_bytes(buf.pull_varint())

    def as_int(parameter_id: int, default: int) -> int:
        raw = values.get(parameter_id)
        return Buffer(raw).pull_varint() if raw else default

    datagram_size = values.get(MAX_DATAGRAM_FRAME_SIZE)
    return TransportParameters(
        original_destination_connection_id=values.get(ORIGINAL_DESTINATION_CONNECTION_ID),
        initial_source_connection_id=values.get(INITIAL_SOURCE_CONNECTION_ID),
        max_idle_timeout_ms=as_int(MAX_IDLE_TIMEOUT, 0),
        max_udp_payload_size=as_int(MAX_UDP_PAYLOAD_SIZE, 65527),
        initial_max_data=as_int(INITIAL_MAX_DATA, 0),
        initial_max_stream_data_bidi_local=as_int(INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0),
        initial_max_stream_data_bidi_remote=as_int(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0),
        initial_max_stream_data_uni=as_int(INITIAL_MAX_STREAM_DATA_UNI, 0),
        initial_max_streams_bidi=as_int(INITIAL_MAX_STREAMS_BIDI, 0),
        initial_max_streams_uni=as_int(INITIAL_MAX_STREAMS_UNI, 0),
        ack_delay_exponent=as_int(ACK_DELAY_EXPONENT, DEFAULT_ACK_DELAY_EXPONENT),
        max_ack_delay_ms=as_int(MAX_ACK_DELAY, DEFAULT_MAX_ACK_DELAY_MS),
        active_connection_id_limit=as_int(ACTIVE_CONNECTION_ID_LIMIT, 2),
        max_datagram_frame_size=Buffer(datagram_size).pull_varint() if datagram_size else None,
    )
