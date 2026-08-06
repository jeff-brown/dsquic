"""qlog structured event output.

draft-ietf-quic-qlog-main-schema-14 and draft-ietf-quic-qlog-quic-events-13.

Serializes events in the sequential format: a header object followed by
one object per event, each introduced by a record separator (main-schema
§5). Event names carry the ``quic`` namespace registered in events §2,
and the schema URI appends the draft number per events §2.1.

Event times are milliseconds relative to the trace's reference time. This
module reads no clock; callers pass the monotonic readings they give the
rest of the core.

Nothing here performs I/O: a trace hands finished records to a callable.
File writing lives in endpoints/.
"""

import json
from collections.abc import Callable
from typing import Any

from dsquic import __version__

RECORD_SEPARATOR = "\x1e"  # main-schema §5
FILE_SCHEMA = "urn:ietf:params:qlog:file:sequential"
EVENT_SCHEMA = "urn:ietf:params:qlog:events:quic-13"
SERIALIZATION_FORMAT = "application/qlog+json-seq"
# The version and format fields the schema used before it moved to URIs.
# Both spellings are emitted; readers that predate the URIs require these.
LEGACY_VERSION = "0.3"
LEGACY_FORMAT = "JSON-SEQ"

# Event names, in the "quic" namespace of events §2.
PACKET_SENT = "quic:packet_sent"  # §5.5
PACKET_RECEIVED = "quic:packet_received"  # §5.6
PACKET_DROPPED = "quic:packet_dropped"  # §5.7
PACKET_LOST = "quic:packet_lost"  # §7.4
PARAMETERS_SET = "quic:parameters_set"  # §5.3
RECOVERY_METRICS_UPDATED = "quic:recovery_metrics_updated"  # §7.2
KEY_UPDATED = "quic:key_updated"  # §6.1
KEY_DISCARDED = "quic:key_discarded"  # §6.2
CONNECTION_STARTED = "quic:connection_started"  # §4.2
CONNECTION_CLOSED = "quic:connection_closed"  # §4.3

# §5.7 trigger values, one per reason the receive path discards a packet.
DROP_KEY_UNAVAILABLE = "key_unavailable"
DROP_DECRYPTION_FAILURE = "decryption_failure"
DROP_DUPLICATE = "duplicate"
DROP_INVALID = "invalid"
DROP_UNSUPPORTED = "unsupported"
DROP_GENERAL = "general"

# The schema's name for each frame in frames.py (events §8, QuicFrame).
FRAME_TYPES = {
    "Padding": "padding",
    "Ping": "ping",
    "Ack": "ack",
    "ResetStream": "reset_stream",
    "StopSending": "stop_sending",
    "Crypto": "crypto",
    "NewToken": "new_token",
    "Stream": "stream",
    "MaxData": "max_data",
    "MaxStreamData": "max_stream_data",
    "MaxStreams": "max_streams",
    "DataBlocked": "data_blocked",
    "StreamDataBlocked": "stream_data_blocked",
    "StreamsBlocked": "streams_blocked",
    "NewConnectionId": "new_connection_id",
    "RetireConnectionId": "retire_connection_id",
    "PathChallenge": "path_challenge",
    "PathResponse": "path_response",
    "ConnectionClose": "connection_close",
    "HandshakeDone": "handshake_done",
    "Datagram": "datagram",
}


# Frame fields the schema names as frames.py does (events §8).
FRAME_FIELDS = ("stream_id", "offset", "fin", "maximum", "limit")

# Frame fields the schema gives another name (events §8).
RENAMED_FRAME_FIELDS = {"ranges": "acked_ranges"}


def frame_detail(frame: object) -> dict[str, Any]:
    """One frame as the schema describes it (events §8)."""
    detail: dict[str, Any] = {"frame_type": frame_type(frame)}
    for name in FRAME_FIELDS:
        value = getattr(frame, name, None)
        if value is not None:
            detail[name] = value
    for name, schema_name in RENAMED_FRAME_FIELDS.items():
        value = getattr(frame, name, None)
        if value is not None:
            detail[schema_name] = value
    return detail


def frame_type(frame: object) -> str:
    """The schema's name for a frame (events §8).

    An unmapped class lowercases its own name rather than raising: a
    trace never fails a connection.
    """
    name = type(frame).__name__
    return FRAME_TYPES.get(name, name.lower())


class QlogTrace:
    """One connection's trace (main-schema §6).

    ``emit`` receives complete records in order. ``group_id`` is the
    original destination connection ID, which associates the two
    endpoints' traces. ``wall_clock_time`` anchors a monotonic trace to
    real time; without it the reference has no epoch.
    """

    def __init__(
        self,
        *,
        emit: Callable[[str], None],
        group_id: str,
        is_client: bool,
        reference_time: float,
        wall_clock_time: str | None = None,
    ) -> None:
        self._emit = emit
        self._reference_time = reference_time
        reference: dict[str, Any] = {"clock_type": "monotonic", "epoch": "unknown"}
        if wall_clock_time is not None:
            reference["wall_clock_time"] = wall_clock_time
        self._emit(
            _record(
                {
                    "file_schema": FILE_SCHEMA,
                    "serialization_format": SERIALIZATION_FORMAT,
                    "qlog_version": LEGACY_VERSION,
                    "qlog_format": LEGACY_FORMAT,
                    "title": "dsquic qlog",
                    "code_version": __version__,
                    "trace": {
                        "event_schemas": [EVENT_SCHEMA],
                        "vantage_point": {"type": "client" if is_client else "server"},
                        "common_fields": {"group_id": group_id, "reference_time": reference},
                    },
                }
            )
        )

    def log(self, now: float, name: str, data: dict[str, Any]) -> None:
        """Record one event at time ``now`` on the caller's clock."""
        self._emit(
            _record({"time": (now - self._reference_time) * 1000, "name": name, "data": data})
        )


def _record(value: dict[str, Any]) -> str:
    """One JSON-SEQ record: separator, compact JSON, newline (§5)."""
    return RECORD_SEPARATOR + json.dumps(value, separators=(",", ":")) + "\n"
