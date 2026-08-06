"""Tests for dsquic.qlog against the sequential format.

draft-ietf-quic-qlog-main-schema-14, draft-ietf-quic-qlog-quic-events-13.
"""

import dataclasses
import json
from typing import Any

from dsquic import frames, qlog


def collect() -> tuple[list[str], qlog.QlogTrace]:
    lines: list[str] = []
    trace = qlog.QlogTrace(
        emit=lines.append,
        group_id="8394c8f03e515708",
        is_client=True,
        reference_time=1000.0,
    )
    return lines, trace


def parse(line: str) -> dict[str, Any]:
    """Strip the record separator and decode one JSON-SEQ record."""
    assert line.startswith(qlog.RECORD_SEPARATOR)
    assert line.endswith("\n")
    decoded: dict[str, Any] = json.loads(line[1:])
    return decoded


def test_header_declares_the_sequential_schema() -> None:
    lines, _ = collect()
    header = parse(lines[0])
    assert header["file_schema"] == "urn:ietf:params:qlog:file:sequential"
    assert header["serialization_format"] == "application/qlog+json-seq"
    # events §2.1: a draft implementation appends the draft number.
    assert header["trace"]["event_schemas"] == ["urn:ietf:params:qlog:events:quic-13"]
    assert header["trace"]["vantage_point"] == {"type": "client"}


def test_header_carries_the_legacy_version_and_format() -> None:
    """Readers predating the URI scheme require these fields."""
    lines, _ = collect()
    header = parse(lines[0])
    assert header["qlog_version"] == "0.3"
    assert header["qlog_format"] == "JSON-SEQ"


def test_common_fields_carry_the_group_id_and_reference_time() -> None:
    lines, _ = collect()
    common = parse(lines[0])["trace"]["common_fields"]
    assert common["group_id"] == "8394c8f03e515708"
    assert common["reference_time"] == {"clock_type": "monotonic", "epoch": "unknown"}


def test_a_wall_clock_anchors_a_monotonic_trace() -> None:
    """main-schema §8: an unknown epoch anchors on wall_clock_time."""
    lines: list[str] = []
    qlog.QlogTrace(
        emit=lines.append,
        group_id="ab",
        is_client=True,
        reference_time=0.0,
        wall_clock_time="2026-08-05T19:13:35.268Z",
    )
    reference = parse(lines[0])["trace"]["common_fields"]["reference_time"]
    assert reference["clock_type"] == "monotonic"
    assert reference["epoch"] == "unknown"
    assert reference["wall_clock_time"] == "2026-08-05T19:13:35.268Z"


def test_vantage_point_follows_the_role() -> None:
    lines: list[str] = []
    qlog.QlogTrace(emit=lines.append, group_id="ab", is_client=False, reference_time=0.0)
    assert parse(lines[0])["trace"]["vantage_point"] == {"type": "server"}


def test_event_time_is_milliseconds_from_the_reference() -> None:
    lines, trace = collect()
    trace.log(1000.25, qlog.PACKET_SENT, {"header": {"packet_number": 0}})
    event = parse(lines[1])
    assert event["time"] == 250.0  # a quarter second after the reference
    assert event["name"] == "quic:packet_sent"
    assert event["data"] == {"header": {"packet_number": 0}}


def test_each_event_is_its_own_record() -> None:
    """main-schema §5: one record per event, each framed on its own."""
    lines, trace = collect()
    trace.log(1000.0, qlog.PACKET_RECEIVED, {"header": {"packet_number": 1}})
    trace.log(1001.0, qlog.PACKET_DROPPED, {"trigger": qlog.DROP_KEY_UNAVAILABLE})

    assert len(lines) == 3  # the header, then one record per event
    assert all(line.startswith(qlog.RECORD_SEPARATOR) and line.endswith("\n") for line in lines)
    assert [parse(line)["name"] for line in lines[1:]] == [
        "quic:packet_received",
        "quic:packet_dropped",
    ]


def test_drop_triggers_are_schema_values() -> None:
    """events §5.7 defines the trigger vocabulary."""
    defined = {
        "internal_error",
        "rejected",
        "unsupported",
        "invalid",
        "duplicate",
        "connection_unknown",
        "decryption_failure",
        "key_unavailable",
        "general",
    }
    ours = {
        qlog.DROP_KEY_UNAVAILABLE,
        qlog.DROP_DECRYPTION_FAILURE,
        qlog.DROP_DUPLICATE,
        qlog.DROP_INVALID,
        qlog.DROP_UNSUPPORTED,
        qlog.DROP_GENERAL,
    }
    assert ours <= defined


def test_frame_types_use_the_schema_names() -> None:
    """events §8: frame names are lowercase with underscores."""
    assert qlog.frame_type(frames.Crypto(offset=0, data=b"")) == "crypto"
    assert qlog.frame_type(frames.HandshakeDone()) == "handshake_done"
    assert qlog.frame_type(frames.MaxStreamData(stream_id=0, maximum=1)) == "max_stream_data"
    assert qlog.frame_type(frames.Ping()) == "ping"


def test_every_frame_class_has_a_schema_name() -> None:
    """Every frame in frames.py maps to a schema name."""
    classes = {
        name
        for name, value in vars(frames).items()
        if isinstance(value, type) and dataclasses.is_dataclass(value) and name != "EcnCounts"
    }
    missing = {name for name in classes if name not in qlog.FRAME_TYPES}
    assert not missing, f"frames with no qlog name: {sorted(missing)}"


def test_ack_frame_records_the_ranges_it_covers() -> None:
    """events §8: an ACK reports `acked_ranges`, without which a trace
    cannot say which packets a peer confirmed."""
    detail = qlog.frame_detail(frames.Ack(largest=9, delay=0, ranges=[(7, 9), (2, 3)]))
    assert detail == {"frame_type": "ack", "acked_ranges": [(7, 9), (2, 3)]}
