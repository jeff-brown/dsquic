"""Tests for dsquic.connection: an in-memory dsquic-to-dsquic connection."""

import datetime
import json
from collections.abc import Callable
from typing import Any

import pytest

from dsquic import frames, hq, qlog
from dsquic.connection import (
    DEFAULT_MAX_DATAGRAM_SIZE,
    PACING_BURST_DATAGRAMS,
    PROBE_PACKETS,
    Connection,
    ConnectionConfig,
    ConnectionState,
    ConnectionTerminated,
    HandshakeCompleted,
    HandshakeConfirmed,
    StreamDataReceived,
)
from dsquic.packet import parse_long_header
from dsquic.qlog import QlogTrace
from dsquic.recovery import MAX_PTO
from dsquic.tls import ClientConfig, EncryptionLevel, ServerConfig
from test_tls import Credentials, issue_leaf, make_ca

VERIFICATION_TIME = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


@pytest.fixture(scope="module")
def credentials() -> Credentials:
    ca_der, ca_key = make_ca()
    leaf_der, leaf_key = issue_leaf(ca_key, "localhost")
    return Credentials(chain=[leaf_der], key=leaf_key, ca=[ca_der], ca_key=ca_key)


def trace_into(sink: list[str]) -> Callable[[bytes, bool, float], QlogTrace]:
    """A qlog factory that appends finished records to ``sink``."""

    def open_trace(group_id: bytes, is_client: bool, reference_time: float) -> QlogTrace:
        return QlogTrace(
            emit=sink.append,
            group_id=group_id.hex(),
            is_client=is_client,
            reference_time=reference_time,
        )

    return open_trace


def qlog_events(records: list[str]) -> list[dict[str, Any]]:
    """Parse JSON-SEQ records, skipping the header (main-schema §5)."""
    events = [json.loads(record[1:]) for record in records]
    return [event for event in events if "name" in event]


def make_pair(
    credentials: Credentials,
    client_keylog: list[str] | None = None,
    client_qlog: list[str] | None = None,
    server_qlog: list[str] | None = None,
    key_update_interval: int | None = None,
) -> tuple[Connection, Connection]:
    client = Connection(
        is_client=True,
        client_config=ClientConfig(
            server_name="localhost",
            alpn=[hq.ALPN],
            transport_parameters=b"",
            ca_certificates=credentials.ca,
            verification_time=VERIFICATION_TIME,
        ),
        config=ConnectionConfig(
            keylog=client_keylog.append if client_keylog is not None else None,
            qlog=trace_into(client_qlog) if client_qlog is not None else None,
            key_update_interval=key_update_interval,
        ),
        destination="server",
    )
    server = Connection(
        is_client=False,
        server_config=ServerConfig(
            certificate_chain=credentials.chain,
            signing_key=credentials.key,
            alpn=[hq.ALPN],
            transport_parameters=b"",
        ),
        config=ConnectionConfig(
            qlog=trace_into(server_qlog) if server_qlog is not None else None,
        ),
        destination="client",
    )
    return client, server


def pump(client: Connection, server: Connection, now: float = 0.0, rounds: int = 12) -> float:
    """Exchange datagrams until both sides go quiet; returns the final clock."""
    for _ in range(rounds):
        moved = False
        for datagram in client.datagrams_to_send(now):
            server.datagram_received(datagram.data, now, source="client")
            moved = True
        now += 0.01
        for datagram in server.datagrams_to_send(now):
            client.datagram_received(datagram.data, now, source="server")
            moved = True
        now += 0.01
        if not moved:
            return now
    return now


def assert_exactly_packets(data: bytes) -> None:
    """Every byte of the datagram belongs to a parseable packet (§12.2)."""
    offset = 0
    while offset < len(data):
        first = data[offset]
        assert first & 0x40, f"packet at offset {offset} has no fixed bit: 0x{first:02x}"
        if not first & 0x80:
            return  # short header: runs to the end of the datagram
        header = parse_long_header(data[offset:])
        offset += header.pn_offset + header.length
    assert offset == len(data), f"{len(data) - offset} trailing bytes after the last packet"


def handshake(credentials: Credentials, **kwargs: object) -> tuple[Connection, Connection, float]:
    client, server = make_pair(credentials, **kwargs)  # type: ignore[arg-type]
    client.connect(0.0)
    now = pump(client, server)
    return client, server, now


class TestHandshake:
    def test_completes_on_both_sides(self, credentials: Credentials) -> None:
        client, server, _ = handshake(credentials)
        assert client.state is ConnectionState.CONNECTED
        assert server.state is ConnectionState.CONNECTED
        assert client.alpn == hq.ALPN
        assert server.alpn == hq.ALPN

    def test_emits_handshake_confirmed(self, credentials: Credentials) -> None:
        client, server, _ = handshake(credentials)
        assert any(isinstance(e, HandshakeConfirmed) for e in client.take_events())
        assert any(isinstance(e, HandshakeConfirmed) for e in server.take_events())

    def test_completion_precedes_confirmation_at_the_client(self, credentials: Credentials) -> None:
        """RFC 9001 §4.1.1 vs §4.1.2. A client is complete when its TLS
        handshake finishes and confirmed only on HANDSHAKE_DONE, which
        can be lost. Gating application data on confirmation strands the
        connection: one was seen retransmitting Handshake CRYPTO for 38
        seconds while the server, already in 1-RTT, waited for a request.
        """
        client, server = make_pair(credentials)
        client.connect(0.0)
        now = 0.0
        # Deliver the server's flight but none of the 1-RTT packets that
        # would carry HANDSHAKE_DONE.
        for datagram in client.datagrams_to_send(now):
            server.datagram_received(datagram.data, now, source="client")
        now = 0.1
        for datagram in server.datagrams_to_send(now):
            client.datagram_received(datagram.data, now, source="server")

        events = client.take_events()
        assert any(isinstance(event, HandshakeCompleted) for event in events)
        assert not any(isinstance(event, HandshakeConfirmed) for event in events)
        # Complete is enough to open a stream and send on it.
        stream_id = client.open_stream()
        client.send_stream_data(stream_id, hq.encode_request("/index"), end_stream=True)
        assert client.datagrams_to_send(now)

    def test_transport_parameters_exchanged(self, credentials: Credentials) -> None:
        client, server, _ = handshake(credentials)
        assert client.peer_parameters is not None
        assert server.peer_parameters is not None
        assert client.peer_parameters.initial_max_data > 0
        # §7.3: the server echoes the client's original destination CID.
        assert client.peer_parameters.original_destination_connection_id is not None

    def test_first_flight_is_padded_to_1200(self, credentials: Credentials) -> None:
        client, _ = make_pair(credentials)
        client.connect(0.0)
        first = client.datagrams_to_send(0.0)
        assert first
        assert len(first[0].data) >= 1200  # §14.1

    def test_datagrams_contain_no_trailing_bytes(self, credentials: Credentials) -> None:
        """§14.1 padding is PADDING frames inside a packet, never bytes
        appended to the datagram: a short header packet runs to the end
        of the datagram, so trailing bytes would corrupt it."""
        client, server = make_pair(credentials)
        client.connect(0.0)
        now = 0.0
        for _ in range(6):
            for datagram in client.datagrams_to_send(now):
                assert_exactly_packets(datagram.data)
                server.datagram_received(datagram.data, now, source="client")
            now += 0.01
            for datagram in server.datagrams_to_send(now):
                assert_exactly_packets(datagram.data)
                client.datagram_received(datagram.data, now, source="server")
            now += 0.01
        assert client.state is ConnectionState.CONNECTED

    def test_initial_and_handshake_keys_discarded(self, credentials: Credentials) -> None:
        client, server, _ = handshake(credentials)
        for connection in (client, server):
            assert connection.keys_discarded(EncryptionLevel.INITIAL)
            assert connection.keys_discarded(EncryptionLevel.HANDSHAKE)

    def test_keylog_emitted(self, credentials: Credentials) -> None:
        lines: list[str] = []
        handshake(credentials, client_keylog=lines)
        assert [line.split()[0] for line in lines] == [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
        ]


class TestStreams:
    def test_hq_request_response(self, credentials: Credentials) -> None:
        client, server, now = handshake(credentials)
        client.take_events()
        server.take_events()

        stream_id = client.open_stream()
        client.send_stream_data(stream_id, hq.encode_request("/index.html"), end_stream=True)
        now = pump(client, server, now)

        request_events = [e for e in server.take_events() if isinstance(e, StreamDataReceived)]
        assert request_events
        received = b"".join(e.data for e in request_events)
        assert hq.parse_request(received) == "/index.html"
        assert request_events[-1].end_stream

        body = b"<html>hello from dsquic</html>"
        server.send_stream_data(stream_id, body, end_stream=True)
        pump(client, server, now)

        response_events = [e for e in client.take_events() if isinstance(e, StreamDataReceived)]
        assert b"".join(e.data for e in response_events) == body
        assert response_events[-1].end_stream

    def test_large_transfer_spans_packets(self, credentials: Credentials) -> None:
        client, server, now = handshake(credentials)
        client.take_events()
        server.take_events()
        stream_id = client.open_stream()
        payload = bytes(range(256)) * 200  # 51200 bytes, many packets
        client.send_stream_data(stream_id, payload, end_stream=True)
        pump(client, server, now, rounds=80)
        events = [e for e in server.take_events() if isinstance(e, StreamDataReceived)]
        assert b"".join(e.data for e in events) == payload
        assert events[-1].end_stream

    def test_server_opened_stream(self, credentials: Credentials) -> None:
        client, server, now = handshake(credentials)
        client.take_events()
        server.take_events()
        stream_id = server.open_stream()
        assert stream_id % 4 == 1  # server-initiated bidirectional (§2.1)
        server.send_stream_data(stream_id, b"push", end_stream=True)
        pump(client, server, now)
        events = [e for e in client.take_events() if isinstance(e, StreamDataReceived)]
        assert b"".join(e.data for e in events) == b"push"


class TestQlog:
    """qlog output (draft-ietf-quic-qlog-quic-events-13)."""

    def make_traced_pair(
        self, credentials: Credentials
    ) -> tuple[Connection, Connection, list[str], list[str]]:
        client_lines: list[str] = []
        server_lines: list[str] = []
        client, server = make_pair(credentials, client_qlog=client_lines, server_qlog=server_lines)
        return client, server, client_lines, server_lines

    def names(self, lines: list[str]) -> list[str]:
        events = [json.loads(line[1:]) for line in lines[1:]]
        return [event["name"] for event in events]

    def test_a_handshake_produces_both_traces(self, credentials: Credentials) -> None:
        client, server, client_lines, server_lines = self.make_traced_pair(credentials)
        client.connect(0.0)
        pump(client, server)

        group_ids: set[str] = set()
        for lines, role in ((client_lines, "client"), (server_lines, "server")):
            header = json.loads(lines[0][1:])
            assert header["trace"]["vantage_point"] == {"type": role}
            group_ids.add(header["trace"]["common_fields"]["group_id"])
            assert "quic:packet_sent" in self.names(lines)
            assert "quic:packet_received" in self.names(lines)

        # §4.2: both endpoints key the trace on the original DCID.
        assert len(group_ids) == 1

    def test_a_silently_dropped_packet_is_recorded(self, credentials: Credentials) -> None:
        """events §5.7: a discarded packet is recorded with its trigger."""
        client, server, _, server_lines = self.make_traced_pair(credentials)
        client.connect(0.0)
        pump(client, server)

        # A packet the server cannot authenticate: right shape, wrong bytes.
        corrupt = bytes([0x40]) + client.peer_cid + bytes(64)
        server.datagram_received(corrupt, 1.0, source="client")

        dropped = [
            json.loads(line[1:])
            for line in server_lines[1:]
            if json.loads(line[1:])["name"] == "quic:packet_dropped"
        ]
        assert dropped, "the discard was not recorded"
        assert dropped[-1]["data"]["trigger"] in {
            qlog.DROP_DECRYPTION_FAILURE,
            qlog.DROP_KEY_UNAVAILABLE,
            qlog.DROP_INVALID,
        }


class TestStreamLimits:
    """§4.6: MAX_STREAMS keeps a long-lived connection from running out."""

    def test_more_streams_than_the_initial_limit(self, credentials: Credentials) -> None:
        """The initial limit is 16 bidirectional streams, so without
        MAX_STREAMS the seventeenth request fails."""
        client, server, now = handshake(credentials)
        client.take_events()
        server.take_events()

        wanted = 40
        answered: set[int] = set()
        for index in range(wanted):
            stream_id = client.open_stream()
            client.send_stream_data(stream_id, hq.encode_request(f"/{index}"), end_stream=True)
            now = pump(client, server, now)
            for event in server.take_events():
                if isinstance(event, StreamDataReceived) and event.end_stream:
                    answered.add(event.stream_id)
                    server.send_stream_data(event.stream_id, b"body", end_stream=True)
            now = pump(client, server, now)
            for event in client.take_events():
                if isinstance(event, StreamDataReceived):
                    pass  # drain, so the receiving halves reach Data Read

        assert len(answered) == wanted


class TestRecovery:
    def test_a_silent_peer_eventually_times_the_connection_out(
        self, credentials: Credentials
    ) -> None:
        """§10.1: the idle period is the negotiated timeout floored at
        three times the PTO, where "the PTO" is the unscaled one.

        Reading it as the backed-off PTO instead would make the deadline
        recede exactly as fast as the backoff grows, and a connection
        that keeps losing probes would never time out at all. quic-go
        and aioquic both use the unscaled value.
        """
        client, _ = make_pair(credentials)
        client.connect(0.0)
        assert client.datagrams_to_send(0.0)  # nothing reaches the server

        now = 0.0
        for _ in range(40):
            timer = client.next_timer()
            assert timer is not None
            now = timer
            client.handle_timer(now)
            client.datagrams_to_send(now)
            if client.state is ConnectionState.TERMINATED:
                break

        assert client.state is ConnectionState.TERMINATED
        # The negotiated 30s dominates the 3 x PTO floor at these RTTs.
        assert 30.0 <= now < 40.0

    def test_pto_backoff_is_capped(self, credentials: Credentials) -> None:
        """RFC 8961 §4: a maximum MAY be placed on the timer, and MUST
        NOT be less than 60 seconds. RFC 9002 sets no ceiling of its own,
        so without one the interval doubles past any useful timescale.
        """
        client, _ = make_pair(credentials)
        client.connect(0.0)
        client.datagrams_to_send(0.0)

        now = 0.0
        for _ in range(30):
            timer = client.next_timer()
            assert timer is not None
            previous, now = now, timer
            client.handle_timer(now)
            client.datagrams_to_send(now)
            assert now - previous <= MAX_PTO
            if client.state is ConnectionState.TERMINATED:
                break
        assert client.recovery.pto() < MAX_PTO  # unscaled, so far below it

    def test_handshake_completes_when_a_large_flight_is_lost(self) -> None:
        """§13.3: a lost CRYPTO frame is resent with the offset it was
        sent with.

        Splicing lost bytes back into the pending buffer instead would
        mislabel every frame sent after them, since that buffer's first
        byte is by definition the next offset to send. The peer's TLS
        then reassembles bytes under the wrong offsets and fails.

        The certificate is deliberately large: the server's flight has
        to outrun its §8.1 amplification budget so that CRYPTO bytes are
        still waiting to be sent when an earlier packet is declared
        lost. That is the state in which the offsets diverge.
        """
        ca_der, ca_key = make_ca()
        leaf_der, leaf_key = issue_leaf(ca_key, "localhost", extra_names=200)
        credentials = Credentials(chain=[leaf_der], key=leaf_key, ca=[ca_der], ca_key=ca_key)
        client, server = make_pair(credentials)
        client.connect(0.0)
        now = 0.0
        datagrams = 0
        for _ in range(80):
            for datagram in client.datagrams_to_send(now):
                datagrams += 1
                if datagrams % 3:  # every third datagram is lost
                    server.datagram_received(datagram.data, now, source="client")
            now += 0.01
            for datagram in server.datagrams_to_send(now):
                datagrams += 1
                if datagrams % 3:
                    client.datagram_received(datagram.data, now, source="server")
            now += 0.01
            for connection in (client, server):
                timer = connection.next_timer()
                if timer is not None and timer <= now:
                    connection.handle_timer(now)
            if ConnectionState.CONNECTED is client.state is server.state:
                break

        assert client.state is ConnectionState.CONNECTED
        assert server.state is ConnectionState.CONNECTED

    def test_pto_sends_two_probes(self, credentials: Credentials) -> None:
        """§6.2.4: up to two datagrams per PTO, "to avoid an expensive
        consecutive PTO expiration due to a single lost datagram".

        The PTO doubles on every expiry, so one unlucky probe costs more
        than a round trip: it doubles the wait for every attempt after
        it. Both probes carry the outstanding flight: the first from the
        retransmit queue, the second as a copy, since every probe packet
        must be ack-eliciting and RFC 9000 §17.2.2 requires a CRYPTO
        frame in the first packet a client sends.
        """
        client, _ = make_pair(credentials)
        client.connect(0.0)
        assert len(client.datagrams_to_send(0.0)) == 1  # the first flight, lost

        probe_at = client.next_timer()
        assert probe_at is not None
        client.handle_timer(probe_at)
        probes = client.datagrams_to_send(probe_at)
        assert len(probes) == 2
        for probe in probes:
            assert len(probe.data) >= 1200  # §14.1 still applies to a probe

    def test_a_pto_never_grows_the_flight(self, credentials: Credentials) -> None:
        """§6.2.4 allows up to two datagrams per PTO. Requeueing the whole
        outstanding flight instead doubles it at every expiry: 2, 3, 6,
        12, 24 datagrams were observed against aioquic, since the small
        CRYPTO fragments never fill the congestion window.
        """
        client, server = make_pair(credentials)
        client.connect(0.0)
        for datagram in client.datagrams_to_send(0.0):
            server.datagram_received(datagram.data, 0.0, source="client")
        for datagram in server.datagrams_to_send(0.1):
            client.datagram_received(datagram.data, 0.1, source="server")
        client.datagrams_to_send(0.2)  # the client's flight, black holed

        for _ in range(5):
            deadline = client.next_timer()
            assert deadline is not None
            client.handle_timer(deadline)
            assert len(client.datagrams_to_send(deadline)) <= PROBE_PACKETS

    def test_every_initial_probe_carries_crypto(self, credentials: Credentials) -> None:
        """RFC 9000 §17.2.2: "The first packet sent by a client always
        includes a CRYPTO frame". When the ClientHello is lost, a probe
        is the first Initial the server sees, and a bare PING leaves it
        with a connection it cannot advance: aioquic closes one with
        PROTOCOL_VIOLATION, which is the runner's handshakeloss failure.
        """
        records: list[str] = []
        client, _ = make_pair(credentials, client_qlog=records)
        client.connect(0.0)
        client.datagrams_to_send(0.0)  # the ClientHello, lost

        probe_at = client.next_timer()
        assert probe_at is not None
        client.handle_timer(probe_at)
        assert len(client.datagrams_to_send(probe_at)) == 2

        probes = [
            event
            for event in qlog_events(records)
            if event["name"] == "quic:packet_sent"
            and event["data"]["header"]["packet_type"] == "initial"
            and event["time"] > 0
        ]
        assert len(probes) == 2
        for probe in probes:
            assert "crypto" in [frame["frame_type"] for frame in probe["data"]["frames"]]

    def test_one_rtt_is_not_processed_before_the_handshake_completes(
        self, credentials: Credentials
    ) -> None:
        """RFC 9001 §5.7: a server does not process 1-RTT packets before
        the handshake completes, and does not acknowledge them.

        It holds 1-RTT keys once it has sent its Finished, so a packet
        overtaking the client's Finished decrypts successfully.
        """
        client, server = make_pair(credentials)
        client.connect(0.0)
        now = 0.0
        # Run the handshake far enough that the server has 1-RTT keys but
        # has not seen the client's Finished: deliver only to the client.
        for _ in range(4):
            for datagram in client.datagrams_to_send(now):
                server.datagram_received(datagram.data, now, source="client")
            now += 0.01
            server_flight = server.datagrams_to_send(now)
            for datagram in server_flight:
                client.datagram_received(datagram.data, now, source="server")
            now += 0.01
            if server_flight:
                break

        assert server.state is ConnectionState.HANDSHAKING
        client.take_events()
        stream_id = client.open_stream()
        client.send_stream_data(stream_id, hq.encode_request("/early"), end_stream=True)
        # Deliver only the 1-RTT packets, holding back the Finished.
        for datagram in client.datagrams_to_send(now):
            if not datagram.data[0] & 0x80:
                server.datagram_received(datagram.data, now, source="client")

        # The packet is dropped rather than acted on, so the server is
        # still waiting for the Finished and has raised no error.
        assert not [e for e in server.take_events() if isinstance(e, ConnectionTerminated)]
        assert server.state is ConnectionState.HANDSHAKING

    def test_lost_handshake_done_is_retransmitted(self, credentials: Credentials) -> None:
        """§13.3: HANDSHAKE_DONE is retransmitted until acknowledged.

        The client confirms the handshake on this frame alone, and
        confirmation discards its Handshake keys (RFC 9001 §4.9.2).
        """
        client, server = make_pair(credentials)
        client.connect(0.0)
        now = 0.0
        dropped = False
        for _ in range(40):
            for datagram in client.datagrams_to_send(now):
                server.datagram_received(datagram.data, now, source="client")
            now += 0.01
            for datagram in server.datagrams_to_send(now):
                # The server's first short-header datagram is the one
                # carrying HANDSHAKE_DONE.
                if not dropped and not datagram.data[0] & 0x80:
                    dropped = True
                    continue
                client.datagram_received(datagram.data, now, source="server")
            now += 0.01
            for connection in (client, server):
                timer = connection.next_timer()
                if timer is not None and timer <= now:
                    connection.handle_timer(now)
            if dropped and client.keys_discarded(EncryptionLevel.HANDSHAKE):
                break

        assert dropped, "the server never sent a 1-RTT packet to drop"
        assert client.keys_discarded(EncryptionLevel.HANDSHAKE)

    def test_lost_client_hello_is_retransmitted_on_pto(self, credentials: Credentials) -> None:
        """§6.2.4: before any ACK arrives, PTO is the only loss signal, so
        the probe has to carry the ClientHello. A bare PING is
        ack-eliciting but redelivers nothing, and the handshake would sit
        there until the idle timer.
        """
        client, server = make_pair(credentials)
        client.connect(0.0)
        assert client.datagrams_to_send(0.0)  # the whole first flight is lost

        probe_at = client.next_timer()
        assert probe_at is not None
        client.handle_timer(probe_at)
        assert client.state is not ConnectionState.TERMINATED

        pump(client, server, probe_at)
        assert client.state is ConnectionState.CONNECTED
        assert server.state is ConnectionState.CONNECTED

    def test_lost_packet_is_retransmitted(self, credentials: Credentials) -> None:
        client, server, now = handshake(credentials)
        client.take_events()
        server.take_events()
        stream_id = client.open_stream()
        client.send_stream_data(stream_id, b"important payload", end_stream=True)

        dropped = client.datagrams_to_send(now)
        assert dropped  # deliberately never delivered
        now += 1.0

        # The PTO fires; the client probes and retransmits the lost frames.
        for _ in range(6):
            timeout = client.next_timer()
            if timeout is None:
                break
            now = max(now, timeout)
            client.handle_timer(now)
            now = pump(client, server, now, rounds=4)

        events = [e for e in server.take_events() if isinstance(e, StreamDataReceived)]
        assert b"".join(e.data for e in events) == b"important payload"

    def test_timer_is_armed_during_handshake(self, credentials: Credentials) -> None:
        client, _ = make_pair(credentials)
        client.connect(0.0)
        client.datagrams_to_send(0.0)
        assert client.next_timer() is not None


class TestTermination:
    def test_close_notifies_peer(self, credentials: Credentials) -> None:
        client, server, now = handshake(credentials)
        client.take_events()
        server.take_events()
        client.close(error_code=frames.NO_ERROR, reason="done")
        pump(client, server, now)
        terminated = [e for e in server.take_events() if isinstance(e, ConnectionTerminated)]
        assert terminated and terminated[0].reason == "done"
        assert server.state is ConnectionState.DRAINING

    def test_draining_connection_sends_nothing(self, credentials: Credentials) -> None:
        client, server, now = handshake(credentials)
        client.close()
        pump(client, server, now)
        assert server.datagrams_to_send(now + 1.0) == []


class TestAntiAmplification:
    def test_server_send_is_capped_before_validation(self, credentials: Credentials) -> None:
        client, server = make_pair(credentials)
        client.connect(0.0)
        first = client.datagrams_to_send(0.0)
        received = sum(len(datagram.data) for datagram in first)
        for datagram in first:
            server.datagram_received(datagram.data, 0.0, source="client")
        sent = sum(len(datagram.data) for datagram in server.datagrams_to_send(0.01))
        assert sent <= 3 * received  # §8.1


class TestKeyUpdate:
    """RFC 9001 §6. Reached in practice because quic-go updates keys
    partway through a transfer, which stalls a peer that cannot follow.
    """

    def fetch(self, credentials: Credentials) -> tuple[Connection, Connection, int, float]:
        """Handshake and open a stream, leaving both sides idle."""
        client, server, now = handshake(credentials)
        stream_id = client.open_stream()
        client.send_stream_data(stream_id, b"GET /\r\n", end_stream=True)
        now = pump(client, server, now)
        return client, server, stream_id, now

    def test_follows_a_peer_key_update(self, credentials: Credentials) -> None:
        client, server, stream_id, now = self.fetch(credentials)
        assert server.initiate_key_update(now)
        server.send_stream_data(stream_id, b"after the update", end_stream=True)
        pump(client, server, now)

        received = [
            event for event in client.take_events() if isinstance(event, StreamDataReceived)
        ]
        assert b"".join(event.data for event in received) == b"after the update"
        assert client.key_phase() is True

    def test_sends_in_the_new_phase_after_following(self, credentials: Credentials) -> None:
        """§6.2: send keys update before the update is acknowledged, so
        the peer must be able to read what comes back."""
        client, server, stream_id, now = self.fetch(credentials)
        assert server.initiate_key_update(now)
        server.send_stream_data(stream_id, b"after the update", end_stream=True)
        now = pump(client, server, now)

        client.send_stream_data(client.open_stream(), b"reply", end_stream=True)
        pump(client, server, now)
        replies = [event for event in server.take_events() if isinstance(event, StreamDataReceived)]
        assert b"reply" in b"".join(event.data for event in replies)

    def reorder_across_update(
        self, credentials: Credentials, delay: float
    ) -> tuple[Connection, bytes]:
        """Hold back a packet sent before a key update and deliver it
        ``delay`` seconds after the packet that carried the update.

        Delivery is explicit rather than pumped: a pump lets the server
        retransmit the held-back data in the new phase, which would
        answer the question by the wrong route.
        """
        client, server, stream_id, now = self.fetch(credentials)
        server.send_stream_data(stream_id, b"before ", end_stream=False)
        held = [datagram.data for datagram in server.datagrams_to_send(now)]
        assert held

        assert server.initiate_key_update(now)
        server.send_stream_data(stream_id, b"after", end_stream=True)
        for datagram in server.datagrams_to_send(now):
            client.datagram_received(datagram.data, now, source="server")
        for data in held:
            client.datagram_received(data, now + delay, source="server")

        received = [
            event for event in client.take_events() if isinstance(event, StreamDataReceived)
        ]
        return client, b"".join(event.data for event in received)

    def test_update_needs_an_ack_from_the_current_phase(self, credentials: Credentials) -> None:
        """§6.1: no second update until the peer acknowledges a packet
        sent in the phase the first one started."""
        client, server, stream_id, now = self.fetch(credentials)
        assert server.initiate_key_update(now)
        assert not server.initiate_key_update(now)

        server.send_stream_data(stream_id, b"after the update", end_stream=True)
        now = pump(client, server, now)
        assert server.initiate_key_update(now)

    def test_update_is_refused_before_the_handshake_is_confirmed(
        self, credentials: Credentials
    ) -> None:
        """§6.1: 1-RTT keys alone are not enough."""
        client, _ = make_pair(credentials)
        client.connect(0.0)
        assert not client.initiate_key_update(0.0)

    def test_reordered_packet_from_the_previous_phase(self, credentials: Credentials) -> None:
        """§6.5: a packet sent before the update still decrypts."""
        _, received = self.reorder_across_update(credentials, delay=0.0)
        assert received == b"before after"

    def test_previous_phase_keys_expire(self, credentials: Credentials) -> None:
        """§6.5: old read keys last three PTOs and no longer, after which
        the packet is undecryptable rather than merely late."""
        _, received = self.reorder_across_update(credentials, delay=3600.0)
        assert received == b""


class TestPacing:
    """RFC 9002 §7.7."""

    def paced_client(self, credentials: Credentials) -> tuple[Connection, Connection, float, int]:
        """A client with more to send than the window, past slow start's
        first round so the window exceeds the burst limit."""
        client, server, now = handshake(credentials)
        stream_id = client.open_stream()
        client.send_stream_data(stream_id, b"x" * 400_000)
        return client, server, pump(client, server, now, rounds=1), stream_id

    def test_a_burst_is_limited_to_the_initial_window(self, credentials: Credentials) -> None:
        client, _, now, _ = self.paced_client(credentials)
        burst = client.datagrams_to_send(now)
        assert burst
        assert sum(len(d.data) for d in burst) <= PACING_BURST_DATAGRAMS * DEFAULT_MAX_DATAGRAM_SIZE

    def test_credit_refills_over_time(self, credentials: Credentials) -> None:
        """Time alone releases more data. No acknowledgement arrives in
        between, so the window does not move: the pacer held it back."""
        client, _, now, _ = self.paced_client(credentials)
        assert client.datagrams_to_send(now)
        assert client.datagrams_to_send(now) == []
        deadline = client.next_timer()
        assert deadline is not None
        assert client.datagrams_to_send(deadline)

    def test_acknowledgements_are_not_paced(self, credentials: Credentials) -> None:
        client, server, now, stream_id = self.paced_client(credentials)
        client.datagrams_to_send(now)
        assert client.datagrams_to_send(now) == []
        server.send_stream_data(stream_id, b"pong")
        for datagram in server.datagrams_to_send(now):
            client.datagram_received(datagram.data, now, source="server")
        answer = client.datagrams_to_send(now)
        assert answer
        assert all(len(d.data) < DEFAULT_MAX_DATAGRAM_SIZE for d in answer)


class TestClientKeyUpdate:
    """RFC 9001 §6.1, driven by ConnectionConfig.key_update_interval."""

    def transfer(self, client: Connection, server: Connection, now: float) -> tuple[bytes, float]:
        """Send one request and read the answer back; returns the body."""
        stream_id = client.open_stream()
        client.send_stream_data(stream_id, hq.encode_request("/index"), end_stream=True)
        now = pump(client, server, now)
        for event in server.take_events():
            if isinstance(event, StreamDataReceived):
                server.send_stream_data(event.stream_id, b"body", end_stream=True)
        now = pump(client, server, now)
        body = b"".join(
            event.data for event in client.take_events() if isinstance(event, StreamDataReceived)
        )
        return body, now

    def test_the_client_starts_a_new_phase_and_data_keeps_flowing(
        self, credentials: Credentials
    ) -> None:
        client, server = make_pair(credentials, key_update_interval=1)
        client.connect(0.0)
        now = pump(client, server)
        phase = client.key_phase()
        body, now = self.transfer(client, server, now)
        assert body == b"body"
        assert client.key_phase() is not phase
        # The peer followed, and the next exchange runs in the new phase.
        body, _ = self.transfer(client, server, now)
        assert body == b"body"
        assert server.key_phase() is client.key_phase()

    def test_no_update_without_the_policy(self, credentials: Credentials) -> None:
        client, server = make_pair(credentials)
        client.connect(0.0)
        now = pump(client, server)
        phase = client.key_phase()
        self.transfer(client, server, now)
        assert client.key_phase() is phase
