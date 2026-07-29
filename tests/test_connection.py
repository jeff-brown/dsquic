"""Tests for dsquic.connection: an in-memory dsquic-to-dsquic connection."""

import datetime

import pytest

from dsquic import frames, hq
from dsquic.connection import (
    Connection,
    ConnectionConfig,
    ConnectionState,
    ConnectionTerminated,
    HandshakeConfirmed,
    StreamDataReceived,
)
from dsquic.packet import parse_long_header
from dsquic.tls import ClientConfig, EncryptionLevel, ServerConfig
from test_tls import Credentials, issue_leaf, make_ca

VERIFICATION_TIME = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


@pytest.fixture(scope="module")
def credentials() -> Credentials:
    ca_der, ca_key = make_ca()
    leaf_der, leaf_key = issue_leaf(ca_key, "localhost")
    return Credentials(chain=[leaf_der], key=leaf_key, ca=[ca_der], ca_key=ca_key)


def make_pair(
    credentials: Credentials,
    client_keylog: list[str] | None = None,
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
        config=ConnectionConfig(keylog=client_keylog.append if client_keylog is not None else None),
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
        config=ConnectionConfig(),
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


class TestRecovery:
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
