"""Tests for dsquic.endpoints.server."""

import selectors
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import INDEX_BODY, LARGE_BODY, PemCredentials
from dsquic import hq
from dsquic.endpoints import load_pem_certificates
from dsquic.endpoints.client import ClientOptions, fetch
from dsquic.endpoints.server import Server, ServerOptions, load_credentials, resolve
from dsquic.packet import (
    QUIC_V1,
    LongHeaderTemplate,
    PacketType,
    build_long_header,
    destination_connection_id,
)
from dsquic.retry import is_retry
from dsquic.tls import ServerConfig


def test_load_credentials(credentials: PemCredentials) -> None:
    chain, key = load_credentials(credentials.certificate_pem, credentials.private_key_pem)
    assert len(chain) == 1
    assert chain[0][:1] == b"\x30"  # DER SEQUENCE
    assert key.key_size >= 256


def test_resolve_serves_files(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_bytes(b"<html>root</html>")
    assert resolve(tmp_path, "/index.html") == b"<html>root</html>"


def test_resolve_missing_file(tmp_path: Path) -> None:
    assert resolve(tmp_path, "/absent.bin") is None


def test_resolve_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "www"
    root.mkdir()
    (tmp_path / "secret.txt").write_bytes(b"private")
    # Even if a path slips past hq.parse_request, the document root is
    # the security boundary.
    assert resolve(root, "/../secret.txt") is None


def test_resolve_rejects_directory(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    assert resolve(tmp_path, "/subdir") is None


def test_load_credentials_rejects_bad_key(tmp_path: Path, credentials: PemCredentials) -> None:
    bogus = tmp_path / "bogus.pem"
    bogus.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
    with pytest.raises(ValueError):
        load_credentials(credentials.certificate_pem, bogus)


class TestDestinationConnectionId:
    """RFC 8999 §5.1: routing reads only version-independent fields."""

    def test_long_header(self) -> None:
        datagram = b"\xc3" + bytes(4) + bytes([8]) + b"\xaa" * 8 + b"rest"
        assert destination_connection_id(datagram, 8) == b"\xaa" * 8

    def test_long_header_of_an_unknown_version(self) -> None:
        # A version we cannot speak still routes: the CID fields are
        # version independent, which is the whole point of RFC 8999.
        datagram = b"\xc3" + b"\x6b\x33\x43\xcf" + bytes([4]) + b"\xbb" * 4
        assert destination_connection_id(datagram, 8) == b"\xbb" * 4

    def test_short_header_uses_the_local_length(self) -> None:
        datagram = b"\x41" + b"\xcc" * 8 + b"payload"
        assert destination_connection_id(datagram, 8) == b"\xcc" * 8

    def test_truncated_datagrams(self) -> None:
        assert destination_connection_id(b"", 8) is None
        assert destination_connection_id(b"\xc3\x00\x00", 8) is None
        assert destination_connection_id(b"\x41\xcc", 8) is None

    def test_oversized_length_is_rejected(self) -> None:
        datagram = b"\xc3" + bytes(4) + bytes([21]) + b"\xaa" * 21
        assert destination_connection_id(datagram, 8) is None


@pytest.fixture
def running_server(
    credentials: PemCredentials, document_root: Path
) -> Iterator[tuple[int, Server]]:
    """A server on a loopback port, serving until the test finishes."""
    chain, key = load_credentials(credentials.certificate_pem, credentials.private_key_pem)
    config = ServerConfig(
        certificate_chain=chain, signing_key=key, alpn=[hq.ALPN], transport_parameters=b""
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    server = Server(
        sock, selector, config, ServerOptions(document_root=document_root, idle_timeout=10.0)
    )

    stop = threading.Event()

    def run() -> None:
        while not stop.is_set():
            server.poll()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield port, server
    finally:
        stop.set()
        thread.join(timeout=10)
        selector.close()
        sock.close()


@pytest.mark.parametrize("retry", [True, False])
def test_an_unusable_token_gets_a_retry_not_silence(
    credentials: PemCredentials, tmp_path: Path, retry: bool
) -> None:
    """RFC 9000 §8.1.3: an Initial whose token does not validate leaves
    the client unvalidated rather than unheard, "including potentially
    sending a Retry packet".

    Reachable without NEW_TOKEN ever being implemented: the key that
    authenticates Retry tokens is generated per process, so a client that
    reconnects with a token issued before a restart presents one this
    server cannot check. Discarding it would hang that client until its
    idle timer.
    """
    chain, key = load_credentials(credentials.certificate_pem, credentials.private_key_pem)
    config = ServerConfig(
        certificate_chain=chain, signing_key=key, alpn=[hq.ALPN], transport_parameters=b""
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    server = Server(
        sock,
        selector,
        config,
        # Short, because poll() blocks until its next deadline: with a
        # long one, a server that correctly stays silent would hang this
        # test rather than fail it.
        ServerOptions(document_root=tmp_path, idle_timeout=0.05, retry=retry),
    )

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Short, because the failure this guards against is silence:
    # a long timeout would make a broken server hang the suite
    # rather than fail it.
    client.settimeout(0.05)
    destination_cid = bytes(range(8))
    template = LongHeaderTemplate(
        packet_type=PacketType.INITIAL,
        version=QUIC_V1,
        destination_cid=destination_cid,
        source_cid=b"\x09" * 8,
        token=b"a token from some earlier connection",
    )
    # §14.1: a client Initial datagram is at least 1200 bytes. The
    # payload is never decrypted here: address validation reads only the
    # header, and answers before any key is involved.
    payload = b"\x00" * 1100
    initial = (
        build_long_header(
            template, payload_length=len(payload), packet_number=0, packet_number_length=1
        )
        + payload
    )
    try:
        client.sendto(initial, ("127.0.0.1", port))
        answer = None
        for _ in range(20):
            server.poll()
            try:
                answer, _ = client.recvfrom(2048)
            except TimeoutError:
                continue
            break
        if retry:
            assert answer is not None, "the server never answered"
            assert is_retry(answer)
        else:
            # The same datagram, with address validation off, draws no
            # Retry: what the assertion above tests is the policy, not
            # some unconditional reply.
            assert answer is None
    finally:
        client.close()
        selector.close()
        sock.close()


def client_fetch(port: int, credentials: PemCredentials, path: str) -> bytes:
    bodies = fetch(
        host="127.0.0.1",
        port=port,
        paths=[path],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
            timeout=20.0,
        ),
    )
    return bodies[path]


class TestConnectionTable:
    def test_sequential_connections_on_one_socket(
        self, credentials: PemCredentials, running_server: tuple[int, Server]
    ) -> None:
        port, server = running_server
        for _ in range(3):
            assert client_fetch(port, credentials, "/index.html") == INDEX_BODY
        # Closed connections drain for a few PTOs before the table drops
        # them (§10.2), so the count trails the transfers.
        deadline = time.monotonic() + 10
        while server.connections_served < 3 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.connections_served == 3

    def test_concurrent_connections_are_kept_apart(
        self, credentials: PemCredentials, running_server: tuple[int, Server]
    ) -> None:
        """Several clients at once, each getting its own body: the proof
        that routing by connection ID keeps the state separate."""
        port, _server = running_server
        wanted = ["/index.html", "/large.bin", "/index.html", "/large.bin"]
        results: dict[int, bytes] = {}

        def worker(index: int, path: str) -> None:
            results[index] = client_fetch(port, credentials, path)

        threads = [
            threading.Thread(target=worker, args=(index, path), daemon=True)
            for index, path in enumerate(wanted)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        expected = {0: INDEX_BODY, 1: LARGE_BODY, 2: INDEX_BODY, 3: LARGE_BODY}
        assert results == expected
