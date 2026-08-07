"""Tests for dsquic.endpoints.client, including loopback over real UDP.

Verification ladder rung 2 (design.md §6.2): dsquic against dsquic
through the reference endpoints, datagrams crossing the kernel on the
loopback interface with a real clock.
"""

import selectors
import socket
import threading
import time
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from conftest import PemCredentials
from dsquic import hq
from dsquic.endpoints import load_pem_certificates
from dsquic.endpoints.client import ClientOptions, fetch, fetch_each
from dsquic.endpoints.server import Server, ServerOptions, load_credentials
from dsquic.tls import ServerConfig

INDEX_BODY = b"<html>hello from dsquic over real UDP</html>"
LARGE_BODY = bytes(range(256)) * 400  # 102400 bytes: many packets, real ACKs


@pytest.fixture
def document_root(tmp_path: Path) -> Path:
    root = tmp_path / "www"
    root.mkdir()
    (root / "index.html").write_bytes(INDEX_BODY)
    (root / "large.bin").write_bytes(LARGE_BODY)
    return root


@contextmanager
def running_server(
    credentials: PemCredentials,
    document_root: Path,
    connection_limit: int,
    family: socket.AddressFamily = socket.AF_INET,
    retry: bool = False,
) -> Generator[tuple[int, Server], None, None]:
    """A dsquic server on a loopback port, serving a fixed number of
    connections and then exiting. Yields the port and the server, whose
    ``connections_served`` is what distinguishes one connection carrying
    several requests from one connection each."""
    chain, key = load_credentials(credentials.certificate_pem, credentials.private_key_pem)
    server_config = ServerConfig(
        certificate_chain=chain, signing_key=key, alpn=[hq.ALPN], transport_parameters=b""
    )
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(("::1" if family is socket.AF_INET6 else "127.0.0.1", 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    running = Server(
        sock,
        selector,
        server_config,
        ServerOptions(document_root=document_root, idle_timeout=5.0, retry=retry),
    )

    thread = threading.Thread(
        target=lambda: running.serve(connection_limit=connection_limit), daemon=True
    )
    thread.start()
    time.sleep(0.05)  # let the bind settle before the client connects
    try:
        yield port, running
    finally:
        thread.join(timeout=15.0)
        selector.close()
        sock.close()


@pytest.fixture
def server(credentials: PemCredentials, document_root: Path) -> Iterator[int]:
    """A dsquic server on a loopback port, one connection per test."""
    with running_server(credentials, document_root, connection_limit=1) as (port, _):
        yield port


@pytest.fixture
def ipv6_server(credentials: PemCredentials, document_root: Path) -> Iterator[int]:
    """The same server on IPv6 loopback."""
    with running_server(credentials, document_root, connection_limit=1, family=socket.AF_INET6) as (
        port,
        _,
    ):
        yield port


@pytest.fixture
def sequential_server(
    credentials: PemCredentials, document_root: Path
) -> Iterator[tuple[int, Server]]:
    """A dsquic server expecting three connections, for multiconnect."""
    with running_server(credentials, document_root, connection_limit=3) as running:
        yield running


def test_loopback_transfer(credentials: PemCredentials, server: int) -> None:
    bodies = fetch(
        host="127.0.0.1",
        port=server,
        paths=["/index.html"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies == {"/index.html": INDEX_BODY}


@pytest.fixture
def retry_server(credentials: PemCredentials, document_root: Path) -> Iterator[int]:
    """A server that validates addresses with a Retry (§8.1.2)."""
    with running_server(credentials, document_root, connection_limit=1, retry=True) as (port, _):
        yield port


def test_loopback_transfer_through_a_retry(credentials: PemCredentials, retry_server: int) -> None:
    """RFC 9000 §8.1.2 end to end: the server answers the first Initial
    with a Retry, and the client repeats its handshake with the token."""
    bodies = fetch(
        host="127.0.0.1",
        port=retry_server,
        paths=["/index.html"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies == {"/index.html": INDEX_BODY}


def test_loopback_transfer_over_ipv6(credentials: PemCredentials, ipv6_server: int) -> None:
    """The endpoints take their address family from the name they are
    given, which is what the runner's ipv6 case exercises."""
    bodies = fetch(
        host="::1",
        port=ipv6_server,
        paths=["/index.html"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies == {"/index.html": INDEX_BODY}


def test_loopback_large_transfer(credentials: PemCredentials, server: int) -> None:
    bodies = fetch(
        host="127.0.0.1",
        port=server,
        paths=["/large.bin"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies["/large.bin"] == LARGE_BODY


def test_loopback_multiple_streams(credentials: PemCredentials, server: int) -> None:
    bodies = fetch(
        host="127.0.0.1",
        port=server,
        paths=["/index.html", "/large.bin"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies["/index.html"] == INDEX_BODY
    assert bodies["/large.bin"] == LARGE_BODY


def test_loopback_missing_file_is_empty_body(credentials: PemCredentials, server: int) -> None:
    bodies = fetch(
        host="127.0.0.1",
        port=server,
        paths=["/absent.bin"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies == {"/absent.bin": b""}


def test_loopback_keylog(
    credentials: PemCredentials, server: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    fetch(
        host="127.0.0.1",
        port=server,
        paths=["/index.html"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    labels = [line.split()[0] for line in keylog.read_text().splitlines()]
    assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in labels
    assert "SERVER_TRAFFIC_SECRET_0" in labels


def test_certificate_validation_rejects_wrong_name(
    credentials: PemCredentials, server: int
) -> None:
    with pytest.raises((RuntimeError, TimeoutError)):
        fetch(
            host="127.0.0.1",
            port=server,
            paths=["/index.html"],
            options=ClientOptions(
                ca_certificates=load_pem_certificates(credentials.ca_pem),
                server_name="wrong.example",
                timeout=3.0,
            ),
        )


def test_loopback_connection_per_request(
    credentials: PemCredentials, sequential_server: tuple[int, Server]
) -> None:
    """The runner's multiconnect case: a fresh handshake per file, which
    is what makes it a test of handshake loss rather than data loss."""
    port, running = sequential_server
    bodies = fetch_each(
        host="127.0.0.1",
        port=port,
        paths=["/index.html", "/large.bin", "/index.html"],
        options=ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        ),
    )
    assert bodies == {"/index.html": INDEX_BODY, "/large.bin": LARGE_BODY}
    # The server counts a connection once it is reaped, which happens on
    # its own thread just after the client closes, so wait rather than
    # race it. Three paths must cost three connections, not one.
    deadline = time.monotonic() + 5.0
    while running.connections_served < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert running.connections_served == 3


def test_loopback_resumption(credentials: PemCredentials, document_root: Path) -> None:
    """The runner's resumption case over real UDP: the first connection
    is a full handshake whose ticket the second offers, and the server
    counts the second as resumed, meaning it selected the PSK and sent
    no Certificate (RFC 8446 §2.2)."""
    with running_server(credentials, document_root, connection_limit=2) as (port, running):
        bodies = fetch_each(
            host="127.0.0.1",
            port=port,
            paths=["/index.html", "/large.bin"],
            options=ClientOptions(
                ca_certificates=load_pem_certificates(credentials.ca_pem),
                server_name="localhost",
                resume=True,
            ),
        )
        assert bodies == {"/index.html": INDEX_BODY, "/large.bin": LARGE_BODY}
        deadline = time.monotonic() + 5.0
        while running.connections_served < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
    assert running.connections_served == 2
    assert running.connections_resumed == 1


def test_fetch_each_enforces_a_total_deadline(credentials: PemCredentials) -> None:
    """The timeout bounds the whole run, so an exhausted budget stops the
    remaining paths instead of granting each a fresh one. Nothing is
    listening on the port: the deadline is what is under test."""
    with pytest.raises(TimeoutError, match="fetched 0 of 3 paths"):
        fetch_each(
            host="127.0.0.1",
            port=1,
            paths=["/index.html", "/large.bin", "/absent.bin"],
            options=ClientOptions(
                ca_certificates=load_pem_certificates(credentials.ca_pem),
                server_name="localhost",
                timeout=0.0,
            ),
        )
