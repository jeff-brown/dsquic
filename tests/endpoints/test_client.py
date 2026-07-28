"""Tests for dsquic.endpoints.client, including loopback over real UDP.

Verification ladder rung 2 (design.md §6.2): dsquic against dsquic
through the reference endpoints, datagrams crossing the kernel on the
loopback interface with a real clock.
"""

import selectors
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import PemCredentials

from dsquic import hq
from dsquic.endpoints import load_pem_certificates
from dsquic.endpoints.client import ClientOptions, fetch
from dsquic.endpoints.server import load_credentials, serve_one
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


@pytest.fixture
def server(credentials: PemCredentials, document_root: Path) -> Iterator[int]:
    """A dsquic server on a loopback port, one connection per test."""
    chain, key = load_credentials(credentials.certificate_pem, credentials.private_key_pem)
    server_config = ServerConfig(
        certificate_chain=chain, signing_key=key, alpn=[hq.ALPN], transport_parameters=b""
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)

    def run() -> None:
        serve_one(sock, selector, server_config, document_root, idle_timeout=5.0)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    time.sleep(0.05)  # let the bind settle before the client connects
    try:
        yield port
    finally:
        thread.join(timeout=5.0)
        selector.close()
        sock.close()


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
