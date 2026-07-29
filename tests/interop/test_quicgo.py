"""Interop against quic-go, in both directions.

Verification ladder rung 3 (design.md §6.2), primary target per §6.
Skipped when the Go toolchain is unavailable.
"""

from pathlib import Path

import pytest
from bodies import INDEX_BODY, LARGE_BODY
from credentials import PemCredentials
from quicgo_peer import QuicGoServer, build_peers, quicgo_fetch

from dsquic.endpoints import load_pem_certificates
from dsquic.endpoints.client import ClientOptions, fetch

PEERS = build_peers()
pytestmark = pytest.mark.skipif(PEERS is None, reason="Go toolchain or quic-go build unavailable")


def peers() -> tuple[Path, Path]:
    assert PEERS is not None
    return PEERS


class TestDsquicClientToQuicGoServer:
    def test_transfer(
        self, credentials: PemCredentials, document_root: Path, free_port: int
    ) -> None:
        server_binary, _ = peers()
        with QuicGoServer(
            server_binary,
            free_port,
            credentials,
            document_root,
        ):
            bodies = fetch(
                host="127.0.0.1",
                port=free_port,
                paths=["/index.html"],
                options=ClientOptions(
                    ca_certificates=load_pem_certificates(credentials.ca_pem),
                    server_name="localhost",
                ),
            )
        assert bodies == {"/index.html": INDEX_BODY}

    def test_large_transfer(
        self, credentials: PemCredentials, document_root: Path, free_port: int
    ) -> None:
        server_binary, _ = peers()
        with QuicGoServer(
            server_binary,
            free_port,
            credentials,
            document_root,
        ):
            bodies = fetch(
                host="127.0.0.1",
                port=free_port,
                paths=["/large.bin"],
                options=ClientOptions(
                    ca_certificates=load_pem_certificates(credentials.ca_pem),
                    server_name="localhost",
                ),
            )
        assert bodies["/large.bin"] == LARGE_BODY


class TestQuicGoClientToDsquicServer:
    def test_transfer(
        self, credentials: PemCredentials, dsquic_server: int, tmp_path: Path
    ) -> None:
        bodies = quicgo_fetch(
            dsquic_server,
            ["/index.html"],
            credentials,
            tmp_path / "downloads",
        )
        assert bodies == {"/index.html": INDEX_BODY}

    def test_large_transfer(
        self, credentials: PemCredentials, dsquic_server: int, tmp_path: Path
    ) -> None:
        bodies = quicgo_fetch(
            dsquic_server,
            ["/large.bin"],
            credentials,
            tmp_path / "downloads",
        )
        assert bodies["/large.bin"] == LARGE_BODY

    def test_hello_retry_request(
        self, credentials: PemCredentials, dsquic_server: int, tmp_path: Path
    ) -> None:
        """The peer offers x25519 but shares only P-256, so the server has
        to ask for a usable share (RFC 8446 §4.1.4).

        This is the shape post-quantum defaults produce in the field: a
        client that lists classical groups without spending bytes on
        shares for them.
        """
        bodies = quicgo_fetch(
            dsquic_server,
            ["/index.html"],
            credentials,
            tmp_path / "downloads",
            force_hello_retry=True,
        )
        assert bodies == {"/index.html": INDEX_BODY}
