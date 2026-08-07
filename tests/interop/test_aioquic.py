"""Interop against aioquic, in both directions.

Verification ladder rung 3 (design.md §6.2). aioquic is an independently
written QUIC stack, so agreement here is evidence that dsquic follows the
RFCs rather than merely agreeing with itself.
"""

from pathlib import Path

from aioquic_peer import AioquicServer, aioquic_fetch
from bodies import INDEX_BODY, LARGE_BODY
from credentials import PemCredentials

from dsquic.endpoints import load_pem_certificates
from dsquic.endpoints.client import ClientOptions, fetch
from dsquic.tls import SessionTicket


class TestDsquicClientToAioquicServer:
    def test_transfer(
        self, credentials: PemCredentials, document_root: Path, free_port: int
    ) -> None:
        with AioquicServer(
            "127.0.0.1",
            free_port,
            credentials.certificate_pem,
            credentials.private_key_pem,
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
        with AioquicServer(
            "127.0.0.1",
            free_port,
            credentials.certificate_pem,
            credentials.private_key_pem,
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

    def test_resumption(
        self, credentials: PemCredentials, document_root: Path, free_port: int
    ) -> None:
        """RFC 8446 §2.2 against aioquic: the second connection offers
        the first one's ticket and aioquic reports the handshake as
        resumed."""
        options = ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        )
        tickets: list[SessionTicket] = []
        with AioquicServer(
            "127.0.0.1",
            free_port,
            credentials.certificate_pem,
            credentials.private_key_pem,
            document_root,
        ) as server:
            first = fetch("127.0.0.1", free_port, ["/index.html"], options, tickets)
            assert tickets, "no ticket arrived on the first connection"
            second = fetch("127.0.0.1", free_port, ["/large.bin"], options, tickets)
            assert first == {"/index.html": INDEX_BODY}
            assert second == {"/large.bin": LARGE_BODY}
            assert server.resumed == [False, True]


class TestAioquicClientToDsquicServer:
    def test_transfer(self, credentials: PemCredentials, dsquic_server: int) -> None:
        bodies = aioquic_fetch("127.0.0.1", dsquic_server, ["/index.html"], credentials.ca_pem)
        assert bodies == {"/index.html": INDEX_BODY}

    def test_large_transfer(self, credentials: PemCredentials, dsquic_server: int) -> None:
        bodies = aioquic_fetch("127.0.0.1", dsquic_server, ["/large.bin"], credentials.ca_pem)
        assert bodies["/large.bin"] == LARGE_BODY
