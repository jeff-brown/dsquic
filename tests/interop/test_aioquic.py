"""Interop against aioquic, in both directions.

Verification ladder rung 3 (design.md §6.2). aioquic is an independently
written QUIC stack, so agreement here is evidence that dsquic follows the
RFCs rather than merely agreeing with itself.
"""

from dataclasses import replace
from pathlib import Path

from aioquic_peer import AioquicServer, aioquic_fetch
from bodies import INDEX_BODY, LARGE_BODY
from credentials import PemCredentials

from dsquic.endpoints import load_pem_certificates
from dsquic.endpoints.client import ClientOptions, SessionStore, fetch


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
        session = SessionStore()
        with AioquicServer(
            "127.0.0.1",
            free_port,
            credentials.certificate_pem,
            credentials.private_key_pem,
            document_root,
        ) as server:
            first = fetch("127.0.0.1", free_port, ["/index.html"], options, session)
            assert session.tickets, "no ticket arrived on the first connection"
            second = fetch("127.0.0.1", free_port, ["/large.bin"], options, session)
            assert first == {"/index.html": INDEX_BODY}
            assert second == {"/large.bin": LARGE_BODY}
            assert server.resumed == [False, True]

    def test_zero_rtt(
        self, credentials: PemCredentials, document_root: Path, free_port: int
    ) -> None:
        """RFC 9001 §4.6 against aioquic: the resumed connection sends
        its requests as early data and aioquic reports the 0-RTT as
        accepted, acting on the request before its handshake completes.
        """
        options = ClientOptions(
            ca_certificates=load_pem_certificates(credentials.ca_pem),
            server_name="localhost",
        )
        session = SessionStore()
        with AioquicServer(
            "127.0.0.1",
            free_port,
            credentials.certificate_pem,
            credentials.private_key_pem,
            document_root,
        ) as server:
            first = fetch("127.0.0.1", free_port, ["/index.html"], options, session)
            assert session.tickets, "no ticket arrived on the first connection"
            early = replace(options, early_data=True)
            second = fetch("127.0.0.1", free_port, ["/large.bin"], early, session)
            assert first == {"/index.html": INDEX_BODY}
            assert second == {"/large.bin": LARGE_BODY}
            assert server.resumed == [False, True]
            assert server.early_data == [False, True]


class TestAioquicClientToDsquicServer:
    def test_transfer(self, credentials: PemCredentials, dsquic_server: int) -> None:
        bodies = aioquic_fetch("127.0.0.1", dsquic_server, ["/index.html"], credentials.ca_pem)
        assert bodies == {"/index.html": INDEX_BODY}

    def test_large_transfer(self, credentials: PemCredentials, dsquic_server: int) -> None:
        bodies = aioquic_fetch("127.0.0.1", dsquic_server, ["/large.bin"], credentials.ca_pem)
        assert bodies["/large.bin"] == LARGE_BODY
