"""Reference QUIC / HTTP/3 server.

A synchronous UDP endpoint driving the sans-IO core in connection.py.
Owns the socket, the clock, and served file reads; contains no protocol
logic. Selects the application protocol by negotiated ALPN (hq.py now,
h3.py once implemented).

Exercises every server-side protocol code path: handshake, transfer,
Retry, resumption, key update, ECN, 0-RTT, HTTP/3 file serving, and
CONNECT-UDP. Acts as the server half of the Interop Runner shim (see
interop/).

Serves many connections over one socket, routing datagrams by
Destination Connection ID. That table is also the point an inner MASQUE
connection would route through (design.md appendix).

Run with: python -m dsquic.endpoints.server
"""

import argparse
import os
import selectors
import socket
import time
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dsquic import hq
from dsquic.connection import (
    CONNECTION_ID_LENGTH,
    Connection,
    ConnectionConfig,
    ConnectionState,
    HandshakeCompleted,
    StreamDataReceived,
)
from dsquic.endpoints import (
    Address,
    keylog_writer,
    load_pem_certificates,
    qlog_trace,
    send_pending,
    wait_for_readable,
)
from dsquic.packet import (
    HEADER_FORM_LONG,
    HeaderParseError,
    LongHeader,
    PacketType,
    UnsupportedVersion,
    destination_connection_id,
    parse_long_header,
    version_negotiation_response,
)
from dsquic.retry import (
    NEW_TOKEN,
    TOKEN_KEY_LENGTH,
    RetryContext,
    TokenError,
    build_retry,
    mint_new_token,
    mint_token,
    validate_new_token,
    validate_token,
)
from dsquic.tls import TICKET_KEY_LENGTH, ServerConfig, SigningKey, TlsServer

TOKEN_LIFETIME = 60.0  # §8.1.4: how long a Retry token proves an address
# §8.1.3: a NEW_TOKEN token is used on some later connection, so it
# lives longer than a Retry token, which proves this very attempt.
NEW_TOKEN_LIFETIME = 3600.0


def _address_bytes(source: object) -> bytes:
    """A socket address as the bytes a token binds itself to.

    The core never interprets an address, so choosing this encoding is
    the endpoint's job (design.md §4.6).
    """
    return repr(source).encode()


def load_credentials(certificate: Path, private_key: Path) -> tuple[list[bytes], SigningKey]:
    """Read a PEM chain and key into the DER form ServerConfig wants."""
    chain = load_pem_certificates(certificate)
    key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise ValueError("private key must be RSA or EC")
    return chain, key


def _initial_header(data: bytes) -> LongHeader | None:
    """The Initial long header at the front of a datagram, or None."""
    if not data or not data[0] & HEADER_FORM_LONG:
        return None
    try:
        header = parse_long_header(data)
    except (HeaderParseError, UnsupportedVersion):
        return None
    return header if header.packet_type is PacketType.INITIAL else None


def resolve(document_root: Path, path: str) -> bytes | None:
    """Map a request path under the document root, or None if absent.

    hq.parse_request already rejects traversal segments; this re-checks
    the resolved path, since the document root is the security boundary.
    """
    candidate = (document_root / path.lstrip("/")).resolve()
    root = document_root.resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate.read_bytes()


class _Session:
    """One connection plus the hq-interop request state on its streams."""

    def __init__(self, connection: Connection, idle_timeout: float) -> None:
        self.connection = connection
        self.requests: dict[int, bytearray] = {}
        self.deadline = time.monotonic() + idle_timeout


@dataclass(frozen=True)
class ServerOptions:
    """What the reference server serves, and how it treats new clients."""

    document_root: Path
    idle_timeout: float = 30.0
    # §8.1.2: answer a new client's first Initial with a Retry, which
    # validates its address before the server commits any state.
    retry: bool = False


class Server:
    """A dsquic server over one socket, serving many connections.

    Datagrams are routed by Destination Connection ID (RFC 9000 §5.2). A
    datagram whose CID is unknown starts a new connection if it carries a
    long header, and is dropped otherwise: without state there is nothing
    to answer with, short of the stateless reset this MVP does not send.

    The table holds two keys per connection: the client's original chosen
    CID, so retransmitted Initials still route, and the CID this server
    issued, which the client switches to once it sees our first packet
    (§7.2).
    """

    def __init__(
        self,
        sock: socket.socket,
        selector: selectors.BaseSelector,
        server_config: ServerConfig,
        options: ServerOptions,
    ) -> None:
        self._sock = sock
        self._selector = selector
        self._server_config = server_config
        if server_config.ticket_key is None:
            # §4.6.1: the key that seals session tickets is process
            # state like the Retry token key below: generated, not
            # configured. A ticket resumes only against the process
            # that issued it, which is what resumption promises.
            self._server_config = replace(server_config, ticket_key=os.urandom(TICKET_KEY_LENGTH))
        self._document_root = options.document_root
        self._idle_timeout = options.idle_timeout
        self._sessions: dict[bytes, _Session] = {}
        # §8.1.4: the key that authenticates our own tokens, Retry and
        # NEW_TOKEN alike. It is ours alone and never leaves the
        # process, so it is generated rather than configured.
        self._token_key = os.urandom(TOKEN_KEY_LENGTH)
        # §8.1.2: whether a new client's first Initial draws a Retry.
        self._retry = options.retry
        self.connections_served = 0
        # Of those, the handshakes that resumed a session via a PSK
        # (§2.2), and those that accepted 0-RTT data (§4.2.10).
        self.connections_resumed = 0
        self.connections_early_data = 0

    def serve(self, connection_limit: int | None = None) -> None:
        """Serve until ``connection_limit`` connections have finished.

        None means forever. The loop sleeps until the earliest deadline
        across every live connection, so idle connections cost nothing.
        """
        while connection_limit is None or self.connections_served < connection_limit:
            self.poll()

    def poll(self) -> None:
        """One I/O step across every connection."""
        for session in list(self._sessions.values()):
            send_pending(session.connection, self._sock)

        deadlines = [session.connection.next_timer() for session in self._sessions.values()]
        deadlines += [session.deadline for session in self._sessions.values()]
        if not deadlines:
            deadlines = [time.monotonic() + self._idle_timeout]
        for data, source in wait_for_readable(self._selector, deadlines):
            self._route(data, source)

        now = time.monotonic()
        for session in list(self._sessions.values()):
            session.connection.handle_timer(now)
            self._serve_requests(session)
            send_pending(session.connection, self._sock)
        self._reap(now)

    def _route(self, data: bytes, source: Address) -> None:
        """Deliver a datagram to its connection, or start a new one."""
        cid = destination_connection_id(data, CONNECTION_ID_LENGTH)
        if cid is None:
            return
        session = self._sessions.get(cid)
        if session is None:
            # §6.1: a packet naming a version we do not speak is answered
            # statelessly, before any connection exists, and before any
            # address validation: the simulator's readiness probe offers
            # an unknown version precisely to elicit this, and reading it
            # as a v1 Initial would drop it instead.
            negotiation = version_negotiation_response(data)
            if negotiation is not None:
                if isinstance(source, tuple):
                    self._sock.sendto(negotiation, source)
                return
            if not data[0] & HEADER_FORM_LONG:
                return  # no state for this CID, and nothing to build it from
            context: RetryContext | None = None
            if self._retry:
                validated = self._validate_address(data, cid, source)
                if validated is False:
                    return  # a Retry went out, or the packet was unusable
                if isinstance(validated, RetryContext):
                    context = validated
            session = self._accept(cid, context)
        session.connection.datagram_received(data, time.monotonic(), source=source)
        session.deadline = time.monotonic() + self._idle_timeout
        # §7.2: the client will switch to the CID we chose, so index both.
        self._sessions.setdefault(session.connection.host_cid, session)

    def _validate_address(self, data: bytes, cid: bytes, source: Address) -> RetryContext | bool:
        """§8.1.2: answer an untokened Initial with a Retry, or check the
        token on one that carries it.

        Returns the context for a client validated by a Retry token,
        True for one validated by a NEW_TOKEN token (no Retry happened,
        so there is no context to echo in transport parameters), and
        False when a Retry went out instead of a connection.
        """
        header = _initial_header(data)
        if header is None:
            return False
        if not header.token:
            self._send_retry(header, source)
            return False
        try:
            if header.token.startswith(NEW_TOKEN):
                # §8.1.3: a stored token validates the address without
                # the Retry round trip, which is what it is for.
                validate_new_token(
                    self._token_key,
                    header.token,
                    client_address=_address_bytes(source),
                    now=time.time(),
                    lifetime=NEW_TOKEN_LIFETIME,
                )
                return True
            original = validate_token(
                self._token_key,
                header.token,
                client_address=_address_bytes(source),
                now=time.time(),
                lifetime=TOKEN_LIFETIME,
            )
        except TokenError:
            # §8.1.3: a token that does not validate leaves the client
            # unvalidated rather than unheard, "including potentially
            # sending a Retry packet". Discarding instead would strand a
            # client holding a token this server cannot check: one from a
            # NEW_TOKEN frame, or one issued before a restart, since the
            # key that authenticates them lives only in this process.
            self._send_retry(header, source)
            return False
        return RetryContext(original_destination_cid=original, source_cid=cid)

    def _send_retry(self, header: LongHeader, source: Address) -> None:
        """§8.1.2: send a Retry naming a fresh connection ID, and keep no
        state; the token carries what the retried Initial will need."""
        retry_cid = os.urandom(CONNECTION_ID_LENGTH)
        token = mint_token(
            self._token_key,
            original_destination_cid=header.destination_cid,
            client_address=_address_bytes(source),
            now=time.time(),
        )
        packet = build_retry(
            destination_cid=header.source_cid,
            source_cid=retry_cid,
            token=token,
            original_destination_cid=header.destination_cid,
        )
        if isinstance(source, tuple):
            self._sock.sendto(packet, source)

    def _accept(self, cid: bytes, retry: RetryContext | None = None) -> _Session:
        connection = Connection(
            is_client=False,
            server_config=self._server_config,
            config=ConnectionConfig(keylog=keylog_writer(), qlog=qlog_trace, retry=retry),
        )
        session = _Session(connection, self._idle_timeout)
        self._sessions[cid] = session
        return session

    def _serve_requests(self, session: _Session) -> None:
        for event in session.connection.take_events():
            if isinstance(event, HandshakeCompleted):
                # §8.1.3: hand the client a token so its next connection
                # skips address validation. Minted here because only the
                # endpoint holds the address the token binds.
                session.connection.send_new_token(
                    mint_new_token(
                        self._token_key,
                        client_address=_address_bytes(session.connection.destination),
                        now=time.time(),
                    )
                )
                continue
            if not isinstance(event, StreamDataReceived):
                continue
            session.deadline = time.monotonic() + self._idle_timeout
            buffer = session.requests.setdefault(event.stream_id, bytearray())
            buffer.extend(event.data)
            if not event.end_stream:
                continue
            try:
                path = hq.parse_request(bytes(buffer))
            except hq.HqError:
                session.connection.send_stream_data(event.stream_id, b"", end_stream=True)
                continue
            body = resolve(self._document_root, path)
            # hq-interop has no status codes: a missing file is an empty body.
            session.connection.send_stream_data(event.stream_id, body or b"", end_stream=True)

    def _reap(self, now: float) -> None:
        finished = {
            cid
            for cid, session in self._sessions.items()
            if session.connection.state is ConnectionState.TERMINATED or now > session.deadline
        }
        if not finished:
            return
        departing = {id(self._sessions[cid]): self._sessions[cid] for cid in finished}
        for cid in finished:
            del self._sessions[cid]
        # A connection is served once, however many CIDs pointed at it.
        remaining = {id(session) for session in self._sessions.values()}
        for session_id, session in departing.items():
            if session_id in remaining:
                continue
            self.connections_served += 1
            tls = session.connection.tls
            if isinstance(tls, TlsServer) and tls.resumed:
                self.connections_resumed += 1
            if isinstance(tls, TlsServer) and tls.early_data_accepted:
                self.connections_early_data += 1


def serve_one(
    sock: socket.socket,
    selector: selectors.BaseSelector,
    server_config: ServerConfig,
    document_root: Path,
    idle_timeout: float,
) -> None:
    """Accept and serve a single connection to completion."""
    options = ServerOptions(document_root=document_root, idle_timeout=idle_timeout)
    Server(sock, selector, server_config, options).serve(connection_limit=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="dsquic reference server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--www", type=Path, default=Path("www"), help="document root")
    parser.add_argument("--idle-timeout", type=float, default=30.0)
    parser.add_argument(
        "--retry",
        action="store_true",
        help="validate client addresses with a Retry packet (RFC 9000 §8.1.2)",
    )
    parser.add_argument("--once", action="store_true", help="serve one connection and exit")
    args = parser.parse_args(argv)

    chain, key = load_credentials(args.certificate, args.private_key)
    server_config = ServerConfig(
        certificate_chain=chain, signing_key=key, alpn=[hq.ALPN], transport_parameters=b""
    )

    family, _, _, _, address = socket.getaddrinfo(
        args.host, args.port, type=socket.SOCK_DGRAM, flags=socket.AI_PASSIVE
    )[0]
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family is socket.AF_INET6:
        # Serve IPv4 peers on the same socket, which arrive as
        # ::ffff:a.b.c.d, rather than running two listeners.
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    print(f"dsquic serving {args.www} on {args.host}:{args.port}", flush=True)

    options = ServerOptions(
        document_root=args.www, idle_timeout=args.idle_timeout, retry=args.retry
    )
    server = Server(sock, selector, server_config, options)
    try:
        server.serve(connection_limit=1 if args.once else None)
    except KeyboardInterrupt:
        pass
    finally:
        selector.close()
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
