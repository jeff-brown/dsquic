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
import selectors
import socket
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dsquic import hq
from dsquic.connection import (
    CONNECTION_ID_LENGTH,
    Connection,
    ConnectionConfig,
    ConnectionState,
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
    destination_connection_id,
    version_negotiation_response,
)
from dsquic.tls import ServerConfig, SigningKey


def load_credentials(certificate: Path, private_key: Path) -> tuple[list[bytes], SigningKey]:
    """Read a PEM chain and key into the DER form ServerConfig wants."""
    chain = load_pem_certificates(certificate)
    key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise ValueError("private key must be RSA or EC")
    return chain, key


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
        document_root: Path,
        idle_timeout: float = 30.0,
    ) -> None:
        self._sock = sock
        self._selector = selector
        self._server_config = server_config
        self._document_root = document_root
        self._idle_timeout = idle_timeout
        self._sessions: dict[bytes, _Session] = {}
        self.connections_served = 0

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
            # statelessly, before any connection exists. The simulator's
            # readiness probe relies on this.
            negotiation = version_negotiation_response(data)
            if negotiation is not None:
                if isinstance(source, tuple):
                    self._sock.sendto(negotiation, source)
                return
            if not data[0] & HEADER_FORM_LONG:
                return  # no state for this CID, and nothing to build it from
            session = self._accept(cid)
        session.connection.datagram_received(data, time.monotonic(), source=source)
        session.deadline = time.monotonic() + self._idle_timeout
        # §7.2: the client will switch to the CID we chose, so index both.
        self._sessions.setdefault(session.connection.host_cid, session)

    def _accept(self, cid: bytes) -> _Session:
        connection = Connection(
            is_client=False,
            server_config=self._server_config,
            config=ConnectionConfig(keylog=keylog_writer(), qlog=qlog_trace),
        )
        session = _Session(connection, self._idle_timeout)
        self._sessions[cid] = session
        return session

    def _serve_requests(self, session: _Session) -> None:
        for event in session.connection.take_events():
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
        gone = {id(self._sessions[cid]) for cid in finished}
        for cid in finished:
            del self._sessions[cid]
        # A connection is served once, however many CIDs pointed at it.
        remaining = {id(session) for session in self._sessions.values()}
        self.connections_served += len(gone - remaining)


def serve_one(
    sock: socket.socket,
    selector: selectors.BaseSelector,
    server_config: ServerConfig,
    document_root: Path,
    idle_timeout: float,
) -> None:
    """Accept and serve a single connection to completion."""
    Server(sock, selector, server_config, document_root, idle_timeout).serve(connection_limit=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="dsquic reference server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--www", type=Path, default=Path("www"), help="document root")
    parser.add_argument("--idle-timeout", type=float, default=30.0)
    parser.add_argument("--once", action="store_true", help="serve one connection and exit")
    args = parser.parse_args(argv)

    chain, key = load_credentials(args.certificate, args.private_key)
    server_config = ServerConfig(
        certificate_chain=chain, signing_key=key, alpn=[hq.ALPN], transport_parameters=b""
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    print(f"dsquic serving {args.www} on {args.host}:{args.port}", flush=True)

    server = Server(sock, selector, server_config, args.www, args.idle_timeout)
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
