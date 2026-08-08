"""Reference QUIC / HTTP/3 client.

A synchronous UDP endpoint driving the sans-IO core in connection.py.
Owns the socket, the clock, and download file writes; contains no
protocol logic. Selects the application protocol by negotiated ALPN
(hq.py now, h3.py once implemented).

Exercises every client-side protocol code path: handshake, transfer,
Retry, resumption, key update, ECN, 0-RTT, HTTP/3 requests, and
CONNECT-UDP. Acts as the client half of the Interop Runner shim (see
interop/). ``fetch`` puts every request on one connection; ``fetch_each``
gives each its own, which is the runner's multiconnect case.

Run with: python -m dsquic.endpoints.client
"""

import argparse
import datetime
import selectors
import socket
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from dsquic import hq
from dsquic.connection import (
    Connection,
    ConnectionConfig,
    ConnectionTerminated,
    HandshakeCompleted,
    HandshakeConfirmed,
    StreamDataReceived,
)
from dsquic.endpoints import keylog_writer, load_pem_certificates, pump, qlog_trace
from dsquic.streams import StreamLimitReached
from dsquic.tls import ClientConfig, SessionTicket, TlsClient

DEFAULT_TIMEOUT = 30.0  # a whole fetch, not a single response


@dataclass(frozen=True)
class ClientOptions:
    """How the client authenticates the server and how long it waits."""

    ca_certificates: list[bytes] = field(default_factory=list[bytes])
    insecure: bool = False
    server_name: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    key_update_interval: int | None = None
    # RFC 8446 §2.2: carry session tickets across the sequential
    # connections of fetch_each, each resuming from the newest ticket
    # the ones before it produced.
    resume: bool = False
    # RFC 9001 §4.6: send the requests as 0-RTT early data when the
    # offered ticket permits it.
    early_data: bool = False


@dataclass
class SessionStore:
    """What one server hands a client to speed up later connections.

    Session tickets (RFC 8446 §4.6.1) resume the TLS session; address
    validation tokens (RFC 9000 §8.1.3) spare the next connection a
    Retry round trip. ``fetch`` offers the newest of each and appends
    what it receives; a token is spent when offered, since clients
    should not reuse one (§8.1.3).
    """

    tickets: list[SessionTicket] = field(default_factory=list[SessionTicket])
    tokens: list[bytes] = field(default_factory=list[bytes])


def issue_requests(
    connection: Connection,
    pending: list[str],
    stream_paths: dict[int, str],
    bodies: dict[int, bytearray],
) -> None:
    """Open a stream per pending path, as far as stream credit allows.

    §4.6 limits are cumulative, so the peer's initial allowance can be
    smaller than the number of paths and rises as streams close.
    """
    while pending:
        try:
            stream_id = connection.open_stream()
        except StreamLimitReached:
            return  # wait for the peer to raise the limit
        path = pending.pop(0)
        stream_paths[stream_id] = path
        bodies[stream_id] = bytearray()
        connection.send_stream_data(stream_id, hq.encode_request(path), end_stream=True)


def _apply_events(connection: Connection, bodies: dict[int, bytearray], finished: set[int]) -> bool:
    """Apply one batch of connection events; True once the handshake
    has completed."""
    connected = False
    for event in connection.take_events():
        match event:
            case ConnectionTerminated():
                raise RuntimeError(f"connection closed: {event.reason or event.error_code}")
            case HandshakeCompleted():
                connected = True
            case HandshakeConfirmed():
                # RFC 9001 §4.1.2: not the gate for sending; the frame
                # it waits on can be lost.
                pass
            case StreamDataReceived():
                bodies.setdefault(event.stream_id, bytearray()).extend(event.data)
                if event.end_stream:
                    finished.add(event.stream_id)
    return connected


def fetch(
    host: str,
    port: int,
    paths: list[str],
    options: ClientOptions | None = None,
    session: SessionStore | None = None,
) -> dict[str, bytes]:
    """Fetch paths over one connection; returns path to body bytes.

    One request per bidirectional stream, per hq-interop. Requests are
    issued as stream credit allows: the peer's initial limit may be
    smaller than the number of paths, and rises as streams close (§4.6).

    ``session`` is the caller's per-server store: the newest ticket is
    offered for resumption, a stored token rides the Initial packets,
    and whatever this connection receives is appended. None disables
    all of it. With ``options.early_data`` the requests are issued
    before the handshake completes, riding 0-RTT packets when the
    ticket permits (RFC 9001 §4.6).
    """
    options = options if options is not None else ClientOptions()
    server_name = options.server_name
    timeout = options.timeout
    # §6.1: the address family follows the name, so an AAAA-only host
    # is reached over IPv6 without a flag.
    family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)

    connection = Connection(
        is_client=True,
        client_config=ClientConfig(
            server_name=server_name if server_name is not None else host,
            alpn=[hq.ALPN],
            transport_parameters=b"",
            ca_certificates=[] if options.insecure else options.ca_certificates,
            insecure_skip_verify=options.insecure,
            verification_time=datetime.datetime.now(datetime.UTC),
            session_ticket=session.tickets[-1] if session is not None and session.tickets else None,
            early_data=options.early_data,
        ),
        config=ConnectionConfig(
            keylog=keylog_writer(),
            qlog=qlog_trace,
            key_update_interval=options.key_update_interval,
            token=session.tokens.pop() if session is not None and session.tokens else b"",
        ),
        destination=address,
    )

    bodies: dict[int, bytearray] = {}
    stream_paths: dict[int, str] = {}
    finished: set[int] = set()
    pending = list(paths)
    connected = False
    deadline = time.monotonic() + timeout

    try:
        connection.connect(time.monotonic())
        if connection.streams is not None:
            # Stream state at connect() means 0-RTT: the requests must
            # be queued before the first flight leaves, or they ride
            # 1-RTT after the handshake and save nothing.
            issue_requests(connection, pending, stream_paths, bodies)
        while time.monotonic() < deadline:
            pump(connection, sock, selector, deadline)
            connected = _apply_events(connection, bodies, finished) or connected
            if connected or connection.streams is not None:
                # Stream state before the handshake completes means
                # 0-RTT: the requests are what the early packets carry.
                issue_requests(connection, pending, stream_paths, bodies)
            if connected and not pending and len(finished) == len(paths):
                break
        else:
            raise TimeoutError(f"no response within {timeout}s")

        if session is not None and isinstance(connection.tls, TlsClient):
            session.tickets.extend(connection.tls.session_tickets)
            session.tokens.extend(connection.new_tokens)
        connection.close()
        pump(connection, sock, selector, time.monotonic())
        return {stream_paths[stream_id]: bytes(body) for stream_id, body in bodies.items()}
    finally:
        selector.close()
        sock.close()


def fetch_each(
    host: str,
    port: int,
    paths: list[str],
    options: ClientOptions | None = None,
) -> dict[str, bytes]:
    """Fetch each path over its own connection, in sequence.

    The Interop Runner's multiconnect case. Every file costs a fresh
    handshake, which is how that case tests loss of handshake packets
    rather than loss of data packets. ``options.timeout`` bounds the
    whole run rather than each connection, so one slow handshake cannot
    spend a budget the remaining paths still need.

    With ``options.resume``, each connection offers the newest ticket
    the ones before it produced, so the first handshake is full and the
    rest resume (RFC 8446 §2.2): the runner's resumption case.
    """
    options = options if options is not None else ClientOptions()
    deadline = time.monotonic() + options.timeout
    session = SessionStore() if options.resume else None
    bodies: dict[str, bytes] = {}
    for path in paths:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise TimeoutError(
                f"fetched {len(bodies)} of {len(paths)} paths within {options.timeout}s"
            )
        bodies.update(fetch(host, port, [path], replace(options, timeout=remaining), session))
    return bodies


def fetch_zero_rtt(
    host: str,
    port: int,
    paths: list[str],
    options: ClientOptions | None = None,
) -> dict[str, bytes]:
    """The runner's zerortt case: the first path over a full
    connection, every remaining path over one resumed connection whose
    requests ride 0-RTT (RFC 9001 §4.6). ``options.timeout`` bounds the
    whole run, like fetch_each.
    """
    options = options if options is not None else ClientOptions()
    deadline = time.monotonic() + options.timeout
    session = SessionStore()
    bodies = fetch(host, port, paths[:1], options, session)
    if not session.tickets:
        raise RuntimeError("the first connection produced no session ticket")
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise TimeoutError(f"only the first of {len(paths)} paths within {options.timeout}s")
    early = replace(options, early_data=True, timeout=remaining)
    bodies.update(fetch(host, port, paths[1:], early, session))
    return bodies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="dsquic reference client")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("paths", nargs="+", help="paths to fetch, e.g. /index.html")
    parser.add_argument("--ca", type=Path, help="PEM trust anchor for the server certificate")
    parser.add_argument(
        "--insecure", action="store_true", help="skip certificate validation (debugging only)"
    )
    parser.add_argument("--server-name", help="SNI name, if it differs from host")
    parser.add_argument("--output-dir", type=Path, help="write bodies here instead of stdout")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--key-update-interval",
        type=int,
        help="start a new key phase after this many 1-RTT packets (RFC 9001 §6.1)",
    )
    parser.add_argument(
        "--connection-per-request",
        action="store_true",
        help="one connection per path, in sequence, instead of one for all of them",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume each connection from the previous one's session ticket (RFC 8446 §2.2)",
    )
    parser.add_argument(
        "--zero-rtt",
        action="store_true",
        help="first path on a full connection, the rest as 0-RTT early data (RFC 9001 §4.6)",
    )
    args = parser.parse_args(argv)

    if not args.insecure and args.ca is None:
        parser.error("--ca is required unless --insecure is given")
    if args.resume and not args.connection_per_request:
        parser.error("--resume requires --connection-per-request")
    if args.zero_rtt and args.connection_per_request:
        parser.error("--zero-rtt and --connection-per-request are different splits")
    ca_certificates = load_pem_certificates(args.ca) if args.ca is not None else []

    if args.zero_rtt:
        run = fetch_zero_rtt
    elif args.connection_per_request:
        run = fetch_each
    else:
        run = fetch
    bodies = run(
        host=args.host,
        port=args.port,
        paths=args.paths,
        options=ClientOptions(
            ca_certificates=ca_certificates,
            insecure=args.insecure,
            server_name=args.server_name,
            timeout=args.timeout,
            key_update_interval=args.key_update_interval,
            resume=args.resume,
        ),
    )
    for path, body in bodies.items():
        if args.output_dir is not None:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            (args.output_dir / Path(path).name).write_bytes(body)
            print(f"{path}: {len(body)} bytes")
        else:
            sys.stdout.buffer.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
