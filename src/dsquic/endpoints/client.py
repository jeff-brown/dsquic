"""Reference QUIC / HTTP/3 client.

A synchronous UDP endpoint driving the sans-IO core in connection.py.
Owns the socket, the clock, and download file writes; contains no
protocol logic. Selects the application protocol by negotiated ALPN
(hq.py now, h3.py once implemented).

Exercises every client-side protocol code path: handshake, transfer,
Retry, resumption, key update, ECN, 0-RTT, HTTP/3 requests, and
CONNECT-UDP. Acts as the client half of the Interop Runner shim (see
interop/).

Run with: python -m dsquic.endpoints.client
"""

import argparse
import datetime
import selectors
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from dsquic import hq
from dsquic.connection import (
    Connection,
    ConnectionConfig,
    ConnectionTerminated,
    HandshakeConfirmed,
    StreamDataReceived,
)
from dsquic.endpoints import keylog_writer, load_pem_certificates, pump
from dsquic.tls import ClientConfig

DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class ClientOptions:
    """How the client authenticates the server and how long it waits."""

    ca_certificates: list[bytes] = field(default_factory=list[bytes])
    insecure: bool = False
    server_name: str | None = None
    timeout: float = DEFAULT_TIMEOUT


def fetch(
    host: str,
    port: int,
    paths: list[str],
    options: ClientOptions | None = None,
) -> dict[str, bytes]:
    """Fetch paths over one connection; returns path to body bytes.

    One request per bidirectional stream, all issued once the handshake
    confirms, per hq-interop.
    """
    options = options if options is not None else ClientOptions()
    server_name = options.server_name
    timeout = options.timeout
    address = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
        ),
        config=ConnectionConfig(keylog=keylog_writer()),
        destination=address,
    )

    bodies: dict[int, bytearray] = {}
    stream_paths: dict[int, str] = {}
    finished: set[int] = set()
    requested = False
    deadline = time.monotonic() + timeout

    try:
        connection.connect(time.monotonic())
        while time.monotonic() < deadline:
            pump(connection, sock, selector, deadline)
            for event in connection.take_events():
                if isinstance(event, HandshakeConfirmed) and not requested:
                    requested = True
                    for path in paths:
                        stream_id = connection.open_stream()
                        stream_paths[stream_id] = path
                        bodies[stream_id] = bytearray()
                        connection.send_stream_data(
                            stream_id, hq.encode_request(path), end_stream=True
                        )
                elif isinstance(event, StreamDataReceived):
                    bodies.setdefault(event.stream_id, bytearray()).extend(event.data)
                    if event.end_stream:
                        finished.add(event.stream_id)
                elif isinstance(event, ConnectionTerminated):
                    raise RuntimeError(f"connection closed: {event.reason or event.error_code}")
            if requested and len(finished) == len(paths):
                break
        else:
            raise TimeoutError(f"no response within {timeout}s")

        connection.close()
        pump(connection, sock, selector, time.monotonic())
        return {stream_paths[stream_id]: bytes(body) for stream_id, body in bodies.items()}
    finally:
        selector.close()
        sock.close()


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
    args = parser.parse_args(argv)

    if not args.insecure and args.ca is None:
        parser.error("--ca is required unless --insecure is given")
    ca_certificates = load_pem_certificates(args.ca) if args.ca is not None else []

    bodies = fetch(
        host=args.host,
        port=args.port,
        paths=args.paths,
        options=ClientOptions(
            ca_certificates=ca_certificates,
            insecure=args.insecure,
            server_name=args.server_name,
            timeout=args.timeout,
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
