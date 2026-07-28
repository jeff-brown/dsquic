"""Reference QUIC / HTTP/3 server.

A synchronous UDP endpoint driving the sans-IO core in connection.py.
Owns the socket, the clock, and served file reads; contains no protocol
logic. Selects the application protocol by negotiated ALPN (hq.py now,
h3.py once implemented).

Exercises every server-side protocol code path: handshake, transfer,
Retry, resumption, key update, ECN, 0-RTT, HTTP/3 file serving, and
CONNECT-UDP. Acts as the server half of the Interop Runner shim (see
interop/).

Serves one connection at a time; the connection table that turns this
into a multi-connection server is the next step, and is also what an
inner MASQUE connection would route through (design.md appendix).

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
    Connection,
    ConnectionConfig,
    ConnectionState,
    StreamDataReceived,
)
from dsquic.endpoints import keylog_writer, load_pem_certificates, pump
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


def serve_one(
    sock: socket.socket,
    selector: selectors.BaseSelector,
    server_config: ServerConfig,
    document_root: Path,
    idle_timeout: float,
) -> None:
    """Accept and serve a single connection to completion."""
    connection = Connection(
        is_client=False,
        server_config=server_config,
        config=ConnectionConfig(keylog=keylog_writer()),
    )
    requests: dict[int, bytearray] = {}
    deadline = time.monotonic() + idle_timeout

    while connection.state is not ConnectionState.TERMINATED:
        if time.monotonic() > deadline:
            return
        pump(connection, sock, selector, deadline)
        for event in connection.take_events():
            if not isinstance(event, StreamDataReceived):
                continue
            deadline = time.monotonic() + idle_timeout
            buffer = requests.setdefault(event.stream_id, bytearray())
            buffer.extend(event.data)
            if not event.end_stream:
                continue
            try:
                path = hq.parse_request(bytes(buffer))
            except hq.HqError:
                connection.send_stream_data(event.stream_id, b"", end_stream=True)
                continue
            body = resolve(document_root, path)
            # hq-interop has no status codes: a missing file is an empty body.
            connection.send_stream_data(event.stream_id, body or b"", end_stream=True)


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

    try:
        while True:
            serve_one(sock, selector, server_config, args.www, args.idle_timeout)
            if args.once:
                return 0
    except KeyboardInterrupt:
        return 0
    finally:
        selector.close()
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
