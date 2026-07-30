"""Reference endpoints: the package's I/O boundary.

Everything directly under dsquic/ is sans-IO. Modules in this subpackage
are the only code in the package permitted to touch sockets, files, and
the clock. They drive the protocol core in connection.py and contain no
protocol logic.
"""

import os
import selectors
import socket
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate, load_pem_x509_certificate

from dsquic.connection import Connection

MAX_DATAGRAM_RECV = 65536
PEM_CERTIFICATE_MARKER = b"-----BEGIN CERTIFICATE-----"

# What an opaque core destination is, once a socket endpoint owns it.
Address = tuple[str, int] | None


def split_pem_chain(data: bytes) -> list[Certificate]:
    """Parse a PEM bundle into certificates, in file order."""
    blocks = data.split(PEM_CERTIFICATE_MARKER)[1:]
    return [load_pem_x509_certificate(PEM_CERTIFICATE_MARKER + block) for block in blocks]


def load_pem_certificates(path: Path) -> list[bytes]:
    """Read a PEM file as DER bytes, the form the core works in.

    The core speaks DER because that is what the wire carries; PEM is a
    file format, so it is converted here at the I/O boundary.
    """
    return [
        certificate.public_bytes(serialization.Encoding.DER)
        for certificate in split_pem_chain(path.read_bytes())
    ]


def keylog_writer() -> Callable[[str], None] | None:
    """Append NSS Key Log Format lines to $SSLKEYLOGFILE, if set.

    The same contract Wireshark and the QUIC Interop Runner expect: one
    line per secret, appended as it becomes available and flushed so a
    live capture can be decrypted while the connection runs.
    """
    path = os.environ.get("SSLKEYLOGFILE")
    if not path:
        return None
    handle = open(path, "a", encoding="ascii")

    def write(line: str) -> None:
        handle.write(line + "\n")
        handle.flush()

    return write


def send_pending(connection: Connection, sock: socket.socket) -> None:
    """Flush whatever the core says is due right now."""
    for datagram in connection.datagrams_to_send(time.monotonic()):
        # The core keeps destinations opaque so a connection can be
        # tunnelled; a socket endpoint knows they are addresses.
        destination = cast("Address", datagram.destination)
        if destination is not None:
            sock.sendto(datagram.data, destination)


def wait_for_readable(
    selector: selectors.BaseSelector, deadlines: Sequence[float | None]
) -> list[tuple[bytes, Address]]:
    """Sleep until a datagram arrives or the earliest deadline passes.

    Taking deadlines rather than a poll interval is what lets one loop
    serve many connections without waking up needlessly (design.md §4.7).
    """
    timeouts = [value for value in deadlines if value is not None]
    wait = min(timeouts) - time.monotonic() if timeouts else None
    if wait is not None and wait < 0:
        wait = 0
    received: list[tuple[bytes, Address]] = []
    for key, _ in selector.select(timeout=wait):
        readable: socket.socket = key.fileobj  # type: ignore[assignment]
        while True:
            try:
                data, source = readable.recvfrom(MAX_DATAGRAM_RECV)
            except BlockingIOError:
                break
            received.append((data, source))
    return received


def pump(
    connection: Connection,
    sock: socket.socket,
    selector: selectors.BaseSelector,
    deadline: float | None = None,
) -> None:
    """Run one I/O step for a single connection: send, wait, receive, tick.

    The whole event loop of a client. The core decides *what* to send and
    *when* to wake up; this decides only how the bytes move.
    """
    send_pending(connection, sock)
    for data, source in wait_for_readable(selector, [connection.next_timer(), deadline]):
        connection.datagram_received(data, time.monotonic(), source=source)
    connection.handle_timer(time.monotonic())
