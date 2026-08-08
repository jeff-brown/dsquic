"""An hq-interop client and server built on aioquic, for interop tests.

Only the wiring is ours: every protocol decision (packets, crypto, loss
recovery, flow control) belongs to aioquic, which is an independently
written stack. That is what makes disagreement between it and dsquic
evidence about dsquic rather than about shared code.
"""

# aioquic leaves parts of its asyncio surface unannotated (callback
# parameters, PathLike generics). These are its typing gaps at a
# third-party boundary, not ours; dsquic itself stays strictly typed.
# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false

import asyncio
import threading
from pathlib import Path
from typing import Any

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, QuicEvent, StreamDataReceived
from aioquic.tls import SessionTicket

ALPN = ["hq-interop"]


class HqServerProtocol(QuicConnectionProtocol):
    """Serves files from a document root over hq-interop."""

    def __init__(
        self,
        *args: Any,
        document_root: Path,
        resumed: list[bool],
        early_data: list[bool],
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._document_root = document_root
        self._requests: dict[int, bytearray] = {}
        self._resumed = resumed
        self._early_data = early_data

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self._resumed.append(event.session_resumed)
            self._early_data.append(event.early_data_accepted)
        if not isinstance(event, StreamDataReceived):
            return
        buffer = self._requests.setdefault(event.stream_id, bytearray())
        buffer += event.data
        if not event.end_stream:
            return
        body = b""
        line = bytes(buffer).decode("ascii", "replace").strip()
        if line.startswith("GET "):
            candidate = (self._document_root / line[4:].lstrip("/")).resolve()
            if candidate.is_relative_to(self._document_root.resolve()) and candidate.is_file():
                body = candidate.read_bytes()
        self._quic.send_stream_data(event.stream_id, body, end_stream=True)
        self.transmit()


class AioquicServer:
    """Runs an aioquic hq-interop server on its own thread and loop."""

    def __init__(
        self, host: str, port: int, certificate: Path, private_key: Path, document_root: Path
    ) -> None:
        self._host = host
        self._port = port
        self._certificate = certificate
        self._private_key = private_key
        self._document_root = document_root
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        # One entry per completed handshake: whether it resumed a
        # session, and whether it accepted 0-RTT data.
        self.resumed: list[bool] = []
        self.early_data: list[bool] = []
        # RFC 8446 §4.6.1: aioquic issues session tickets only when given
        # somewhere to keep them, which is how its interop image runs.
        self._tickets: dict[bytes, SessionTicket] = {}

    def _store_ticket(self, ticket: SessionTicket) -> None:
        self._tickets[ticket.ticket] = ticket

    def _fetch_ticket(self, label: bytes) -> SessionTicket | None:
        return self._tickets.pop(label, None)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())
        self._loop.close()

    async def _serve(self) -> None:
        configuration = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
        configuration.load_cert_chain(self._certificate, self._private_key)

        def create_protocol(*args: Any, **kwargs: Any) -> HqServerProtocol:
            return HqServerProtocol(
                *args,
                document_root=self._document_root,
                resumed=self.resumed,
                early_data=self.early_data,
                **kwargs,
            )

        await serve(
            self._host,
            self._port,
            configuration=configuration,
            create_protocol=create_protocol,
            session_ticket_fetcher=self._fetch_ticket,
            session_ticket_handler=self._store_ticket,
        )
        self._stop = asyncio.Event()
        self._ready.set()
        await self._stop.wait()

    def __enter__(self) -> "AioquicServer":
        self._thread.start()
        if not self._ready.wait(timeout=10):
            raise TimeoutError("aioquic server did not start")
        return self

    def __exit__(self, *exc_info: object) -> None:
        stop = self._stop
        if stop is not None:
            self._loop.call_soon_threadsafe(stop.set)
        self._thread.join(timeout=5)


def aioquic_fetch(
    host: str,
    port: int,
    paths: list[str],
    ca_certificate: Path,
    server_name: str = "localhost",
) -> dict[str, bytes]:
    """Fetch paths from a server using aioquic as the client."""
    timeout = 15.0

    async def run() -> dict[str, bytes]:
        configuration = QuicConfiguration(is_client=True, alpn_protocols=ALPN)
        configuration.server_name = server_name
        configuration.load_verify_locations(cafile=str(ca_certificate))
        bodies: dict[str, bytes] = {}
        async with connect(host, port, configuration=configuration) as protocol:
            await protocol.wait_connected()
            for path in paths:
                reader, writer = await protocol.create_stream()
                writer.write(f"GET {path}\r\n".encode("ascii"))
                writer.write_eof()
                bodies[path] = await reader.read()
        return bodies

    result: dict[str, dict[str, bytes] | BaseException] = {}

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result["ok"] = loop.run_until_complete(asyncio.wait_for(run(), timeout))
        except BaseException as exc:  # surfaced on the calling thread
            result["error"] = exc
        finally:
            loop.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout + 5)
    if "error" in result:
        raise result["error"]  # type: ignore[misc]
    if "ok" not in result:
        raise TimeoutError("aioquic client did not finish")
    return result["ok"]  # type: ignore[return-value]
