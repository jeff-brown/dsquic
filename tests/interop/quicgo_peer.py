"""Builds and runs the quic-go hq-interop peers for interop tests.

Only the wiring in quicgo/ is ours; every protocol decision belongs to
quic-go. The binaries are built on demand and cached for the session, so
a checkout without Go simply skips these tests.
"""

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from credentials import PemCredentials

SOURCE_DIR = Path(__file__).parent / "quicgo"
BUILD_DIR = Path(tempfile.gettempdir()) / "dsquic-quicgo-bin"


def go_executable() -> str | None:
    return shutil.which("go") or next(
        (path for path in ("/opt/homebrew/bin/go", "/usr/local/go/bin/go") if Path(path).exists()),
        None,
    )


def build_peers() -> tuple[Path, Path] | None:
    """Build the quic-go client and server, or None if Go is unavailable."""
    go = go_executable()
    if go is None:
        return None
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    server = BUILD_DIR / "hq-server"
    client = BUILD_DIR / "hq-client"
    if server.exists() and client.exists():
        return server, client
    for target, output in (("./server", server), ("./client", client)):
        result = subprocess.run(
            [go, "build", "-o", str(output), target],
            cwd=SOURCE_DIR,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            return None
    return server, client


class QuicGoServer:
    """Runs the quic-go hq-interop server as a subprocess."""

    def __init__(
        self,
        binary: Path,
        port: int,
        credentials: PemCredentials,
        document_root: Path,
    ) -> None:
        self._command = [
            str(binary),
            "-addr",
            f"127.0.0.1:{port}",
            "-cert",
            str(credentials.certificate_pem),
            "-key",
            str(credentials.private_key_pem),
            "-www",
            str(document_root),
        ]
        self._process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "QuicGoServer":
        self._process = subprocess.Popen(
            self._command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        assert self._process.stdout is not None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            line = self._process.stdout.readline()
            if line.strip() == "ready":
                return self
            if self._process.poll() is not None:
                raise RuntimeError(f"quic-go server exited: {self._process.stderr.read()}")  # type: ignore[union-attr]
        raise TimeoutError("quic-go server did not become ready")

    def __exit__(self, *exc_info: object) -> None:
        if self._process is not None:
            self._process.terminate()
            self._process.wait(timeout=10)


def quicgo_fetch(
    port: int,
    paths: list[str],
    credentials: PemCredentials,
    output_dir: Path,
    *,
    force_hello_retry: bool = False,
) -> dict[str, bytes]:
    """Fetch paths from a server using quic-go as the client.

    ``force_hello_retry`` makes the peer prefer P-256, so its ClientHello
    carries no x25519 share and the server must send a
    HelloRetryRequest (RFC 8446 §4.1.4).
    """
    built = build_peers()
    if built is None:
        raise RuntimeError("the quic-go peers are not built")
    _server_binary, binary = built
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_certificate = credentials.ca_pem
    server_name = "localhost"
    command = [
        str(binary),
        "-addr",
        f"127.0.0.1:{port}",
        "-ca",
        str(ca_certificate),
        "-server-name",
        server_name,
        "-output-dir",
        str(output_dir),
        "-paths",
        ",".join(paths),
    ]
    if force_hello_retry:
        command.append("-force-hello-retry")
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"quic-go client failed: {result.stderr.strip()}")
    return {path: (output_dir / Path(path).name).read_bytes() for path in paths}
