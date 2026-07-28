"""hq-interop application protocol.

No RFC. The wire convention is defined by the QUIC Interop Runner
(https://github.com/quic-interop/quic-interop-runner) and descends from
HTTP/0.9; the ALPN token is "hq-interop".

A request is one client-initiated bidirectional stream carrying
``GET /<path>`` terminated by CRLF, then FIN. The response is the raw
body bytes, then FIN: no status line, no headers, no content length; end
of stream delimits the body. Concurrent requests are concurrent streams.

Sans-IO: this module defines request and response byte semantics only.
Sockets and file access live in endpoints/. Divergence note: peers vary
on the request terminator (CRLF, bare LF, or none); parse_request is
called at FIN and tolerates all three, matching quic-go's server.
"""

ALPN = "hq-interop"


class HqError(Exception):
    """The request line is not a well-formed hq-interop GET."""


def encode_request(path: str) -> bytes:
    """The request line for one file: ``GET <path>\\r\\n``."""
    if not path.startswith("/"):
        raise ValueError(f"path must start with '/': {path!r}")
    return f"GET {path}\r\n".encode("ascii")


def parse_request(data: bytes) -> str:
    """Extract the request path from a complete (FIN-terminated) request.

    Returns the path with its leading slash. Rejects anything that is
    not a GET, a non-ASCII line, an empty path, or a path with ``..``
    segments (the server maps paths under a document root).
    """
    try:
        line = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HqError("request is not ASCII") from exc
    line = line.rstrip("\r\n")
    if "\n" in line or "\r" in line:
        raise HqError("request contains more than one line")
    if not line.startswith("GET "):
        raise HqError(f"not a GET request: {line[:20]!r}")
    path = line[len("GET ") :].strip()
    if not path.startswith("/"):
        raise HqError(f"path must start with '/': {path!r}")
    if ".." in path.split("/"):
        raise HqError(f"path traversal rejected: {path!r}")
    return path
