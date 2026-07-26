"""hq-interop application protocol.

No RFC. The wire convention is defined by the QUIC Interop Runner
(https://github.com/quic-interop/quic-interop-runner) and descends from
HTTP/0.9; the ALPN token is "hq-interop".

A request is one client-initiated bidirectional stream carrying
``GET /<path>`` terminated by CRLF, then FIN. The response is the raw
body bytes, then FIN: no status line, no headers, no content length; end
of stream delimits the body. Concurrent requests are concurrent streams.

Sans-IO: this module defines request and response byte semantics only.
Sockets and file access live in endpoints/.
"""
