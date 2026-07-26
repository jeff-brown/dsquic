"""Reference QUIC / HTTP/3 server.

A synchronous UDP endpoint driving the sans-IO core in connection.py.
With client.py, one of the only two modules in the package that perform
I/O; it owns the socket and the clock and contains no protocol logic.

Exercises every server-side protocol code path: handshake, transfer,
Retry, resumption, key update, ECN, 0-RTT, HTTP/3 file serving, and
CONNECT-UDP. Acts as the server half of the Interop Runner shim (see
interop/).

Run with: python -m dsquic.server
"""
