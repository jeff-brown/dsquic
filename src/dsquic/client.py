"""Reference QUIC / HTTP/3 client.

A synchronous UDP endpoint driving the sans-IO core in connection.py.
With server.py, one of the only two modules in the package that perform
I/O; it owns the socket and the clock and contains no protocol logic.

Exercises every client-side protocol code path: handshake, transfer,
Retry, resumption, key update, ECN, 0-RTT, HTTP/3 requests, and
CONNECT-UDP. Acts as the client half of the Interop Runner shim (see
interop/).

Run with: python -m dsquic.client
"""
