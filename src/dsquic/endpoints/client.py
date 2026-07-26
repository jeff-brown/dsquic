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
