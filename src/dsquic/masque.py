"""MASQUE: proxying UDP over HTTP/3.

RFC 9298 (CONNECT-UDP), RFC 9297 (HTTP datagrams and capsules), RFC 9221
(QUIC DATAGRAM frames).

CONNECT-UDP upgrades an Extended CONNECT request into a UDP tunnel.
Datagrams flow as HTTP Datagrams with a context ID prefix, carried in
QUIC DATAGRAM frames when available and in capsules otherwise.
"""
