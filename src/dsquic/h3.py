"""HTTP/3 framing, control streams, and request mapping.

RFC 9114, with Extended CONNECT per RFC 9220.

Each request/response is a bidirectional QUIC stream carrying H3 frames
(HEADERS, DATA, SETTINGS, GOAWAY); unidirectional streams carry the
control stream and the QPACK encoder and decoder streams. Header
compression is delegated to qpack.py. Extended CONNECT and capsule
handling serve masque.py.
"""
