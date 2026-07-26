"""dsquic: a readable, spec-faithful QUIC / MASQUE / HTTP-3 implementation in pure Python.

The protocol core is sans-IO: state machines take bytes and clock readings
in and return bytes, deadlines, and events out. No sockets, threads, or
event loops in the protocol path.

Module map (each module docstring cites the RFC sections it implements):

    buffer      - varints and wire encoding (RFC 9000 §16)
    packet      - packet formats and header parsing (RFC 9000 §17)
    frames      - frame types, encoding, decoding (RFC 9000 §12.4, §19)
    streams     - stream states and flow control (RFC 9000 §2-§4)
    connection  - connection state machine (RFC 9000 §5, §7, §10)
    tls         - TLS 1.3 handshake, scoped to QUIC (RFC 8446)
    protection  - packet protection: keys, AEAD, header protection (RFC 9001)
    recovery    - loss detection and congestion control (RFC 9002)
    h3          - HTTP/3 (RFC 9114)
    qpack       - QPACK field compression (RFC 9204)
    masque      - MASQUE proxying: CONNECT-UDP (RFC 9298)
    qlog        - qlog structured event output (draft-ietf-quic-qlog)
"""

__version__ = "0.0.1"
