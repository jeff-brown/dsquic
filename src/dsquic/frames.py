"""Frame types: encoding, decoding, and per-frame semantics.

RFC 9000 §12.4 and §19.

One class per frame type, PADDING (0x00) through HANDSHAKE_DONE (0x1e),
each citing its RFC section. CRYPTO frame reassembly is independent of
stream reassembly (§19.6): CRYPTO frames carry an offset but no stream ID
and no flow control, one ordered byte stream per encryption level.
"""
