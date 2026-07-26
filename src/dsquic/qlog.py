"""qlog structured event output.

draft-ietf-quic-qlog-main-schema and draft-ietf-quic-qlog-quic-events.

Protocol modules emit events (packet_sent, packet_received, recovery
metrics, key updates) as they happen; this module serializes them. The
emitted schema version is cited here once serialization lands.
"""
