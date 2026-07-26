"""Packet formats: long and short headers, packet types, packet numbers.

RFC 9000 §17 (packet formats), §12 (packets and frames), §8.1 (Retry),
§6 and §17.2.1 (version negotiation).

Parses and serializes Initial, 0-RTT, Handshake, Retry, 1-RTT, and Version
Negotiation packets. Packet numbers are monotonic per packet number space,
sent truncated (§17.1), and recovered against the largest acknowledged
value. The packet number field cannot be read until header protection is
removed (see protection.py), so headers are exposed in both protected and
unprotected forms.
"""
