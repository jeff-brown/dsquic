"""TLS 1.3 handshake, scoped to what QUIC requires.

RFC 8446, as profiled by RFC 9001 §4.

A message-level state machine over the handshake messages: no record
layer, no renegotiation, no version fallback, minimal cipher suite set.
Cryptographic primitives are delegated to the cryptography package.

Interface to the rest of the package:

    QUIC to TLS:  handshake bytes received at encryption level L (from
                  CRYPTO frames); peer transport parameters
    TLS to QUIC:  handshake bytes to send at level L (into CRYPTO
                  frames); secret available (level, direction, secret,
                  cipher suite); handshake complete; handshake
                  confirmed; alert (CONNECTION_CLOSE 0x0100 + alert)

The key schedule is standard TLS 1.3 and yields the standard traffic
secrets. QUIC derives its own packet protection keys from those secrets;
see protection.py.

Emits NSS Key Log Format entries through a keylog callback as each
secret becomes available; endpoints/ writes them to the file named by
SSLKEYLOGFILE so wire captures can be decrypted.
"""
