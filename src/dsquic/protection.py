"""Packet protection: key derivation, AEAD, header protection.

RFC 9001 §5 (packet protection) and §6 (key update).

Keys derive from TLS traffic secrets via HKDF-Expand-Label with the
labels "quic key", "quic iv", and "quic hp" (§5.1). Initial keys derive
from the client's first Destination Connection ID and a fixed salt, not
from TLS (§5.2). The AEAD nonce is the IV XORed with the left-padded
packet number (§5.3). The AAD is the full header including the
unprotected packet number; header protection is then applied over the
result, keyed by "quic hp" and sampling 16 bytes of ciphertext at an
offset that assumes a 4-byte packet number field (§5.4). Encrypt order
is AEAD then header protection; decrypt order is the reverse. Key update
applies the label "quic ku" to the current secret and is signalled by
the key phase bit; the header protection key does not rotate (§6).
"""
