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

MVP cipher: AES-128-GCM with SHA-256 (TLS_AES_128_GCM_SHA256), which is
also what Initial packets always use (§5.2).
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dsquic.packet import HEADER_FORM_LONG, decode_packet_number
from dsquic.tls import hkdf_expand_label, hkdf_extract

INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # §5.2

AEAD_TAG_LENGTH = 16
SAMPLE_LENGTH = 16  # §5.4.2
MAX_PN_LENGTH = 4
PN_LENGTH_BITS = 0x03
LONG_PROTECTED_BITS = 0x0F  # §5.4.1
SHORT_PROTECTED_BITS = 0x1F


@dataclass(frozen=True)
class PacketKeys:
    """AEAD key and IV plus the header protection key for one direction."""

    key: bytes
    iv: bytes
    hp: bytes


@dataclass(frozen=True)
class InitialSecrets:
    """Client and server Initial traffic secrets (§5.2)."""

    client: bytes
    server: bytes


def derive_initial_secrets(client_dcid: bytes) -> InitialSecrets:
    """Derive Initial secrets from the client's first Destination CID (§5.2).

    These do not come from TLS: anyone observing the first packet can
    compute them. Initial protection provides anti-ossification and
    integrity, not confidentiality.
    """
    initial_secret = hkdf_extract(INITIAL_SALT_V1, client_dcid)
    return InitialSecrets(
        client=hkdf_expand_label(initial_secret, b"client in", b"", 32),
        server=hkdf_expand_label(initial_secret, b"server in", b"", 32),
    )


def derive_packet_keys(secret: bytes) -> PacketKeys:
    """Derive the packet protection keys from a traffic secret (§5.1)."""
    return PacketKeys(
        key=hkdf_expand_label(secret, b"quic key", b"", 16),
        iv=hkdf_expand_label(secret, b"quic iv", b"", 12),
        hp=hkdf_expand_label(secret, b"quic hp", b"", 16),
    )


def header_protection_mask(hp_key: bytes, sample: bytes) -> bytes:
    """Compute the 5-byte header protection mask (§5.4.3, AES-based)."""
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return (encryptor.update(sample) + encryptor.finalize())[:5]


def _nonce(iv: bytes, packet_number: int) -> bytes:
    """The AEAD nonce: IV XOR left-padded packet number (§5.3)."""
    return bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(len(iv), "big"), strict=True))


def protect(keys: PacketKeys, header: bytes, payload: bytes, packet_number: int) -> bytes:
    """Protect one packet: AEAD, then header protection (§5.3, §5.4.2).

    ``header`` ends with the truncated packet number, whose length is
    encoded in the two low bits of the first byte. The full
    ``packet_number`` feeds the nonce. Returns the complete wire packet.
    """
    pn_length = (header[0] & PN_LENGTH_BITS) + 1
    ciphertext = AESGCM(keys.key).encrypt(_nonce(keys.iv, packet_number), payload, header)
    # §5.4.2: sample as though the packet number were 4 bytes long.
    sample_offset = MAX_PN_LENGTH - pn_length
    sample = ciphertext[sample_offset : sample_offset + SAMPLE_LENGTH]
    mask = header_protection_mask(keys.hp, sample)
    protected = bytearray(header + ciphertext)
    first_byte_bits = LONG_PROTECTED_BITS if header[0] & HEADER_FORM_LONG else SHORT_PROTECTED_BITS
    protected[0] ^= mask[0] & first_byte_bits
    pn_offset = len(header) - pn_length
    for i in range(pn_length):
        protected[pn_offset + i] ^= mask[1 + i]
    return bytes(protected)


def unprotect(
    keys: PacketKeys, packet: bytes, pn_offset: int, largest_pn: int
) -> tuple[int, bytes]:
    """Unprotect one packet: remove header protection, then AEAD (§5.4.1, §5.3).

    ``packet`` is one complete packet, header through AEAD tag;
    ``largest_pn`` is the largest packet number processed in this space,
    or -1 if none. Returns the full packet number and decrypted payload.
    Raises cryptography's InvalidTag if authentication fails.
    """
    sample_start = pn_offset + MAX_PN_LENGTH
    sample = packet[sample_start : sample_start + SAMPLE_LENGTH]
    if len(sample) < SAMPLE_LENGTH:
        raise ValueError("packet too short to sample for header protection")
    mask = header_protection_mask(keys.hp, sample)
    first_byte_bits = LONG_PROTECTED_BITS if packet[0] & HEADER_FORM_LONG else SHORT_PROTECTED_BITS
    first = packet[0] ^ (mask[0] & first_byte_bits)
    pn_length = (first & PN_LENGTH_BITS) + 1
    pn_bytes = bytes(packet[pn_offset + i] ^ mask[1 + i] for i in range(pn_length))
    packet_number = decode_packet_number(largest_pn, int.from_bytes(pn_bytes, "big"), pn_length * 8)
    header = bytes([first]) + packet[1:pn_offset] + pn_bytes
    ciphertext = packet[pn_offset + pn_length :]
    payload = AESGCM(keys.key).decrypt(_nonce(keys.iv, packet_number), ciphertext, header)
    return packet_number, payload
