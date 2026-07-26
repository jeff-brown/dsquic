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

This module currently contains the message codecs (RFC 8446 §4) and the
key schedule (§7.1), verified against the RFC 8448 simple 1-RTT trace.
Unknown extensions are preserved on parse and ignored, never rejected
(grease tolerance, RFC 8701).
"""

import enum
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from dsquic.buffer import Buffer

TLS_AES_128_GCM_SHA256 = 0x1301
TLS_LEGACY_VERSION = 0x0303  # frozen at "TLS 1.2" (RFC 8446 §4.1.2)
TLS_1_3 = 0x0304
X25519_GROUP = 0x001D
SHA256_LENGTH = 32

RSA_PSS_RSAE_SHA256 = 0x0804
ECDSA_SECP256R1_SHA256 = 0x0403


class HandshakeType(enum.IntEnum):
    """RFC 8446 §4, HandshakeType."""

    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_VERIFY = 15
    FINISHED = 20


class ExtensionType(enum.IntEnum):
    """RFC 8446 §4.2 plus the QUIC extension (RFC 9001 §8.2)."""

    SERVER_NAME = 0
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    SUPPORTED_VERSIONS = 43
    PSK_KEY_EXCHANGE_MODES = 45
    KEY_SHARE = 51
    QUIC_TRANSPORT_PARAMETERS = 0x39


class HandshakeParseError(Exception):
    """A handshake message is malformed."""


# --- HKDF (RFC 8446 §7.1; RFC 5869) -----------------------------------------


def hkdf_label(label: bytes, context: bytes, length: int) -> bytes:
    """Build the HkdfLabel structure (RFC 8446 §7.1)."""
    full_label = b"tls13 " + label
    return (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """HKDF-Expand-Label over SHA-256 (RFC 8446 §7.1)."""
    info = hkdf_label(label, context, length)
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """HKDF-Extract over SHA-256 (RFC 5869 §2.2): HMAC(salt, ikm)."""
    mac = hmac.HMAC(salt, hashes.SHA256())
    mac.update(input_key_material)
    return mac.finalize()


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


EMPTY_TRANSCRIPT_HASH = _sha256(b"")


class KeySchedule:
    """The RFC 8446 §7.1 key schedule over SHA-256.

    Stages advance one way: Early Secret at construction (no PSK),
    add_ecdhe() moves to the Handshake Secret, advance_to_master() to
    the Master Secret. Traffic secrets are Derive-Secret over the
    running transcript hash, so callers must update_transcript() with
    each handshake message in wire order before deriving.
    """

    def __init__(self) -> None:
        self._transcript = hashes.Hash(hashes.SHA256())
        self._secret = hkdf_extract(bytes(SHA256_LENGTH), bytes(SHA256_LENGTH))

    def update_transcript(self, handshake_message: bytes) -> None:
        self._transcript.update(handshake_message)

    def transcript_hash(self) -> bytes:
        return self._transcript.copy().finalize()

    def _derive(self, label: bytes) -> bytes:
        return hkdf_expand_label(self._secret, label, self.transcript_hash(), SHA256_LENGTH)

    def add_ecdhe(self, shared_secret: bytes) -> None:
        """Early Secret to Handshake Secret (§7.1)."""
        derived = hkdf_expand_label(self._secret, b"derived", EMPTY_TRANSCRIPT_HASH, SHA256_LENGTH)
        self._secret = hkdf_extract(derived, shared_secret)

    def advance_to_master(self) -> None:
        """Handshake Secret to Master Secret (§7.1)."""
        derived = hkdf_expand_label(self._secret, b"derived", EMPTY_TRANSCRIPT_HASH, SHA256_LENGTH)
        self._secret = hkdf_extract(derived, bytes(SHA256_LENGTH))

    def client_handshake_traffic_secret(self) -> bytes:
        return self._derive(b"c hs traffic")

    def server_handshake_traffic_secret(self) -> bytes:
        return self._derive(b"s hs traffic")

    def client_application_traffic_secret(self) -> bytes:
        return self._derive(b"c ap traffic")

    def server_application_traffic_secret(self) -> bytes:
        return self._derive(b"s ap traffic")


def finished_verify_data(base_secret: bytes, transcript_hash: bytes) -> bytes:
    """Compute the Finished MAC (RFC 8446 §4.4.4)."""
    finished_key = hkdf_expand_label(base_secret, b"finished", b"", SHA256_LENGTH)
    mac = hmac.HMAC(finished_key, hashes.SHA256())
    mac.update(transcript_hash)
    return mac.finalize()


# --- Handshake messages (RFC 8446 §4) ----------------------------------------


@dataclass(frozen=True)
class Extension:
    """One extension, payload kept opaque (RFC 8446 §4.2)."""

    type: int
    data: bytes


@dataclass(frozen=True)
class ClientHello:
    """RFC 8446 §4.1.2."""

    random: bytes
    legacy_session_id: bytes
    cipher_suites: list[int]
    extensions: list[Extension]


@dataclass(frozen=True)
class ServerHello:
    """RFC 8446 §4.1.3."""

    random: bytes
    legacy_session_id_echo: bytes
    cipher_suite: int
    extensions: list[Extension]


@dataclass(frozen=True)
class EncryptedExtensions:
    """RFC 8446 §4.3.1."""

    extensions: list[Extension]


@dataclass(frozen=True)
class CertificateEntry:
    """One certificate plus its extensions (RFC 8446 §4.4.2)."""

    data: bytes
    extensions: list[Extension]


@dataclass(frozen=True)
class Certificate:
    """RFC 8446 §4.4.2."""

    request_context: bytes
    entries: list[CertificateEntry]


@dataclass(frozen=True)
class CertificateVerify:
    """RFC 8446 §4.4.3."""

    algorithm: int
    signature: bytes


@dataclass(frozen=True)
class Finished:
    """RFC 8446 §4.4.4."""

    verify_data: bytes


@dataclass(frozen=True)
class NewSessionTicket:
    """RFC 8446 §4.6.1; carried opaquely and ignored (no resumption yet)."""

    body: bytes


HandshakeMessage = (
    ClientHello
    | ServerHello
    | EncryptedExtensions
    | Certificate
    | CertificateVerify
    | Finished
    | NewSessionTicket
)


def _vec(width: int, data: bytes) -> bytes:
    return len(data).to_bytes(width, "big") + data


def _encode_extensions(extensions: list[Extension]) -> bytes:
    body = b"".join(ext.type.to_bytes(2, "big") + _vec(2, ext.data) for ext in extensions)
    return _vec(2, body)


def _parse_extensions(buf: Buffer) -> list[Extension]:
    block = Buffer(buf.pull_bytes(buf.pull_uint16()))
    extensions = []
    while not block.is_empty:
        ext_type = block.pull_uint16()
        extensions.append(Extension(type=ext_type, data=block.pull_bytes(block.pull_uint16())))
    return extensions


def _handshake_message(message_type: HandshakeType, body: bytes) -> bytes:
    return bytes([message_type]) + _vec(3, body)


def encode_client_hello(hello: ClientHello) -> bytes:
    suites = b"".join(suite.to_bytes(2, "big") for suite in hello.cipher_suites)
    body = (
        TLS_LEGACY_VERSION.to_bytes(2, "big")
        + hello.random
        + _vec(1, hello.legacy_session_id)
        + _vec(2, suites)
        + _vec(1, b"\x00")  # legacy_compression_methods: null only (§4.1.2)
        + _encode_extensions(hello.extensions)
    )
    return _handshake_message(HandshakeType.CLIENT_HELLO, body)


def encode_server_hello(hello: ServerHello) -> bytes:
    body = (
        TLS_LEGACY_VERSION.to_bytes(2, "big")
        + hello.random
        + _vec(1, hello.legacy_session_id_echo)
        + hello.cipher_suite.to_bytes(2, "big")
        + b"\x00"  # legacy_compression_method (§4.1.3)
        + _encode_extensions(hello.extensions)
    )
    return _handshake_message(HandshakeType.SERVER_HELLO, body)


def encode_encrypted_extensions(message: EncryptedExtensions) -> bytes:
    body = _encode_extensions(message.extensions)
    return _handshake_message(HandshakeType.ENCRYPTED_EXTENSIONS, body)


def encode_certificate(message: Certificate) -> bytes:
    entries = b"".join(
        _vec(3, entry.data) + _encode_extensions(entry.extensions) for entry in message.entries
    )
    body = _vec(1, message.request_context) + _vec(3, entries)
    return _handshake_message(HandshakeType.CERTIFICATE, body)


def encode_certificate_verify(message: CertificateVerify) -> bytes:
    body = message.algorithm.to_bytes(2, "big") + _vec(2, message.signature)
    return _handshake_message(HandshakeType.CERTIFICATE_VERIFY, body)


def encode_finished(message: Finished) -> bytes:
    return _handshake_message(HandshakeType.FINISHED, message.verify_data)


def _parse_client_hello(buf: Buffer) -> ClientHello:
    if buf.pull_uint16() != TLS_LEGACY_VERSION:
        raise HandshakeParseError("legacy_version is not 0x0303")
    random = buf.pull_bytes(32)
    session_id = buf.pull_bytes(buf.pull_uint8())
    suites_block = Buffer(buf.pull_bytes(buf.pull_uint16()))
    cipher_suites = []
    while not suites_block.is_empty:
        cipher_suites.append(suites_block.pull_uint16())
    if buf.pull_bytes(buf.pull_uint8()) != b"\x00":
        raise HandshakeParseError("legacy_compression_methods is not null-only")
    return ClientHello(
        random=random,
        legacy_session_id=session_id,
        cipher_suites=cipher_suites,
        extensions=_parse_extensions(buf),
    )


def _parse_server_hello(buf: Buffer) -> ServerHello:
    if buf.pull_uint16() != TLS_LEGACY_VERSION:
        raise HandshakeParseError("legacy_version is not 0x0303")
    random = buf.pull_bytes(32)
    session_id_echo = buf.pull_bytes(buf.pull_uint8())
    cipher_suite = buf.pull_uint16()
    if buf.pull_uint8() != 0:
        raise HandshakeParseError("legacy_compression_method is not null")
    return ServerHello(
        random=random,
        legacy_session_id_echo=session_id_echo,
        cipher_suite=cipher_suite,
        extensions=_parse_extensions(buf),
    )


def _parse_certificate(buf: Buffer) -> Certificate:
    request_context = buf.pull_bytes(buf.pull_uint8())
    entries_block = Buffer(buf.pull_bytes(buf.pull_uint24()))
    entries = []
    while not entries_block.is_empty:
        data = entries_block.pull_bytes(entries_block.pull_uint24())
        entries.append(CertificateEntry(data=data, extensions=_parse_extensions(entries_block)))
    return Certificate(request_context=request_context, entries=entries)


def _parse_certificate_verify(buf: Buffer) -> CertificateVerify:
    algorithm = buf.pull_uint16()
    return CertificateVerify(algorithm=algorithm, signature=buf.pull_bytes(buf.pull_uint16()))


def parse_handshake_message(data: bytes) -> tuple[HandshakeMessage, int]:
    """Parse one handshake message; returns the message and bytes consumed.

    RFC 8446 §4: one-byte type, three-byte length, body. The caller
    (CRYPTO stream reassembly) slices complete messages out of its
    buffer using the returned length.
    """
    buf = Buffer(data)
    try:
        message_type = HandshakeType(buf.pull_uint8())
    except ValueError as exc:
        raise HandshakeParseError(f"unknown handshake message type: {exc}") from exc
    body = Buffer(buf.pull_bytes(buf.pull_uint24()))
    message: HandshakeMessage
    if message_type is HandshakeType.CLIENT_HELLO:
        message = _parse_client_hello(body)
    elif message_type is HandshakeType.SERVER_HELLO:
        message = _parse_server_hello(body)
    elif message_type is HandshakeType.ENCRYPTED_EXTENSIONS:
        message = EncryptedExtensions(extensions=_parse_extensions(body))
    elif message_type is HandshakeType.CERTIFICATE:
        message = _parse_certificate(body)
    elif message_type is HandshakeType.CERTIFICATE_VERIFY:
        message = _parse_certificate_verify(body)
    elif message_type is HandshakeType.FINISHED:
        message = Finished(verify_data=body.pull_bytes(body.remaining))
    else:
        message = NewSessionTicket(body=body.pull_bytes(body.remaining))
    if not body.is_empty:
        raise HandshakeParseError(f"trailing bytes in {message_type.name}")
    return message, buf.position
