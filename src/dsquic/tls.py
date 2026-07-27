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

Contents: the message codecs (RFC 8446 §4) and key schedule (§7.1),
verified against the RFC 8448 simple 1-RTT trace; the TlsClient and
TlsServer handshake state machines (states per RFC 8446 Appendix A);
CertificateVerify signing and verification; certificate policy on the
client (chain to configured anchors plus RFC 9525 hostname matching,
delegated to cryptography's verifier, with an explicit insecure flag);
and the NSS-format keylog callback. Unknown extensions are preserved on
parse and ignored, never rejected (grease tolerance, RFC 8701).
"""

import datetime
import enum
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509 import DNSName, load_der_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

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
    extensions: list[Extension] = []
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
    cipher_suites: list[int] = []
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
    entries: list[CertificateEntry] = []
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


# --- Handshake state machines (RFC 8446 Appendix A; RFC 9001 §4) --------------


class EncryptionLevel(enum.Enum):
    """QUIC encryption levels carrying CRYPTO data (RFC 9001 §4.1.1)."""

    INITIAL = enum.auto()
    HANDSHAKE = enum.auto()
    ONE_RTT = enum.auto()


class Direction(enum.Enum):
    """Which endpoint's traffic a secret protects (absolute, not read/write)."""

    CLIENT = enum.auto()
    SERVER = enum.auto()


@dataclass(frozen=True)
class SendData:
    """Handshake bytes to carry in CRYPTO frames at the given level."""

    level: EncryptionLevel
    data: bytes


@dataclass(frozen=True)
class SecretAvailable:
    """A traffic secret is ready; protection.py derives packet keys from it."""

    level: EncryptionLevel
    direction: Direction
    secret: bytes


@dataclass(frozen=True)
class HandshakeComplete:
    """The handshake finished; negotiated values are final."""

    alpn: str
    peer_transport_parameters: bytes


TlsEvent = SendData | SecretAvailable | HandshakeComplete

UNEXPECTED_MESSAGE = 10
HANDSHAKE_FAILURE = 40
BAD_CERTIFICATE = 42
ILLEGAL_PARAMETER = 47
DECRYPT_ERROR = 51
PROTOCOL_VERSION = 70
MISSING_EXTENSION = 109
NO_APPLICATION_PROTOCOL = 120


class TlsAlert(Exception):
    """A fatal TLS alert (RFC 8446 §6.2); QUIC maps it to 0x0100 + code."""

    def __init__(self, alert: int, reason: str) -> None:
        super().__init__(reason)
        self.alert = alert


SigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

# RFC 8446 §4.1.3: a ServerHello with this random is a HelloRetryRequest.
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

CERTIFICATE_VERIFY_CONTEXT = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"


@dataclass(frozen=True)
class ClientConfig:
    """What a client needs to offer a handshake.

    Certificate policy per the recorded decision: strict by default
    (chain to ``ca_certificates`` plus RFC 9525 DNS-ID matching of
    ``server_name``, both delegated to cryptography's verifier).
    ``insecure_skip_verify`` disables policy validation for debugging
    only; the CertificateVerify signature is checked regardless.
    ``verification_time`` is the clock reading used for validity
    periods; the caller supplies it (sans-IO), None meaning now.
    """

    server_name: str
    alpn: list[str]
    transport_parameters: bytes
    ca_certificates: list[bytes] = field(default_factory=list[bytes])
    insecure_skip_verify: bool = False
    verification_time: datetime.datetime | None = None

    def __post_init__(self) -> None:
        if not self.insecure_skip_verify and not self.ca_certificates:
            raise ValueError("ca_certificates required unless insecure_skip_verify")


@dataclass(frozen=True)
class ServerConfig:
    """What a server needs to answer one: a DER chain and its signing key."""

    certificate_chain: list[bytes]
    signing_key: SigningKey
    alpn: list[str]
    transport_parameters: bytes


class ClientState(enum.Enum):
    """RFC 8446 Appendix A.1, restricted to the paths this profile takes."""

    START = enum.auto()
    WAIT_SERVER_HELLO = enum.auto()
    WAIT_ENCRYPTED_EXTENSIONS = enum.auto()
    WAIT_CERTIFICATE = enum.auto()
    WAIT_CERTIFICATE_VERIFY = enum.auto()
    WAIT_FINISHED = enum.auto()
    CONNECTED = enum.auto()


class ServerState(enum.Enum):
    """RFC 8446 Appendix A.2, restricted likewise."""

    START = enum.auto()
    WAIT_FINISHED = enum.auto()
    CONNECTED = enum.auto()


# What each state is waiting for, and at which encryption level it must
# arrive (RFC 9001 §4.1.4). The state machine is this table.
CLIENT_EXPECTS: dict[ClientState, tuple[HandshakeType, EncryptionLevel]] = {
    ClientState.WAIT_SERVER_HELLO: (HandshakeType.SERVER_HELLO, EncryptionLevel.INITIAL),
    ClientState.WAIT_ENCRYPTED_EXTENSIONS: (
        HandshakeType.ENCRYPTED_EXTENSIONS,
        EncryptionLevel.HANDSHAKE,
    ),
    ClientState.WAIT_CERTIFICATE: (HandshakeType.CERTIFICATE, EncryptionLevel.HANDSHAKE),
    ClientState.WAIT_CERTIFICATE_VERIFY: (
        HandshakeType.CERTIFICATE_VERIFY,
        EncryptionLevel.HANDSHAKE,
    ),
    ClientState.WAIT_FINISHED: (HandshakeType.FINISHED, EncryptionLevel.HANDSHAKE),
}

SERVER_EXPECTS: dict[ServerState, tuple[HandshakeType, EncryptionLevel]] = {
    ServerState.START: (HandshakeType.CLIENT_HELLO, EncryptionLevel.INITIAL),
    ServerState.WAIT_FINISHED: (HandshakeType.FINISHED, EncryptionLevel.HANDSHAKE),
}

_MESSAGE_TYPE_OF: dict[type[HandshakeMessage], HandshakeType] = {
    ClientHello: HandshakeType.CLIENT_HELLO,
    ServerHello: HandshakeType.SERVER_HELLO,
    EncryptedExtensions: HandshakeType.ENCRYPTED_EXTENSIONS,
    Certificate: HandshakeType.CERTIFICATE,
    CertificateVerify: HandshakeType.CERTIFICATE_VERIFY,
    Finished: HandshakeType.FINISHED,
    NewSessionTicket: HandshakeType.NEW_SESSION_TICKET,
}


def _find_extension(extensions: list[Extension], ext_type: int) -> bytes | None:
    for extension in extensions:
        if extension.type == ext_type:
            return extension.data
    return None


def _key_share_entry(public_key: bytes) -> bytes:
    return X25519_GROUP.to_bytes(2, "big") + _vec(2, public_key)


def _parse_key_share_entry(data: bytes) -> bytes:
    buf = Buffer(data)
    if buf.pull_uint16() != X25519_GROUP:
        raise TlsAlert(ILLEGAL_PARAMETER, "key_share group is not x25519")
    return buf.pull_bytes(buf.pull_uint16())


def _client_key_share(entries: bytes) -> bytes | None:
    """Find an x25519 public key among a ClientHello's KeyShareEntry list."""
    block = Buffer(Buffer(entries).pull_bytes(int.from_bytes(entries[:2], "big") + 2)[2:])
    while not block.is_empty:
        group = block.pull_uint16()
        public_key = block.pull_bytes(block.pull_uint16())
        if group == X25519_GROUP:
            return public_key
    return None


def _alpn_extension(protocols: list[str]) -> bytes:
    return _vec(2, b"".join(_vec(1, protocol.encode("ascii")) for protocol in protocols))


def _parse_alpn(data: bytes) -> list[str]:
    block = Buffer(Buffer(data).pull_bytes(int.from_bytes(data[:2], "big") + 2)[2:])
    protocols: list[str] = []
    while not block.is_empty:
        protocols.append(block.pull_bytes(block.pull_uint8()).decode("ascii"))
    return protocols


def _sign_certificate_verify(key: SigningKey, transcript_hash: bytes) -> tuple[int, bytes]:
    """Sign the CertificateVerify content (RFC 8446 §4.4.3)."""
    content = CERTIFICATE_VERIFY_CONTEXT + transcript_hash
    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(
            content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SHA256_LENGTH),
            hashes.SHA256(),
        )
        return RSA_PSS_RSAE_SHA256, signature
    signature = key.sign(content, ec.ECDSA(hashes.SHA256()))
    return ECDSA_SECP256R1_SHA256, signature


def _verify_certificate_verify(
    leaf_certificate: bytes, message: CertificateVerify, transcript_hash: bytes
) -> None:
    """Check the CertificateVerify signature against the presented leaf.

    RFC 8446 §4.4.3. Chain and hostname validation are a separate,
    later policy check; this proves the sender holds the leaf's key.
    """
    content = CERTIFICATE_VERIFY_CONTEXT + transcript_hash
    public_key = load_der_x509_certificate(leaf_certificate).public_key()
    try:
        if message.algorithm == RSA_PSS_RSAE_SHA256 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                message.signature,
                content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SHA256_LENGTH),
                hashes.SHA256(),
            )
        elif message.algorithm == ECDSA_SECP256R1_SHA256 and isinstance(
            public_key, ec.EllipticCurvePublicKey
        ):
            public_key.verify(message.signature, content, ec.ECDSA(hashes.SHA256()))
        else:
            raise TlsAlert(ILLEGAL_PARAMETER, "unsupported CertificateVerify algorithm")
    except InvalidSignature as exc:
        raise TlsAlert(DECRYPT_ERROR, "CertificateVerify signature is invalid") from exc


class _Handshake:
    """State shared by both roles: reassembly, transcript, events, keylog."""

    def __init__(self, keylog: Callable[[str], None] | None) -> None:
        self.schedule = KeySchedule()
        self.events: list[TlsEvent] = []
        self._buffers: dict[EncryptionLevel, bytearray] = {
            level: bytearray() for level in EncryptionLevel
        }
        self.client_hs_secret = b""
        self.server_hs_secret = b""
        self._keylog_callback = keylog
        self._client_random = b""

    def _keylog(self, label: str, secret: bytes) -> None:
        """Emit one NSS Key Log Format line; endpoints write SSLKEYLOGFILE."""
        if self._keylog_callback is not None:
            self._keylog_callback(f"{label} {self._client_random.hex()} {secret.hex()}")

    def take_events(self) -> list[TlsEvent]:
        events, self.events = self.events, []
        return events

    def receive(self, level: EncryptionLevel, data: bytes) -> None:
        """Consume CRYPTO bytes received at an encryption level."""
        header_length = 4  # one-byte type, three-byte length (RFC 8446 §4)
        buffer = self._buffers[level]
        buffer += data
        while len(buffer) >= header_length:
            length = header_length + int.from_bytes(buffer[1:4], "big")
            if len(buffer) < length:
                break
            raw = bytes(buffer[:length])
            del buffer[:length]
            message, _ = parse_handshake_message(raw)
            self._handle(level, message, raw)

    def _handle(self, level: EncryptionLevel, message: HandshakeMessage, raw: bytes) -> None:
        raise NotImplementedError

    def _require(
        self,
        expects: tuple[HandshakeType, EncryptionLevel],
        level: EncryptionLevel,
        message: HandshakeMessage,
    ) -> None:
        expected_type, expected_level = expects
        received = _MESSAGE_TYPE_OF[type(message)]
        if received is not expected_type:
            reason = f"expected {expected_type.name}, got {received.name}"
            raise TlsAlert(UNEXPECTED_MESSAGE, reason)
        if level is not expected_level:
            raise TlsAlert(UNEXPECTED_MESSAGE, f"{received.name} at wrong level {level.name}")

    def _emit_handshake_secrets(self, shared_secret: bytes) -> None:
        self.schedule.add_ecdhe(shared_secret)
        self.client_hs_secret = self.schedule.client_handshake_traffic_secret()
        self.server_hs_secret = self.schedule.server_handshake_traffic_secret()
        self._keylog("CLIENT_HANDSHAKE_TRAFFIC_SECRET", self.client_hs_secret)
        self._keylog("SERVER_HANDSHAKE_TRAFFIC_SECRET", self.server_hs_secret)
        self.events.append(
            SecretAvailable(EncryptionLevel.HANDSHAKE, Direction.CLIENT, self.client_hs_secret)
        )
        self.events.append(
            SecretAvailable(EncryptionLevel.HANDSHAKE, Direction.SERVER, self.server_hs_secret)
        )

    def _emit_application_secrets(self) -> None:
        """Derive 1-RTT secrets; transcript must end at the server Finished."""
        self.schedule.advance_to_master()
        client_secret = self.schedule.client_application_traffic_secret()
        server_secret = self.schedule.server_application_traffic_secret()
        self._keylog("CLIENT_TRAFFIC_SECRET_0", client_secret)
        self._keylog("SERVER_TRAFFIC_SECRET_0", server_secret)
        self.events.append(
            SecretAvailable(EncryptionLevel.ONE_RTT, Direction.CLIENT, client_secret)
        )
        self.events.append(
            SecretAvailable(EncryptionLevel.ONE_RTT, Direction.SERVER, server_secret)
        )


class TlsClient(_Handshake):
    """Client handshake state machine (RFC 8446 Appendix A.1)."""

    def __init__(
        self,
        config: ClientConfig,
        random: bytes | None = None,
        key: X25519PrivateKey | None = None,
        keylog: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(keylog)
        self._config = config
        self._random = random if random is not None else os.urandom(32)
        self._client_random = self._random
        self._key = key if key is not None else X25519PrivateKey.generate()
        self._leaf_certificate = b""
        self._alpn = ""
        self._peer_transport_parameters = b""
        self.state = ClientState.START

    def start(self) -> None:
        """Send the ClientHello (RFC 8446 §4.1.2) at the Initial level."""
        hello = ClientHello(
            random=self._random,
            legacy_session_id=b"",  # QUIC has no middlebox compatibility mode (RFC 9001 §8.4)
            cipher_suites=[TLS_AES_128_GCM_SHA256],
            extensions=[
                Extension(
                    ExtensionType.SERVER_NAME,
                    _vec(2, b"\x00" + _vec(2, self._config.server_name.encode("ascii"))),
                ),
                Extension(ExtensionType.SUPPORTED_GROUPS, _vec(2, X25519_GROUP.to_bytes(2, "big"))),
                Extension(
                    ExtensionType.SIGNATURE_ALGORITHMS,
                    _vec(
                        2,
                        RSA_PSS_RSAE_SHA256.to_bytes(2, "big")
                        + ECDSA_SECP256R1_SHA256.to_bytes(2, "big"),
                    ),
                ),
                Extension(ExtensionType.ALPN, _alpn_extension(self._config.alpn)),
                Extension(ExtensionType.SUPPORTED_VERSIONS, _vec(1, TLS_1_3.to_bytes(2, "big"))),
                Extension(
                    ExtensionType.KEY_SHARE,
                    _vec(2, _key_share_entry(self._key.public_key().public_bytes_raw())),
                ),
                Extension(
                    ExtensionType.QUIC_TRANSPORT_PARAMETERS, self._config.transport_parameters
                ),
            ],
        )
        raw = encode_client_hello(hello)
        self.schedule.update_transcript(raw)
        self.events.append(SendData(EncryptionLevel.INITIAL, raw))
        self.state = ClientState.WAIT_SERVER_HELLO

    def _handle(self, level: EncryptionLevel, message: HandshakeMessage, raw: bytes) -> None:
        if self.state is ClientState.CONNECTED:
            if isinstance(message, NewSessionTicket):
                return  # no resumption yet (RFC 8446 §4.6.1)
            raise TlsAlert(UNEXPECTED_MESSAGE, "handshake message after completion")
        self._require(CLIENT_EXPECTS[self.state], level, message)
        if isinstance(message, ServerHello):
            self._on_server_hello(message, raw)
        elif isinstance(message, EncryptedExtensions):
            self._on_encrypted_extensions(message, raw)
        elif isinstance(message, Certificate):
            self._on_certificate(message, raw)
        elif isinstance(message, CertificateVerify):
            self._on_certificate_verify(message, raw)
        elif isinstance(message, Finished):
            self._on_finished(message, raw)

    def _on_server_hello(self, hello: ServerHello, raw: bytes) -> None:
        if hello.random == HELLO_RETRY_REQUEST_RANDOM:
            raise TlsAlert(HANDSHAKE_FAILURE, "HelloRetryRequest not supported")
        if hello.legacy_session_id_echo != b"":
            raise TlsAlert(ILLEGAL_PARAMETER, "session id echo is not empty")
        if hello.cipher_suite != TLS_AES_128_GCM_SHA256:
            raise TlsAlert(ILLEGAL_PARAMETER, "server selected an unoffered cipher suite")
        versions = _find_extension(hello.extensions, ExtensionType.SUPPORTED_VERSIONS)
        if versions != TLS_1_3.to_bytes(2, "big"):
            raise TlsAlert(PROTOCOL_VERSION, "server did not select TLS 1.3")
        key_share = _find_extension(hello.extensions, ExtensionType.KEY_SHARE)
        if key_share is None:
            raise TlsAlert(MISSING_EXTENSION, "ServerHello has no key_share")
        peer_public = _parse_key_share_entry(key_share)
        self.schedule.update_transcript(raw)
        shared = self._key.exchange(X25519PublicKey.from_public_bytes(peer_public))
        self._emit_handshake_secrets(shared)
        self.state = ClientState.WAIT_ENCRYPTED_EXTENSIONS

    def _on_encrypted_extensions(self, message: EncryptedExtensions, raw: bytes) -> None:
        alpn_data = _find_extension(message.extensions, ExtensionType.ALPN)
        if alpn_data is None:
            raise TlsAlert(NO_APPLICATION_PROTOCOL, "server selected no ALPN protocol")
        selected = _parse_alpn(alpn_data)
        if len(selected) != 1 or selected[0] not in self._config.alpn:
            raise TlsAlert(NO_APPLICATION_PROTOCOL, "server selected an unoffered ALPN protocol")
        transport_parameters = _find_extension(
            message.extensions, ExtensionType.QUIC_TRANSPORT_PARAMETERS
        )
        if transport_parameters is None:
            raise TlsAlert(MISSING_EXTENSION, "no quic_transport_parameters (RFC 9001 §8.2)")
        self._alpn = selected[0]
        self._peer_transport_parameters = transport_parameters
        self.schedule.update_transcript(raw)
        self.state = ClientState.WAIT_CERTIFICATE

    def _on_certificate(self, message: Certificate, raw: bytes) -> None:
        if not message.entries:
            raise TlsAlert(ILLEGAL_PARAMETER, "empty certificate chain")
        self._leaf_certificate = message.entries[0].data
        if not self._config.insecure_skip_verify:
            self._verify_certificate_policy(message)
        self.schedule.update_transcript(raw)
        self.state = ClientState.WAIT_CERTIFICATE_VERIFY

    def _verify_certificate_policy(self, message: Certificate) -> None:
        """Chain and hostname validation, delegated to cryptography.

        Path building to the configured trust anchors plus RFC 9525
        DNS-ID matching of the SNI name, both inside
        ``build_server_verifier``. Distinct from the CertificateVerify
        signature check, which only proves possession of the leaf key.
        """
        leaf = load_der_x509_certificate(message.entries[0].data)
        intermediates = [load_der_x509_certificate(entry.data) for entry in message.entries[1:]]
        store = Store([load_der_x509_certificate(der) for der in self._config.ca_certificates])
        builder = PolicyBuilder().store(store)
        if self._config.verification_time is not None:
            builder = builder.time(self._config.verification_time)
        verifier = builder.build_server_verifier(DNSName(self._config.server_name))
        try:
            verifier.verify(leaf, intermediates)
        except VerificationError as exc:
            raise TlsAlert(BAD_CERTIFICATE, f"certificate verification failed: {exc}") from exc

    def _on_certificate_verify(self, message: CertificateVerify, raw: bytes) -> None:
        _verify_certificate_verify(self._leaf_certificate, message, self.schedule.transcript_hash())
        self.schedule.update_transcript(raw)
        self.state = ClientState.WAIT_FINISHED

    def _on_finished(self, message: Finished, raw: bytes) -> None:
        expected = finished_verify_data(self.server_hs_secret, self.schedule.transcript_hash())
        if message.verify_data != expected:
            raise TlsAlert(DECRYPT_ERROR, "server Finished verify_data mismatch")
        self.schedule.update_transcript(raw)
        # 1-RTT secrets use the transcript through the server Finished
        # (RFC 8446 §7.1); the client Finished is not included.
        self._emit_application_secrets()
        verify = finished_verify_data(self.client_hs_secret, self.schedule.transcript_hash())
        finished = encode_finished(Finished(verify_data=verify))
        self.schedule.update_transcript(finished)
        self.events.append(SendData(EncryptionLevel.HANDSHAKE, finished))
        self.events.append(HandshakeComplete(self._alpn, self._peer_transport_parameters))
        self.state = ClientState.CONNECTED


class TlsServer(_Handshake):
    """Server handshake state machine (RFC 8446 Appendix A.2)."""

    def __init__(
        self,
        config: ServerConfig,
        random: bytes | None = None,
        key: X25519PrivateKey | None = None,
        keylog: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(keylog)
        self._config = config
        self._random = random if random is not None else os.urandom(32)
        self._key = key if key is not None else X25519PrivateKey.generate()
        self._alpn = ""
        self._client_transport_parameters = b""
        self.state = ServerState.START

    def _handle(self, level: EncryptionLevel, message: HandshakeMessage, raw: bytes) -> None:
        if self.state is ServerState.CONNECTED:
            raise TlsAlert(UNEXPECTED_MESSAGE, "handshake message after completion")
        self._require(SERVER_EXPECTS[self.state], level, message)
        if isinstance(message, ClientHello):
            self._on_client_hello(message, raw)
        elif isinstance(message, Finished):
            self._on_finished(message, raw)

    def _negotiate_alpn(self, hello: ClientHello) -> str:
        alpn_data = _find_extension(hello.extensions, ExtensionType.ALPN)
        offered = _parse_alpn(alpn_data) if alpn_data is not None else []
        for protocol in self._config.alpn:
            if protocol in offered:
                return protocol
        raise TlsAlert(NO_APPLICATION_PROTOCOL, "no ALPN protocol in common")

    def _on_client_hello(self, hello: ClientHello, raw: bytes) -> None:
        if TLS_AES_128_GCM_SHA256 not in hello.cipher_suites:
            raise TlsAlert(HANDSHAKE_FAILURE, "client did not offer TLS_AES_128_GCM_SHA256")
        versions = _find_extension(hello.extensions, ExtensionType.SUPPORTED_VERSIONS)
        if versions is None or TLS_1_3.to_bytes(2, "big") not in versions:
            raise TlsAlert(PROTOCOL_VERSION, "client did not offer TLS 1.3")
        key_share = _find_extension(hello.extensions, ExtensionType.KEY_SHARE)
        peer_public = _client_key_share(key_share) if key_share is not None else None
        if peer_public is None:
            # A HelloRetryRequest could ask for x25519; out of scope.
            raise TlsAlert(HANDSHAKE_FAILURE, "client offered no x25519 key share")
        client_transport_parameters = _find_extension(
            hello.extensions, ExtensionType.QUIC_TRANSPORT_PARAMETERS
        )
        if client_transport_parameters is None:
            raise TlsAlert(MISSING_EXTENSION, "no quic_transport_parameters (RFC 9001 §8.2)")
        alpn = self._negotiate_alpn(hello)
        self._client_random = hello.random

        self.schedule.update_transcript(raw)
        server_hello = ServerHello(
            random=self._random,
            legacy_session_id_echo=hello.legacy_session_id,
            cipher_suite=TLS_AES_128_GCM_SHA256,
            extensions=[
                Extension(ExtensionType.SUPPORTED_VERSIONS, TLS_1_3.to_bytes(2, "big")),
                Extension(
                    ExtensionType.KEY_SHARE,
                    _key_share_entry(self._key.public_key().public_bytes_raw()),
                ),
            ],
        )
        raw_server_hello = encode_server_hello(server_hello)
        self.schedule.update_transcript(raw_server_hello)
        self.events.append(SendData(EncryptionLevel.INITIAL, raw_server_hello))
        shared = self._key.exchange(X25519PublicKey.from_public_bytes(peer_public))
        self._emit_handshake_secrets(shared)

        encrypted_extensions = encode_encrypted_extensions(
            EncryptedExtensions(
                extensions=[
                    Extension(ExtensionType.ALPN, _alpn_extension([alpn])),
                    Extension(
                        ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                        self._config.transport_parameters,
                    ),
                ]
            )
        )
        certificate = encode_certificate(
            Certificate(
                request_context=b"",
                entries=[
                    CertificateEntry(data=data, extensions=[])
                    for data in self._config.certificate_chain
                ],
            )
        )
        self.schedule.update_transcript(encrypted_extensions)
        self.schedule.update_transcript(certificate)
        algorithm, signature = _sign_certificate_verify(
            self._config.signing_key, self.schedule.transcript_hash()
        )
        certificate_verify = encode_certificate_verify(
            CertificateVerify(algorithm=algorithm, signature=signature)
        )
        self.schedule.update_transcript(certificate_verify)
        verify = finished_verify_data(self.server_hs_secret, self.schedule.transcript_hash())
        finished = encode_finished(Finished(verify_data=verify))
        self.schedule.update_transcript(finished)
        self.events.append(
            SendData(
                EncryptionLevel.HANDSHAKE,
                encrypted_extensions + certificate + certificate_verify + finished,
            )
        )
        self._emit_application_secrets()
        self._alpn = alpn
        self._client_transport_parameters = client_transport_parameters
        self.state = ServerState.WAIT_FINISHED

    def _on_finished(self, message: Finished, raw: bytes) -> None:
        expected = finished_verify_data(self.client_hs_secret, self.schedule.transcript_hash())
        if message.verify_data != expected:
            raise TlsAlert(DECRYPT_ERROR, "client Finished verify_data mismatch")
        self.schedule.update_transcript(raw)
        self.events.append(HandshakeComplete(self._alpn, self._client_transport_parameters))
        self.state = ServerState.CONNECTED
