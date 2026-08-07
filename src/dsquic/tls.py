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
HelloRetryRequest on both sides (§4.1.4) with the message_hash
transcript substitution (§4.4.1); CertificateVerify signing and
verification; certificate policy on the client (chain to configured
anchors plus RFC 9525 hostname matching, delegated to cryptography's
verifier, with an explicit insecure flag); session-ticket resumption
(§4.6.1): sealed tickets issued by the server and stored by the client,
the client's pre_shared_key offer with its binder (§4.2.11), and
server-side PSK selection (§4.2.9, §4.2.11), which extracts the PSK
into the Early Secret (§7.1) and omits certificate authentication
(§2.2); and the NSS-format keylog callback. Unknown extensions are
preserved on parse and ignored, never rejected (grease tolerance,
RFC 8701).

One key exchange group, x25519. That is enough to interoperate, because
peers offering post-quantum groups also offer classical ones; when such a
peer sends no x25519 share, the server asks for one with a
HelloRetryRequest rather than failing.
"""

import datetime
import enum
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

TICKET_NONCE_LENGTH = 12  # AES-GCM nonce for a sealed ticket
TICKET_KEY_LENGTH = 32  # AES-256-GCM key that seals session tickets (§4.6.1)
PSK_DHE_KE = 1  # §4.2.9: resumption with an ECDHE exchange
SESSION_TICKET_LIFETIME = 7200  # seconds; §4.6.1 caps this at 7 days
MESSAGE_HASH_TYPE = 254  # §4.4.1, the HelloRetryRequest transcript stand-in
SUPPORTED_GROUPS = [X25519_GROUP]  # groups this implementation can key with


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
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
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

    def __init__(self, psk: bytes | None = None) -> None:
        """§7.1: the Early Secret extracts a PSK when resuming, and all
        zeros when not."""
        self._transcript = hashes.Hash(hashes.SHA256())
        ikm = psk if psk is not None else bytes(SHA256_LENGTH)
        self._secret = hkdf_extract(bytes(SHA256_LENGTH), ikm)

    def update_transcript(self, handshake_message: bytes) -> None:
        self._transcript.update(handshake_message)

    def transcript_hash(self) -> bytes:
        return self._transcript.copy().finalize()

    def replace_transcript_with_message_hash(self) -> None:
        """Substitute ClientHello1 with a synthetic message (§4.4.1).

        After a HelloRetryRequest the transcript is not the messages as
        sent: the first ClientHello is replaced by a ``message_hash``
        handshake message (type 254) carrying its hash, so the second
        ClientHello hashes over a fixed-size stand-in rather than the
        original bytes. Every secret downstream depends on getting this
        right, which is why it is done in one place.
        """
        digest = self.transcript_hash()
        self._transcript = hashes.Hash(hashes.SHA256())
        synthetic = bytes([MESSAGE_HASH_TYPE]) + len(digest).to_bytes(3, "big") + digest
        self._transcript.update(synthetic)

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

    def binder_key(self) -> bytes:
        """§7.1: the base secret a PSK binder is computed from.

        Derived at the Early Secret, before any ECDHE, because the binder
        covers a ClientHello that has not been answered yet. The binder
        itself is finished_verify_data over it, since §4.2.11.2 gives the
        binder the same construction as a Finished message.
        """
        return hkdf_expand_label(self._secret, b"res binder", EMPTY_TRANSCRIPT_HASH, SHA256_LENGTH)

    def resumption_master_secret(self) -> bytes:
        """§7.1: derived at the Master Secret over the transcript through
        the client's Finished, which is the last message it covers."""
        return self._derive(b"res master")

    def client_handshake_traffic_secret(self) -> bytes:
        return self._derive(b"c hs traffic")

    def server_handshake_traffic_secret(self) -> bytes:
        return self._derive(b"s hs traffic")

    def client_application_traffic_secret(self) -> bytes:
        return self._derive(b"c ap traffic")

    def server_application_traffic_secret(self) -> bytes:
        return self._derive(b"s ap traffic")


@dataclass(frozen=True)
class SessionTicket:
    """A ticket a client holds for resumption (RFC 8446 §4.6.1).

    ``identity`` is the opaque ticket the server issued, ``psk`` the
    secret it stands for, and ``age_add`` the value added to its age
    when offering it so observers cannot correlate offers.
    """

    identity: bytes
    psk: bytes
    age_add: int
    lifetime: int
    received_at: float


def seal_ticket(key: bytes, psk: bytes, now: float) -> bytes:
    """§4.6.1: a ticket only its issuer can read.

    The PSK travels inside, so the server needs no per-ticket state; the
    issue time travels with it so expiry can be checked on return.
    """
    nonce = os.urandom(TICKET_NONCE_LENGTH)
    plaintext = int(now).to_bytes(8, "big") + psk
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def open_ticket(key: bytes, ticket: bytes, now: float, lifetime: float) -> bytes:
    """Recover the PSK a ticket stands for, or raise (§4.6.1)."""
    nonce, sealed = ticket[:TICKET_NONCE_LENGTH], ticket[TICKET_NONCE_LENGTH:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, sealed, None)
    except InvalidTag as exc:
        raise TicketError("ticket does not authenticate") from exc
    issued = int.from_bytes(plaintext[:8], "big")
    if now - issued > lifetime:
        raise TicketError("ticket has expired")
    return plaintext[8:]


class TicketError(Exception):
    """A ticket that cannot be used (§4.6.1)."""


@dataclass(frozen=True)
class PskIdentity:
    """One offered ticket (RFC 8446 §4.2.11).

    ``obfuscated_ticket_age`` is the ticket's age in milliseconds plus
    the ``age_add`` it was issued with, so an observer cannot correlate
    offers by age.
    """

    identity: bytes
    obfuscated_ticket_age: int


def encode_offered_psks(identities: list[PskIdentity], binders: list[bytes]) -> bytes:
    """The pre_shared_key extension a client offers (§4.2.11).

    It is the last extension in a ClientHello, because the binders cover
    everything before them and nothing can follow.
    """
    offered = b"".join(
        _vec(2, identity.identity) + identity.obfuscated_ticket_age.to_bytes(4, "big")
        for identity in identities
    )
    return _vec(2, offered) + _vec(2, b"".join(_vec(1, binder) for binder in binders))


def parse_offered_psks(data: bytes) -> tuple[list[PskIdentity], list[bytes]]:
    """Read a client's pre_shared_key extension (§4.2.11)."""
    buf = Buffer(data)
    identities_block = Buffer(buf.pull_bytes(buf.pull_uint16()))
    identities: list[PskIdentity] = []
    while not identities_block.is_empty:
        identity = identities_block.pull_bytes(identities_block.pull_uint16())
        identities.append(
            PskIdentity(
                identity=identity,
                obfuscated_ticket_age=identities_block.pull_uint32(),
            )
        )
    binders_block = Buffer(buf.pull_bytes(buf.pull_uint16()))
    binders: list[bytes] = []
    while not binders_block.is_empty:
        binders.append(binders_block.pull_bytes(binders_block.pull_uint8()))
    if len(identities) != len(binders):
        raise TlsAlert(ILLEGAL_PARAMETER, "one binder per identity is required")
    return identities, binders


def binder_transcript(client_hello: bytes, binder_count: int = 1) -> bytes:
    """§4.2.11.2: the ClientHello bytes a binder is computed over.

    Everything up to the binders, which a binder cannot cover since it is
    one of them. The header's length field still counts them, so this
    truncates the encoded message rather than encoding a shorter one.
    """
    trailing = 2 + binder_count * (1 + SHA256_LENGTH)
    if len(client_hello) <= trailing:
        raise TlsAlert(DECODE_ERROR, "ClientHello is too short to carry its binders")
    return client_hello[:-trailing]


def resumption_psk(resumption_master_secret: bytes, ticket_nonce: bytes) -> bytes:
    """§4.6.1: the PSK a ticket stands for.

    The nonce makes every ticket issued on one connection derive a
    different PSK, so tickets cannot be correlated by the value they
    carry.
    """
    return hkdf_expand_label(resumption_master_secret, b"resumption", ticket_nonce, SHA256_LENGTH)


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
    """RFC 8446 §4.6.1.

    ``nonce`` is what makes each ticket stand for a different PSK, and
    ``ticket`` is opaque to the client: only the server that issued it
    can read it back.
    """

    lifetime: int
    age_add: int
    nonce: bytes
    ticket: bytes
    extensions: list[Extension]


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


def encode_new_session_ticket(message: NewSessionTicket) -> bytes:
    body = (
        message.lifetime.to_bytes(4, "big")
        + message.age_add.to_bytes(4, "big")
        + _vec(1, message.nonce)
        + _vec(2, message.ticket)
        + _encode_extensions(message.extensions)
    )
    return _handshake_message(HandshakeType.NEW_SESSION_TICKET, body)


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


def _parse_new_session_ticket(buf: Buffer) -> NewSessionTicket:
    return NewSessionTicket(
        lifetime=buf.pull_uint32(),
        age_add=buf.pull_uint32(),
        nonce=buf.pull_bytes(buf.pull_uint8()),
        ticket=buf.pull_bytes(buf.pull_uint16()),
        extensions=_parse_extensions(buf),
    )


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
        message = _parse_new_session_ticket(body)
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
DECODE_ERROR = 50
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
    # Which offered groups to send a key share for. None means all of
    # them. A client may deliberately offer groups without shares to keep
    # the ClientHello small, accepting a HelloRetryRequest round trip in
    # exchange; an empty list does that for every group.
    key_share_groups: list[int] | None = None
    # §4.6.1: a ticket kept from an earlier connection to this server.
    # None means offer no PSK, which is an ordinary full handshake.
    session_ticket: "SessionTicket | None" = None

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
    # §4.6.1: the key that seals session tickets. A server keeps no state
    # for a ticket it issued, so everything needed to resume travels
    # inside it, sealed. None means tickets are not issued.
    ticket_key: bytes | None = None


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
    WAIT_SECOND_CLIENT_HELLO = enum.auto()  # a HelloRetryRequest is outstanding
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
    ServerState.WAIT_SECOND_CLIENT_HELLO: (
        HandshakeType.CLIENT_HELLO,
        EncryptionLevel.INITIAL,
    ),
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


def _key_share_entry(group: int, public_key: bytes) -> bytes:
    return group.to_bytes(2, "big") + _vec(2, public_key)


def _parse_key_share_entry(data: bytes) -> tuple[int, bytes]:
    buf = Buffer(data)
    group = buf.pull_uint16()
    if group not in SUPPORTED_GROUPS:
        raise TlsAlert(ILLEGAL_PARAMETER, f"key_share group {group:#06x} is not supported")
    return group, buf.pull_bytes(buf.pull_uint16())


def _client_key_share(entries: bytes) -> bytes | None:
    """Find an x25519 public key among a ClientHello's KeyShareEntry list."""
    block = Buffer(Buffer(entries).pull_bytes(int.from_bytes(entries[:2], "big") + 2)[2:])
    while not block.is_empty:
        group = block.pull_uint16()
        public_key = block.pull_bytes(block.pull_uint16())
        if group == X25519_GROUP:
            return public_key
    return None


def _parse_supported_groups(data: bytes) -> list[int]:
    """The groups a peer will accept, in preference order (§4.2.7)."""
    block = Buffer(Buffer(data).pull_bytes(int.from_bytes(data[:2], "big") + 2)[2:])
    groups: list[int] = []
    while not block.is_empty:
        groups.append(block.pull_uint16())
    return groups


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
        # The caller's last clock reading, stamped into session tickets.
        self._now = 0.0
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

    def receive(self, level: EncryptionLevel, data: bytes, now: float) -> None:
        """Consume CRYPTO bytes received at an encryption level.

        ``now`` is the caller's clock reading, which a server stamps into
        the session tickets it issues (§4.6.1). Nothing here reads a
        clock of its own.
        """
        self._now = now
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
        # §4.6.1: tickets arrive after the handshake, so a caller reads
        # them once the connection is up and keeps them for next time.
        self.session_tickets: list[SessionTicket] = []
        self._fallback_schedule: KeySchedule | None = None
        # §2.2: whether the server took the PSK offer; its ServerHello decides.
        self.resumed = False
        if config.session_ticket is not None:
            # §7.1: resuming extracts the PSK into the Early Secret, and
            # the binder is derived from it, so the schedule has to carry
            # the PSK before the ClientHello is built. Whether the server
            # takes the offer is unknown until its ServerHello, so a
            # zero-PSK schedule rides along for the decline path
            # (§4.2.11).
            self.schedule = KeySchedule(psk=config.session_ticket.psk)
            self._fallback_schedule = KeySchedule()
        self._random = random if random is not None else os.urandom(32)
        self._client_random = self._random
        share_groups = (
            SUPPORTED_GROUPS if config.key_share_groups is None else config.key_share_groups
        )
        self._keys: dict[int, X25519PrivateKey] = {
            group: (key if key is not None else X25519PrivateKey.generate())
            for group in share_groups
        }
        self._hello_retried = False
        self._leaf_certificate = b""
        self._alpn = ""
        self._peer_transport_parameters = b""
        self.state = ClientState.START

    def _build_client_hello(self) -> ClientHello:
        """RFC 8446 §4.1.2. Sent again unchanged except for key_share if
        the server answers with a HelloRetryRequest (§4.1.4)."""
        shares = b"".join(
            _key_share_entry(group, key.public_key().public_bytes_raw())
            for group, key in self._keys.items()
        )
        groups = b"".join(group.to_bytes(2, "big") for group in SUPPORTED_GROUPS)
        return ClientHello(
            random=self._random,
            legacy_session_id=b"",  # QUIC has no middlebox compatibility mode (RFC 9001 §8.4)
            cipher_suites=[TLS_AES_128_GCM_SHA256],
            extensions=[
                Extension(
                    ExtensionType.SERVER_NAME,
                    _vec(2, b"\x00" + _vec(2, self._config.server_name.encode("ascii"))),
                ),
                Extension(ExtensionType.SUPPORTED_GROUPS, _vec(2, groups)),
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
                Extension(ExtensionType.KEY_SHARE, _vec(2, shares)),
                Extension(
                    ExtensionType.QUIC_TRANSPORT_PARAMETERS, self._config.transport_parameters
                ),
                *(
                    self._psk_extensions(self._config.session_ticket)
                    if self._config.session_ticket is not None
                    else []
                ),
            ],
        )

    def start(self, now: float) -> None:
        """Send the ClientHello at the Initial level.

        ``now`` is the caller's clock reading; a resumption offer
        measures its ticket's age from it (§4.2.11.1).
        """
        self._now = now
        raw = encode_client_hello(self._build_client_hello())
        if self._config.session_ticket is not None:
            raw = self._fill_psk_binder(raw)
        else:
            self.schedule.update_transcript(raw)
        if self._fallback_schedule is not None:
            self._fallback_schedule.update_transcript(raw)
        self.events.append(SendData(EncryptionLevel.INITIAL, raw))
        self.state = ClientState.WAIT_SERVER_HELLO

    def _psk_extensions(self, ticket: SessionTicket) -> list[Extension]:
        """§4.2.9 and §4.2.11: offer a ticket, with a placeholder binder.

        pre_shared_key is last because the binder covers everything
        before it, so nothing may follow. The binder is written over the
        placeholder once the message is encoded, since it is a MAC of
        those very bytes.
        """
        age = int((self._now - ticket.received_at) * 1000) + ticket.age_add
        return [
            # psk_dhe_ke: resumption still does an ECDHE exchange, so the
            # new connection has forward secrecy of its own.
            Extension(ExtensionType.PSK_KEY_EXCHANGE_MODES, _vec(1, bytes([PSK_DHE_KE]))),
            Extension(
                ExtensionType.PRE_SHARED_KEY,
                encode_offered_psks(
                    [PskIdentity(identity=ticket.identity, obfuscated_ticket_age=age % 2**32)],
                    [bytes(SHA256_LENGTH)],
                ),
            ),
        ]

    def _fill_psk_binder(self, raw: bytes) -> bytes:
        """§4.2.11.2: replace the placeholder binder with the real one.

        The binder is a Finished over the running transcript plus this
        hello truncated at its binders; after a HelloRetryRequest that
        transcript already holds the first hello and the retry. The
        schedule is fed in two chunks so the binder can be read off
        between them. The message is patched rather than re-encoded
        short: the length field the binder covers counts the binder, so
        a shorter encoding would authenticate different bytes than the
        ones sent.
        """
        truncated = binder_transcript(raw)
        self.schedule.update_transcript(truncated)
        binder = finished_verify_data(self.schedule.binder_key(), self.schedule.transcript_hash())
        patched = raw[: -len(binder)] + binder
        self.schedule.update_transcript(patched[len(truncated) :])
        return patched

    def _on_hello_retry_request(self, hello: ServerHello, raw: bytes) -> None:
        """Generate the requested key share and send a second ClientHello.

        RFC 8446 §4.1.4. Exactly one retry is permitted, the requested
        group must be one we offered, and it must differ from a share we
        already sent, since a retry that changes nothing is a loop.
        """
        if self._hello_retried:
            raise TlsAlert(UNEXPECTED_MESSAGE, "second HelloRetryRequest")
        # §4.1.4: the retry's key_share carries a NamedGroup and nothing else.
        selected_group_length = 2
        key_share = _find_extension(hello.extensions, ExtensionType.KEY_SHARE)
        if key_share is None or len(key_share) != selected_group_length:
            raise TlsAlert(MISSING_EXTENSION, "HelloRetryRequest has no selected group")
        group = int.from_bytes(key_share, "big")
        if group not in SUPPORTED_GROUPS:
            raise TlsAlert(ILLEGAL_PARAMETER, f"HelloRetryRequest group {group:#06x} not offered")
        if group in self._keys:
            raise TlsAlert(ILLEGAL_PARAMETER, "HelloRetryRequest asks for a group already shared")
        self._hello_retried = True
        # §4.4.1: ClientHello1 becomes a message_hash before the retry.
        self.schedule.replace_transcript_with_message_hash()
        self.schedule.update_transcript(raw)
        if self._fallback_schedule is not None:
            self._fallback_schedule.replace_transcript_with_message_hash()
            self._fallback_schedule.update_transcript(raw)
        self._keys = {group: X25519PrivateKey.generate()}
        retry = encode_client_hello(self._build_client_hello())
        if self._config.session_ticket is not None:
            # §4.1.4: the second hello recomputes its binder, which now
            # covers the first hello and the retry (§4.2.11.2).
            retry = self._fill_psk_binder(retry)
        else:
            self.schedule.update_transcript(retry)
        if self._fallback_schedule is not None:
            self._fallback_schedule.update_transcript(retry)
        self.events.append(SendData(EncryptionLevel.INITIAL, retry))
        self.state = ClientState.WAIT_SERVER_HELLO

    def _handle(self, level: EncryptionLevel, message: HandshakeMessage, raw: bytes) -> None:
        if self.state is ClientState.CONNECTED:
            if isinstance(message, NewSessionTicket):
                self._store_session_ticket(message)
                return
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
            self._on_hello_retry_request(hello, raw)
            return
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
        group, peer_public = _parse_key_share_entry(key_share)
        our_key = self._keys.get(group)
        if our_key is None:
            raise TlsAlert(ILLEGAL_PARAMETER, f"server chose group {group:#06x} with no share")
        selected = _find_extension(hello.extensions, ExtensionType.PRE_SHARED_KEY)
        if selected is not None:
            if self._config.session_ticket is None:
                raise TlsAlert(ILLEGAL_PARAMETER, "pre_shared_key answers an offer never made")
            if int.from_bytes(selected, "big") != 0:
                # §4.2.11: selected_identity indexes the offered list,
                # which held exactly one identity.
                raise TlsAlert(ILLEGAL_PARAMETER, "selected_identity is out of range")
            self.resumed = True
        elif self._fallback_schedule is not None:
            # §4.2.11: the offer was declined, so this is a full
            # handshake and the Early Secret extracts zeros rather than
            # the ticket's PSK (§7.1).
            self.schedule = self._fallback_schedule
        self._fallback_schedule = None
        self.schedule.update_transcript(raw)
        shared = our_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
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
        # §2.2: a PSK authenticates the connection, so a resumed
        # handshake carries no Certificate or CertificateVerify.
        self.state = ClientState.WAIT_FINISHED if self.resumed else ClientState.WAIT_CERTIFICATE

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

    def _store_session_ticket(self, message: NewSessionTicket) -> None:
        """§4.6.1: keep what a later handshake needs to resume.

        The PSK is derived now rather than stored by the server, so the
        ticket the client keeps is a secret in its own right and is held
        for exactly as long as the server said it is good for.
        """
        self.session_tickets.append(
            SessionTicket(
                identity=message.ticket,
                psk=resumption_psk(self.schedule.resumption_master_secret(), message.nonce),
                age_add=message.age_add,
                lifetime=message.lifetime,
                received_at=self._now,
            )
        )

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
        self._hello_retry_sent = False
        self._alpn = ""
        self._client_transport_parameters = b""
        # §2.2: whether this handshake resumed a session via a PSK.
        self.resumed = False
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

    def _send_hello_retry_request(self, hello: ClientHello, raw: bytes, group: int) -> None:
        """Ask the client to retry with a key share for ``group`` (§4.1.4).

        A HelloRetryRequest is a ServerHello carrying the reserved random
        and a key_share holding only the selected group. Only one may be
        sent per connection, and the transcript substitutes a
        message_hash for the first ClientHello (§4.4.1).
        """
        if self._hello_retry_sent:
            raise TlsAlert(HANDSHAKE_FAILURE, "client retried without a usable key share")
        self._hello_retry_sent = True
        self.schedule.update_transcript(raw)
        self.schedule.replace_transcript_with_message_hash()
        retry = encode_server_hello(
            ServerHello(
                random=HELLO_RETRY_REQUEST_RANDOM,
                legacy_session_id_echo=hello.legacy_session_id,
                cipher_suite=TLS_AES_128_GCM_SHA256,
                extensions=[
                    Extension(ExtensionType.SUPPORTED_VERSIONS, TLS_1_3.to_bytes(2, "big")),
                    Extension(ExtensionType.KEY_SHARE, group.to_bytes(2, "big")),
                ],
            )
        )
        self.schedule.update_transcript(retry)
        self.events.append(SendData(EncryptionLevel.INITIAL, retry))
        self.state = ServerState.WAIT_SECOND_CLIENT_HELLO

    def _select_psk(self, hello: ClientHello, raw: bytes) -> tuple[int, bytes] | None:
        """Pick an offered PSK this server can honour (§4.2.11).

        Returns the selected identity's index and the PSK it stands for,
        or None to proceed with a full handshake, which §4.2.11 always
        permits. A selected identity's binder must verify or the
        handshake aborts (§4.2.11.2); ticket ages are not checked, since
        §4.2.11 reserves them for 0-RTT freshness.
        """
        offer = _find_extension(hello.extensions, ExtensionType.PRE_SHARED_KEY)
        if offer is None:
            return None
        if hello.extensions[-1].type != ExtensionType.PRE_SHARED_KEY:
            raise TlsAlert(ILLEGAL_PARAMETER, "pre_shared_key is not the last extension")
        modes = _find_extension(hello.extensions, ExtensionType.PSK_KEY_EXCHANGE_MODES)
        if modes is None:
            raise TlsAlert(
                MISSING_EXTENSION, "pre_shared_key without psk_key_exchange_modes (§4.2.9)"
            )
        if PSK_DHE_KE not in modes[1:]:
            # Only resumption with an ECDHE exchange is supported.
            return None
        if self._config.ticket_key is None:
            return None
        if self._hello_retry_sent:
            # A second ClientHello's binder covers ClientHello1 and the
            # HelloRetryRequest (§4.2.11.2), a transcript this server no
            # longer holds message bytes for.
            return None
        identities, binders = parse_offered_psks(offer)
        for index, psk_identity in enumerate(identities):
            try:
                psk = open_ticket(
                    self._config.ticket_key,
                    psk_identity.identity,
                    self._now,
                    SESSION_TICKET_LIFETIME,
                )
            except TicketError:
                continue
            expected = finished_verify_data(
                KeySchedule(psk=psk).binder_key(),
                _sha256(binder_transcript(raw, binder_count=len(binders))),
            )
            if binders[index] != expected:
                raise TlsAlert(DECRYPT_ERROR, "PSK binder does not verify (§4.2.11.2)")
            return index, psk
        return None

    def _on_client_hello(self, hello: ClientHello, raw: bytes) -> None:
        if TLS_AES_128_GCM_SHA256 not in hello.cipher_suites:
            raise TlsAlert(HANDSHAKE_FAILURE, "client did not offer TLS_AES_128_GCM_SHA256")
        versions = _find_extension(hello.extensions, ExtensionType.SUPPORTED_VERSIONS)
        if versions is None or TLS_1_3.to_bytes(2, "big") not in versions:
            raise TlsAlert(PROTOCOL_VERSION, "client did not offer TLS 1.3")
        key_share = _find_extension(hello.extensions, ExtensionType.KEY_SHARE)
        peer_public = _client_key_share(key_share) if key_share is not None else None
        if peer_public is None:
            # No usable share. If the client would nevertheless accept a
            # group we support, ask for it rather than giving up (§4.1.4).
            # This is the common case against clients that offer a
            # post-quantum group and keep their ClientHello small by
            # sending fewer shares than groups.
            groups_data = _find_extension(hello.extensions, ExtensionType.SUPPORTED_GROUPS)
            offered = _parse_supported_groups(groups_data) if groups_data is not None else []
            common = next((group for group in SUPPORTED_GROUPS if group in offered), None)
            if common is None:
                raise TlsAlert(HANDSHAKE_FAILURE, "no key exchange group in common")
            self._send_hello_retry_request(hello, raw, common)
            return
        client_transport_parameters = _find_extension(
            hello.extensions, ExtensionType.QUIC_TRANSPORT_PARAMETERS
        )
        if client_transport_parameters is None:
            raise TlsAlert(MISSING_EXTENSION, "no quic_transport_parameters (RFC 9001 §8.2)")
        alpn = self._negotiate_alpn(hello)
        self._client_random = hello.random

        selected = self._select_psk(hello, raw)
        self.resumed = selected is not None
        if selected is not None:
            # §7.1: resuming extracts the PSK into the Early Secret, so
            # the schedule is rebuilt before it sees this ClientHello.
            self.schedule = KeySchedule(psk=selected[1])
        self.schedule.update_transcript(raw)
        server_hello = ServerHello(
            random=self._random,
            legacy_session_id_echo=hello.legacy_session_id,
            cipher_suite=TLS_AES_128_GCM_SHA256,
            extensions=[
                Extension(ExtensionType.SUPPORTED_VERSIONS, TLS_1_3.to_bytes(2, "big")),
                Extension(
                    ExtensionType.KEY_SHARE,
                    _key_share_entry(X25519_GROUP, self._key.public_key().public_bytes_raw()),
                ),
                # §4.2.11: which offered identity was selected.
                *(
                    [Extension(ExtensionType.PRE_SHARED_KEY, selected[0].to_bytes(2, "big"))]
                    if selected is not None
                    else []
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
        self.schedule.update_transcript(encrypted_extensions)
        if selected is None:
            certificate = encode_certificate(
                Certificate(
                    request_context=b"",
                    entries=[
                        CertificateEntry(data=data, extensions=[])
                        for data in self._config.certificate_chain
                    ],
                )
            )
            self.schedule.update_transcript(certificate)
            algorithm, signature = _sign_certificate_verify(
                self._config.signing_key, self.schedule.transcript_hash()
            )
            certificate_verify = encode_certificate_verify(
                CertificateVerify(algorithm=algorithm, signature=signature)
            )
            self.schedule.update_transcript(certificate_verify)
            flight = encrypted_extensions + certificate + certificate_verify
        else:
            # §2.2: a PSK authenticates the connection, so Certificate
            # and CertificateVerify are not sent.
            flight = encrypted_extensions
        verify = finished_verify_data(self.server_hs_secret, self.schedule.transcript_hash())
        finished = encode_finished(Finished(verify_data=verify))
        self.schedule.update_transcript(finished)
        self.events.append(SendData(EncryptionLevel.HANDSHAKE, flight + finished))
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
        self._issue_session_ticket()

    def _issue_session_ticket(self) -> None:
        """§4.6.1: offer the client a ticket it can resume with.

        Sent after the client's Finished because the resumption master
        secret is derived over a transcript that ends there. The ticket
        goes out at the application level, which RFC 9001 §4.5 requires
        of any post-handshake message.
        """
        if self._config.ticket_key is None:
            return
        nonce = os.urandom(TICKET_NONCE_LENGTH)
        psk = resumption_psk(self.schedule.resumption_master_secret(), nonce)
        ticket = NewSessionTicket(
            lifetime=SESSION_TICKET_LIFETIME,
            age_add=int.from_bytes(os.urandom(4), "big"),
            nonce=nonce,
            ticket=seal_ticket(self._config.ticket_key, psk, self._now),
            extensions=[],
        )
        self.events.append(SendData(EncryptionLevel.ONE_RTT, encode_new_session_ticket(ticket)))
