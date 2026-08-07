"""Tests for dsquic.tls: RFC 8448 trace vectors and the in-memory handshake."""

import datetime
import hashlib
from dataclasses import dataclass, replace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import rfc8448_vectors as rfc8448
from dsquic.protection import derive_packet_keys
from dsquic.tls import (
    BAD_CERTIFICATE,
    DECRYPT_ERROR,
    ECDSA_SECP256R1_SHA256,
    HANDSHAKE_FAILURE,
    HELLO_RETRY_REQUEST_RANDOM,
    ILLEGAL_PARAMETER,
    MESSAGE_HASH_TYPE,
    MISSING_EXTENSION,
    NO_APPLICATION_PROTOCOL,
    PSK_DHE_KE,
    RSA_PSS_RSAE_SHA256,
    TLS_1_3,
    TLS_AES_128_GCM_SHA256,
    UNEXPECTED_MESSAGE,
    X25519_GROUP,
    Certificate,
    CertificateVerify,
    ClientConfig,
    ClientHello,
    ClientState,
    Direction,
    EncryptedExtensions,
    EncryptionLevel,
    Extension,
    ExtensionType,
    Finished,
    HandshakeComplete,
    HandshakeMessage,
    HandshakeParseError,
    KeySchedule,
    NewSessionTicket,
    PskIdentity,
    SecretAvailable,
    SendData,
    ServerConfig,
    ServerHello,
    ServerState,
    SessionTicket,
    TicketError,
    TlsAlert,
    TlsClient,
    TlsEvent,
    TlsServer,
    binder_transcript,
    encode_certificate,
    encode_certificate_verify,
    encode_client_hello,
    encode_encrypted_extensions,
    encode_finished,
    encode_new_session_ticket,
    encode_offered_psks,
    encode_server_hello,
    finished_verify_data,
    hkdf_expand_label,
    hkdf_label,
    open_ticket,
    parse_handshake_message,
    parse_offered_psks,
    resumption_psk,
    seal_ticket,
)

# --- RFC 8448 §3 vectors ------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "length", "expected"),
    [
        (b"client in", 32, "00200f746c73313320636c69656e7420696e00"),
        (b"server in", 32, "00200f746c7331332073657276657220696e00"),
        (b"quic key", 16, "00100e746c7331332071756963206b657900"),
        (b"quic iv", 12, "000c0d746c733133207175696320697600"),
        (b"quic hp", 16, "00100d746c733133207175696320687000"),
    ],
)
def test_hkdf_label_rfc9001_a1(label: bytes, length: int, expected: str) -> None:
    assert hkdf_label(label, b"", length) == bytes.fromhex(expected)


def test_x25519_shared_secret_matches_trace() -> None:
    client_key = X25519PrivateKey.from_private_bytes(rfc8448.CLIENT_X25519_PRIVATE)
    server_public = X25519PublicKey.from_public_bytes(rfc8448.SERVER_X25519_PUBLIC)
    assert client_key.public_key().public_bytes_raw() == rfc8448.CLIENT_X25519_PUBLIC
    assert client_key.exchange(server_public) == rfc8448.ECDHE_SHARED_SECRET
    server_key = X25519PrivateKey.from_private_bytes(rfc8448.SERVER_X25519_PRIVATE)
    client_public = X25519PublicKey.from_public_bytes(rfc8448.CLIENT_X25519_PUBLIC)
    assert server_key.exchange(client_public) == rfc8448.ECDHE_SHARED_SECRET


def test_client_hello_parse_and_roundtrip() -> None:
    message, consumed = parse_handshake_message(rfc8448.CLIENT_HELLO)
    assert consumed == len(rfc8448.CLIENT_HELLO)
    assert isinstance(message, ClientHello)
    assert message.legacy_session_id == b""
    assert message.cipher_suites == [0x1301, 0x1303, 0x1302]
    extension_types = [ext.type for ext in message.extensions]
    assert ExtensionType.SERVER_NAME in extension_types
    assert ExtensionType.KEY_SHARE in extension_types
    key_share = next(e for e in message.extensions if e.type == ExtensionType.KEY_SHARE)
    assert rfc8448.CLIENT_X25519_PUBLIC in key_share.data
    server_name = next(e for e in message.extensions if e.type == ExtensionType.SERVER_NAME)
    assert b"server" in server_name.data
    assert encode_client_hello(message) == rfc8448.CLIENT_HELLO


def test_server_hello_parse_and_roundtrip() -> None:
    message, consumed = parse_handshake_message(rfc8448.SERVER_HELLO)
    assert consumed == len(rfc8448.SERVER_HELLO)
    assert isinstance(message, ServerHello)
    assert message.cipher_suite == TLS_AES_128_GCM_SHA256
    key_share = next(e for e in message.extensions if e.type == ExtensionType.KEY_SHARE)
    assert rfc8448.SERVER_X25519_PUBLIC in key_share.data
    assert encode_server_hello(message) == rfc8448.SERVER_HELLO


def test_encrypted_extensions_roundtrip() -> None:
    message, _ = parse_handshake_message(rfc8448.ENCRYPTED_EXTENSIONS)
    assert isinstance(message, EncryptedExtensions)
    assert encode_encrypted_extensions(message) == rfc8448.ENCRYPTED_EXTENSIONS


def test_certificate_parse_and_roundtrip() -> None:
    message, _ = parse_handshake_message(rfc8448.CERTIFICATE)
    assert isinstance(message, Certificate)
    assert message.request_context == b""
    assert len(message.entries) == 1
    assert len(message.entries[0].data) == 432
    assert message.entries[0].extensions == []
    assert encode_certificate(message) == rfc8448.CERTIFICATE


def test_certificate_verify_parse_and_roundtrip() -> None:
    message, _ = parse_handshake_message(rfc8448.CERTIFICATE_VERIFY)
    assert isinstance(message, CertificateVerify)
    assert message.algorithm == RSA_PSS_RSAE_SHA256
    assert message.algorithm != ECDSA_SECP256R1_SHA256
    assert encode_certificate_verify(message) == rfc8448.CERTIFICATE_VERIFY


def test_finished_parse_and_roundtrip() -> None:
    message, _ = parse_handshake_message(rfc8448.SERVER_FINISHED)
    assert isinstance(message, Finished)
    assert message.verify_data == rfc8448.SERVER_FINISHED_VERIFY
    assert encode_finished(message) == rfc8448.SERVER_FINISHED


def test_key_schedule_walks_the_rfc8448_trace() -> None:
    schedule = KeySchedule()
    schedule.update_transcript(rfc8448.CLIENT_HELLO)
    schedule.update_transcript(rfc8448.SERVER_HELLO)
    schedule.add_ecdhe(rfc8448.ECDHE_SHARED_SECRET)
    client_hs = schedule.client_handshake_traffic_secret()
    server_hs = schedule.server_handshake_traffic_secret()
    assert client_hs == rfc8448.CLIENT_HS_TRAFFIC_SECRET
    assert server_hs == rfc8448.SERVER_HS_TRAFFIC_SECRET

    schedule.update_transcript(rfc8448.ENCRYPTED_EXTENSIONS)
    schedule.update_transcript(rfc8448.CERTIFICATE)
    schedule.update_transcript(rfc8448.CERTIFICATE_VERIFY)
    assert finished_verify_data(server_hs, schedule.transcript_hash()) == (
        rfc8448.SERVER_FINISHED_VERIFY
    )

    schedule.update_transcript(rfc8448.SERVER_FINISHED)
    schedule.advance_to_master()
    assert schedule.client_application_traffic_secret() == rfc8448.CLIENT_AP_TRAFFIC_SECRET
    assert schedule.server_application_traffic_secret() == rfc8448.SERVER_AP_TRAFFIC_SECRET
    assert finished_verify_data(client_hs, schedule.transcript_hash()) == (
        rfc8448.CLIENT_FINISHED_VERIFY
    )


def test_parse_rejects_trailing_bytes() -> None:
    body_length = len(rfc8448.SERVER_HELLO) - 4 + 1
    grown = (
        rfc8448.SERVER_HELLO[:1]
        + body_length.to_bytes(3, "big")
        + rfc8448.SERVER_HELLO[4:]
        + b"\x00"
    )
    with pytest.raises(HandshakeParseError, match="trailing"):
        parse_handshake_message(grown)


def test_parse_rejects_unknown_message_type() -> None:
    with pytest.raises(HandshakeParseError, match="unknown"):
        parse_handshake_message(b"\x63\x00\x00\x00")


def test_parse_rejects_nonnull_compression() -> None:
    body = bytearray(rfc8448.CLIENT_HELLO)
    assert body[47:49] == b"\x01\x00"  # legacy_compression_methods: one entry, null
    body[48] = 0x01
    with pytest.raises(HandshakeParseError, match="compression"):
        parse_handshake_message(bytes(body))


# --- In-memory handshake (verification ladder rung 2 half-step) ---------------

VERIFICATION_TIME = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


@dataclass(frozen=True)
class Credentials:
    chain: list[bytes]
    key: ec.EllipticCurvePrivateKey
    ca: list[bytes]
    ca_key: ec.EllipticCurvePrivateKey


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca() -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("dsquic test CA"))
        .issuer_name(_name("dsquic test CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER), key


def issue_leaf(
    ca_key: ec.EllipticCurvePrivateKey, hostname: str, extra_names: int = 0
) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Issue a leaf certificate for ``hostname``.

    ``extra_names`` pads the SAN list, which is how a test asks for a
    certificate large enough that the server's handshake flight spans
    several packets and runs into the §8.1 amplification limit.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    names = [x509.DNSName(hostname)]
    names += [x509.DNSName(f"host{index}.{hostname}") for index in range(extra_names)]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(hostname))
        .issuer_name(_name("dsquic test CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER), key


@pytest.fixture(scope="module")
def credentials() -> Credentials:
    ca_der, ca_key = make_ca()
    leaf_der, leaf_key = issue_leaf(ca_key, "localhost")
    return Credentials(chain=[leaf_der], key=leaf_key, ca=[ca_der], ca_key=ca_key)


def make_client(
    credentials: Credentials,
    *,
    alpn: list[str] | None = None,
    server_name: str = "localhost",
    insecure_skip_verify: bool = False,
    keylog: list[str] | None = None,
) -> TlsClient:
    config = ClientConfig(
        server_name=server_name,
        alpn=alpn if alpn is not None else ["hq-interop"],
        transport_parameters=b"client-params",
        ca_certificates=[] if insecure_skip_verify else credentials.ca,
        insecure_skip_verify=insecure_skip_verify,
        verification_time=VERIFICATION_TIME,
    )
    return TlsClient(config, keylog=keylog.append if keylog is not None else None)


def make_server(
    credentials: Credentials,
    alpn: list[str] | None = None,
    keylog: list[str] | None = None,
    ticket_key: bytes | None = None,
    key: X25519PrivateKey | None = None,
) -> TlsServer:
    config = ServerConfig(
        certificate_chain=credentials.chain,
        signing_key=credentials.key,
        alpn=alpn if alpn is not None else ["hq-interop"],
        transport_parameters=b"server-params",
        ticket_key=ticket_key,
    )
    return TlsServer(config, key=key, keylog=keylog.append if keylog is not None else None)


def pump(client: TlsClient, server: TlsServer) -> tuple[list[TlsEvent], list[TlsEvent]]:
    """Shuttle SendData between the machines until both go quiet."""
    client_events: list[TlsEvent] = []
    server_events: list[TlsEvent] = []
    if client.state is ClientState.START:
        client.start(0.0)
    for _ in range(10):
        moved = False
        for event in client.take_events():
            client_events.append(event)
            if isinstance(event, SendData):
                server.receive(event.level, event.data, 0.0)
                moved = True
        for event in server.take_events():
            server_events.append(event)
            if isinstance(event, SendData):
                client.receive(event.level, event.data, 0.0)
                moved = True
        if not moved:
            return client_events, server_events
    raise AssertionError("handshake did not converge")


def secrets_of(events: list[TlsEvent]) -> dict[tuple[EncryptionLevel, Direction], bytes]:
    return {(e.level, e.direction): e.secret for e in events if isinstance(e, SecretAvailable)}


def test_in_memory_handshake_completes(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client_events, server_events = pump(client, server)
    assert client.state is ClientState.CONNECTED
    assert server.state is ServerState.CONNECTED

    client_secrets = secrets_of(client_events)
    server_secrets = secrets_of(server_events)
    assert client_secrets == server_secrets
    assert set(client_secrets) == {
        (EncryptionLevel.HANDSHAKE, Direction.CLIENT),
        (EncryptionLevel.HANDSHAKE, Direction.SERVER),
        (EncryptionLevel.ONE_RTT, Direction.CLIENT),
        (EncryptionLevel.ONE_RTT, Direction.SERVER),
    }
    assert len(set(client_secrets.values())) == 4

    client_done = next(e for e in client_events if isinstance(e, HandshakeComplete))
    server_done = next(e for e in server_events if isinstance(e, HandshakeComplete))
    assert client_done.alpn == "hq-interop"
    assert server_done.alpn == "hq-interop"
    assert client_done.peer_transport_parameters == b"server-params"
    assert server_done.peer_transport_parameters == b"client-params"


def test_handshake_secrets_feed_packet_protection(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client_events, _ = pump(client, server)
    secrets = secrets_of(client_events)
    keys = derive_packet_keys(secrets[(EncryptionLevel.ONE_RTT, Direction.CLIENT)])
    assert len(keys.key) == 16
    assert len(keys.iv) == 12
    assert len(keys.hp) == 16


def test_handshake_bytes_survive_fragmentation(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client.start(0.0)
    for event in client.take_events():
        if isinstance(event, SendData):
            for i in range(len(event.data)):  # one byte at a time
                server.receive(event.level, event.data[i : i + 1], 0.0)
    assert server.state is ServerState.WAIT_FINISHED


def test_keylog_lines(credentials: Credentials) -> None:
    client_lines: list[str] = []
    server_lines: list[str] = []
    client = make_client(credentials, keylog=client_lines)
    server = make_server(credentials, keylog=server_lines)
    pump(client, server)
    labels = [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    ]
    assert [line.split()[0] for line in client_lines] == labels
    assert sorted(client_lines) == sorted(server_lines)
    for line in client_lines:
        _, client_random, secret = line.split()
        assert len(client_random) == 64
        assert len(secret) == 64
        bytes.fromhex(client_random)
        bytes.fromhex(secret)


def test_wrong_hostname_rejected(credentials: Credentials) -> None:
    leaf_der, leaf_key = issue_leaf(credentials.ca_key, "other.example")
    bad = Credentials(chain=[leaf_der], key=leaf_key, ca=credentials.ca, ca_key=credentials.ca_key)
    client = make_client(bad, server_name="localhost")
    server = make_server(bad)
    with pytest.raises(TlsAlert) as excinfo:
        pump(client, server)
    assert excinfo.value.alert == BAD_CERTIFICATE


def test_untrusted_ca_rejected(credentials: Credentials) -> None:
    other_ca_der, _ = make_ca()
    distrusting = Credentials(
        chain=credentials.chain, key=credentials.key, ca=[other_ca_der], ca_key=credentials.ca_key
    )
    client = make_client(distrusting)
    server = make_server(credentials)
    with pytest.raises(TlsAlert) as excinfo:
        pump(client, server)
    assert excinfo.value.alert == BAD_CERTIFICATE


def test_expired_certificate_rejected(credentials: Credentials) -> None:
    config = ClientConfig(
        server_name="localhost",
        alpn=["hq-interop"],
        transport_parameters=b"client-params",
        ca_certificates=credentials.ca,
        verification_time=datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC),
    )
    client = TlsClient(config)
    server = make_server(credentials)
    with pytest.raises(TlsAlert) as excinfo:
        pump(client, server)
    assert excinfo.value.alert == BAD_CERTIFICATE


def test_insecure_skip_verify_accepts_untrusted(credentials: Credentials) -> None:
    other_ca_der, other_ca_key = make_ca()
    leaf_der, leaf_key = issue_leaf(other_ca_key, "localhost")
    untrusted = Credentials(chain=[leaf_der], key=leaf_key, ca=[other_ca_der], ca_key=other_ca_key)
    client = make_client(credentials, insecure_skip_verify=True)
    server = make_server(untrusted)
    pump(client, server)
    assert client.state is ClientState.CONNECTED


def test_client_config_requires_trust_anchors() -> None:
    with pytest.raises(ValueError, match="ca_certificates"):
        ClientConfig(server_name="localhost", alpn=["hq-interop"], transport_parameters=b"")


def test_alpn_mismatch_raises(credentials: Credentials) -> None:
    client = make_client(credentials, alpn=["h3"])
    server = make_server(credentials, alpn=["hq-interop"])
    client.start(0.0)
    send = next(e for e in client.take_events() if isinstance(e, SendData))
    with pytest.raises(TlsAlert) as excinfo:
        server.receive(send.level, send.data, 0.0)
    assert excinfo.value.alert == NO_APPLICATION_PROTOCOL


def test_tampered_server_finished_raises(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client.start(0.0)
    for event in client.take_events():
        if isinstance(event, SendData):
            server.receive(event.level, event.data, 0.0)
    with pytest.raises(TlsAlert) as excinfo:
        for event in server.take_events():
            if isinstance(event, SendData):
                data = bytearray(event.data)
                data[-1] ^= 0x01  # last byte of the server Finished verify_data
                client.receive(event.level, bytes(data), 0.0)
    assert excinfo.value.alert == DECRYPT_ERROR


def test_message_at_wrong_level_raises(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client.start(0.0)
    send = next(e for e in client.take_events() if isinstance(e, SendData))
    with pytest.raises(TlsAlert) as excinfo:
        server.receive(EncryptionLevel.HANDSHAKE, send.data, 0.0)
    assert excinfo.value.alert == UNEXPECTED_MESSAGE


class TestHelloRetryRequest:
    """RFC 8446 §4.1.4 and §4.4.1.

    Reachable in the field because Go, Chrome, and Firefox default to the
    post-quantum group X25519MLKEM768: a client may offer classical
    groups without spending 1.2KB on shares for them.
    """

    def make_withholding_client(self, credentials: Credentials) -> TlsClient:
        config = ClientConfig(
            server_name="localhost",
            alpn=["hq-interop"],
            transport_parameters=b"client-params",
            ca_certificates=credentials.ca,
            verification_time=VERIFICATION_TIME,
            key_share_groups=[],  # offer groups, send no shares
        )
        return TlsClient(config)

    def test_retry_completes_the_handshake(self, credentials: Credentials) -> None:
        client = self.make_withholding_client(credentials)
        server = make_server(credentials)
        client_events, server_events = pump(client, server)
        assert client.state is ClientState.CONNECTED
        assert server.state is ServerState.CONNECTED
        # The secrets still agree, which is the real test of the §4.4.1
        # message_hash transcript substitution.
        assert secrets_of(client_events) == secrets_of(server_events)

    def test_retry_costs_one_extra_flight(self, credentials: Credentials) -> None:
        retried = self.make_withholding_client(credentials)
        retried_events, _ = pump(retried, make_server(credentials))
        direct_events, _ = pump(make_client(credentials), make_server(credentials))
        sent = [e for e in retried_events if isinstance(e, SendData)]
        direct = [e for e in direct_events if isinstance(e, SendData)]
        assert len(sent) == len(direct) + 1

    def test_server_sends_a_real_hello_retry_request(self, credentials: Credentials) -> None:
        client = self.make_withholding_client(credentials)
        server = make_server(credentials)
        client.start(0.0)
        for event in client.take_events():
            if isinstance(event, SendData):
                server.receive(event.level, event.data, 0.0)
        first = next(e for e in server.take_events() if isinstance(e, SendData))
        message, _ = parse_handshake_message(first.data)
        assert isinstance(message, ServerHello)
        assert message.random == HELLO_RETRY_REQUEST_RANDOM
        key_share = next(e for e in message.extensions if e.type == ExtensionType.KEY_SHARE)
        assert key_share.data == X25519_GROUP.to_bytes(2, "big")  # group only, no key
        assert server.state is ServerState.WAIT_SECOND_CLIENT_HELLO

    def test_no_common_group_is_a_handshake_failure(self, credentials: Credentials) -> None:
        """A client offering only groups we cannot do gets no retry: a
        HelloRetryRequest would not help."""
        server = make_server(credentials)
        hello = ClientHello(
            random=bytes(32),
            legacy_session_id=b"",
            cipher_suites=[TLS_AES_128_GCM_SHA256],
            extensions=[
                Extension(ExtensionType.SUPPORTED_VERSIONS, b"\x02\x03\x04"),
                Extension(ExtensionType.SUPPORTED_GROUPS, b"\x00\x02\x11\xec"),  # MLKEM768 only
                Extension(ExtensionType.KEY_SHARE, b"\x00\x00"),
                Extension(ExtensionType.ALPN, b"\x00\x0b\nhq-interop"),
                Extension(ExtensionType.QUIC_TRANSPORT_PARAMETERS, b"x"),
            ],
        )
        with pytest.raises(TlsAlert) as excinfo:
            server.receive(EncryptionLevel.INITIAL, encode_client_hello(hello), 0.0)
        assert excinfo.value.alert == HANDSHAKE_FAILURE

    def test_second_retry_is_refused(self, credentials: Credentials) -> None:
        """A client that retries still without a usable share is not sent
        a second HelloRetryRequest (§4.1.4 forbids the loop)."""
        client = self.make_withholding_client(credentials)
        server = make_server(credentials)
        client.start(0.0)
        first = next(e for e in client.take_events() if isinstance(e, SendData))
        server.receive(first.level, first.data, 0.0)
        server.take_events()
        with pytest.raises(TlsAlert) as excinfo:
            server.receive(first.level, first.data, 0.0)  # the same share-less hello again
        assert excinfo.value.alert == HANDSHAKE_FAILURE

    def test_client_refuses_a_pointless_retry(self, credentials: Credentials) -> None:
        """A retry asking for a group the client already shared would loop."""
        client = make_client(credentials)  # sends an x25519 share
        client.start(0.0)
        client.take_events()
        retry = encode_server_hello(
            ServerHello(
                random=HELLO_RETRY_REQUEST_RANDOM,
                legacy_session_id_echo=b"",
                cipher_suite=TLS_AES_128_GCM_SHA256,
                extensions=[
                    Extension(ExtensionType.SUPPORTED_VERSIONS, TLS_1_3.to_bytes(2, "big")),
                    Extension(ExtensionType.KEY_SHARE, X25519_GROUP.to_bytes(2, "big")),
                ],
            )
        )
        with pytest.raises(TlsAlert) as excinfo:
            client.receive(EncryptionLevel.INITIAL, retry, 0.0)
        assert excinfo.value.alert == ILLEGAL_PARAMETER

    def test_client_refuses_an_unoffered_group(self, credentials: Credentials) -> None:
        client = self.make_withholding_client(credentials)
        client.start(0.0)
        client.take_events()
        retry = encode_server_hello(
            ServerHello(
                random=HELLO_RETRY_REQUEST_RANDOM,
                legacy_session_id_echo=b"",
                cipher_suite=TLS_AES_128_GCM_SHA256,
                extensions=[
                    Extension(ExtensionType.SUPPORTED_VERSIONS, TLS_1_3.to_bytes(2, "big")),
                    Extension(ExtensionType.KEY_SHARE, b"\x11\xec"),  # MLKEM768, never offered
                ],
            )
        )
        with pytest.raises(TlsAlert) as excinfo:
            client.receive(EncryptionLevel.INITIAL, retry, 0.0)
        assert excinfo.value.alert == ILLEGAL_PARAMETER


def test_unexpected_message_order_raises(credentials: Credentials) -> None:
    client = make_client(credentials)
    client.start(0.0)
    client.take_events()
    finished = encode_finished(Finished(verify_data=bytes(32)))
    with pytest.raises(TlsAlert) as excinfo:
        client.receive(EncryptionLevel.INITIAL, finished, 0.0)
    assert excinfo.value.alert == UNEXPECTED_MESSAGE


class TestResumptionKeySchedule:
    """RFC 8448 §4 against the RFC 8446 §7.1 key schedule."""

    def test_psk_comes_from_the_resumption_secret_and_nonce(self) -> None:
        """§4.6.1: one PSK per ticket, keyed by the ticket's nonce."""
        assert (
            resumption_psk(rfc8448.RESUMPTION_MASTER_SECRET, rfc8448.TICKET_NONCE)
            == rfc8448.RESUMPTION_PSK
        )

    def test_early_secret_extracts_the_psk(self) -> None:
        """The binder key hangs off the Early Secret, so this pins the
        extract step as well as the derivation."""
        schedule = KeySchedule(psk=rfc8448.RESUMPTION_PSK)
        finished_key = hkdf_expand_label(schedule.binder_key(), b"finished", b"", 32)
        assert finished_key == rfc8448.BINDER_FINISHED_KEY

    def test_binder_is_a_finished_over_the_truncated_client_hello(self) -> None:
        """§4.2.11.2: the binder proves the client holds the PSK, and
        covers the ClientHello up to the identities, since the binder
        cannot cover itself."""
        schedule = KeySchedule(psk=rfc8448.RESUMPTION_PSK)
        binder = finished_verify_data(schedule.binder_key(), rfc8448.BINDER_TRANSCRIPT_HASH)
        assert binder == rfc8448.BINDER

    def test_each_ticket_nonce_gives_a_different_psk(self) -> None:
        """§4.6.1: the nonce is why several tickets issued on one
        connection cannot be correlated by the PSK they stand for."""
        first = resumption_psk(rfc8448.RESUMPTION_MASTER_SECRET, b"\x00\x00")
        second = resumption_psk(rfc8448.RESUMPTION_MASTER_SECRET, b"\x00\x01")
        assert first == rfc8448.RESUMPTION_PSK
        assert second != first

    def test_client_early_traffic_secret_matches_the_zero_rtt_trace(self) -> None:
        """§7.1: derived at the Early Secret over the complete
        ClientHello, binders included, unlike the binder itself, which
        stops where the binders start. RFC 9001 §5.1 protects 0-RTT
        packets with this secret."""
        hello = rfc8448.CLIENT_HELLO_BINDER_PREFIX + b"\x00\x21" + b"\x20" + rfc8448.BINDER
        schedule = KeySchedule(psk=rfc8448.RESUMPTION_PSK)
        schedule.update_transcript(hello)
        assert schedule.client_early_traffic_secret() == rfc8448.CLIENT_EARLY_TRAFFIC_SECRET


def test_new_session_ticket_round_trips_the_spec_vector() -> None:
    """RFC 8446 §4.6.1, against the 205-octet ticket of RFC 8448 §3.

    The nonce is what the resumption PSK is derived from, so parsing it
    correctly is what makes the ticket usable at all.
    """
    message, consumed = parse_handshake_message(rfc8448.NEW_SESSION_TICKET)
    assert consumed == len(rfc8448.NEW_SESSION_TICKET)
    assert isinstance(message, NewSessionTicket)
    assert message.nonce == rfc8448.TICKET_NONCE
    assert message.lifetime == 0x1E
    assert encode_new_session_ticket(message) == rfc8448.NEW_SESSION_TICKET
    # §4.2.10: the ticket says how much early data it permits.
    assert [ext.type for ext in message.extensions] == [ExtensionType.EARLY_DATA]


class TestPskBinder:
    """RFC 8446 §4.2.11 against RFC 8448 §4."""

    def test_binder_covers_the_hello_up_to_the_binders(self) -> None:
        """The binder cannot cover itself, so the transcript stops where
        the binders start. The header's length field still counts them,
        which is why this truncates rather than re-encodes."""
        binders = b"\x00\x21" + b"\x20" + rfc8448.BINDER
        complete = rfc8448.CLIENT_HELLO_BINDER_PREFIX + binders
        assert binder_transcript(complete) == rfc8448.CLIENT_HELLO_BINDER_PREFIX
        # The prefix keeps the length of the whole message, not its own.
        assert int.from_bytes(complete[1:4], "big") + 4 == len(complete)

    def test_binder_over_that_prefix_matches_the_vector(self) -> None:
        schedule = KeySchedule(psk=rfc8448.RESUMPTION_PSK)
        transcript = hashlib.sha256(rfc8448.CLIENT_HELLO_BINDER_PREFIX).digest()
        assert finished_verify_data(schedule.binder_key(), transcript) == rfc8448.BINDER

    def test_offered_psks_round_trip(self) -> None:
        identities = [PskIdentity(identity=b"ticket-bytes", obfuscated_ticket_age=0x01020304)]
        binders = [rfc8448.BINDER]
        encoded = encode_offered_psks(identities, binders)
        assert parse_offered_psks(encoded) == (identities, binders)

    def test_a_missing_binder_is_rejected(self) -> None:
        """§4.2.11: exactly one binder per identity."""
        identities = [
            PskIdentity(identity=b"one", obfuscated_ticket_age=0),
            PskIdentity(identity=b"two", obfuscated_ticket_age=0),
        ]
        with pytest.raises(TlsAlert):
            parse_offered_psks(encode_offered_psks(identities, [rfc8448.BINDER]))


class TestSessionTickets:
    """RFC 8446 §4.6.1: a server keeps no state for a ticket it issues."""

    KEY = bytes(range(32))
    PSK = bytes(range(32, 64))

    def test_a_ticket_returns_the_psk_it_sealed(self) -> None:
        ticket = seal_ticket(self.KEY, self.PSK, now=1000.0)
        assert open_ticket(self.KEY, ticket, now=1100.0, lifetime=3600.0) == self.PSK

    def test_an_expired_ticket_is_refused(self) -> None:
        ticket = seal_ticket(self.KEY, self.PSK, now=1000.0)
        with pytest.raises(TicketError, match="expired"):
            open_ticket(self.KEY, ticket, now=9000.0, lifetime=3600.0)

    def test_another_server_cannot_read_it(self) -> None:
        """Only the issuer holds the key, which is what lets the ticket
        carry the PSK instead of an index into server state."""
        ticket = seal_ticket(self.KEY, self.PSK, now=1000.0)
        with pytest.raises(TicketError, match="authenticate"):
            open_ticket(bytes(32), ticket, now=1000.0, lifetime=3600.0)

    def test_a_tampered_ticket_is_refused(self) -> None:
        ticket = bytearray(seal_ticket(self.KEY, self.PSK, now=1000.0))
        ticket[-1] ^= 0x01
        with pytest.raises(TicketError, match="authenticate"):
            open_ticket(self.KEY, bytes(ticket), now=1000.0, lifetime=3600.0)

    def test_two_tickets_for_one_psk_differ(self) -> None:
        """A fresh nonce per ticket, so two offers cannot be linked."""
        first = seal_ticket(self.KEY, self.PSK, now=1000.0)
        second = seal_ticket(self.KEY, self.PSK, now=1000.0)
        assert first != second


def test_a_ticket_travels_from_server_to_client(credentials: Credentials) -> None:
    """RFC 8446 §4.6.1 end to end over a handshake: the server issues a
    ticket once the client's Finished lands, and both sides arrive at the
    same PSK, the server from the secret it sealed and the client from
    the nonce it was sent.
    """
    key = bytes(range(32))
    client = make_client(credentials)
    server = make_server(credentials, ticket_key=key)
    pump(client, server)
    assert client.session_tickets, "the client kept no ticket"
    ticket = client.session_tickets[0]
    assert open_ticket(key, ticket.identity, now=0.0, lifetime=7200.0) == ticket.psk


def test_no_ticket_without_a_ticket_key(credentials: Credentials) -> None:
    """A server that cannot seal a ticket does not offer one."""
    client = make_client(credentials)
    pump(client, make_server(credentials))
    assert client.session_tickets == []


def test_a_client_advertises_psk_modes_without_an_offer(credentials: Credentials) -> None:
    """RFC 8446 §4.2.9: the extension also governs the tickets a server
    may issue, so it goes out on every hello; spec-following servers
    issue no NewSessionTicket to a client that advertised no modes."""
    client = make_client(credentials)
    client.start(0.0)
    hello = next(e for e in client.take_events() if isinstance(e, SendData)).data
    message, _ = parse_handshake_message(hello)
    assert isinstance(message, ClientHello)
    types = [e.type for e in message.extensions]
    assert ExtensionType.PSK_KEY_EXCHANGE_MODES in types
    assert ExtensionType.PRE_SHARED_KEY not in types
    modes = next(
        e.data for e in message.extensions if e.type == ExtensionType.PSK_KEY_EXCHANGE_MODES
    )
    assert modes == bytes([1, PSK_DHE_KE])


def test_a_client_offers_a_ticket_with_a_verifiable_binder(credentials: Credentials) -> None:
    """RFC 8446 §4.2.11: the offer carries a binder proving the client
    holds the PSK, computed over the ClientHello up to the binder.

    Checked the way a server checks it: re-derive from the ticket's PSK
    over the truncated message and compare.
    """
    key = bytes(range(32))
    first = make_client(credentials)
    pump(first, make_server(credentials, ticket_key=key))
    ticket = first.session_tickets[0]

    resuming = TlsClient(
        ClientConfig(
            server_name="localhost",
            alpn=["hq-interop"],
            transport_parameters=b"client-params",
            ca_certificates=credentials.ca,
            verification_time=VERIFICATION_TIME,
            session_ticket=ticket,
        )
    )
    resuming.start(0.0)
    sent = [e for e in resuming.take_events() if isinstance(e, SendData)]
    hello = sent[0].data

    message, _ = parse_handshake_message(hello)
    assert isinstance(message, ClientHello)
    # §4.2.11: pre_shared_key is the last extension, since the binder
    # covers everything before it.
    assert message.extensions[-1].type == ExtensionType.PRE_SHARED_KEY
    identities, binders = parse_offered_psks(message.extensions[-1].data)
    assert identities[0].identity == ticket.identity

    expected = finished_verify_data(
        KeySchedule(psk=ticket.psk).binder_key(),
        hashlib.sha256(binder_transcript(hello)).digest(),
    )
    assert binders == [expected]


# --- RFC 8446 §4.2.11: server-side PSK selection ------------------------------


def make_resuming_client(
    credentials: Credentials,
    ticket: SessionTicket,
    key: X25519PrivateKey | None = None,
) -> TlsClient:
    config = ClientConfig(
        server_name="localhost",
        alpn=["hq-interop"],
        transport_parameters=b"client-params",
        ca_certificates=credentials.ca,
        verification_time=VERIFICATION_TIME,
        session_ticket=ticket,
    )
    return TlsClient(config, key=key)


def obtain_ticket(credentials: Credentials, ticket_key: bytes) -> SessionTicket:
    """Run a full handshake and return the ticket it produced."""
    client = make_client(credentials)
    pump(client, make_server(credentials, ticket_key=ticket_key))
    return client.session_tickets[0]


def resuming_hello(credentials: Credentials, ticket: SessionTicket) -> bytes:
    client = make_resuming_client(credentials, ticket)
    client.start(0.0)
    return next(e for e in client.take_events() if isinstance(e, SendData)).data


def parse_flight(data: bytes) -> list[HandshakeMessage]:
    messages: list[HandshakeMessage] = []
    while data:
        message, consumed = parse_handshake_message(data)
        messages.append(message)
        data = data[consumed:]
    return messages


class TestServerPskSelection:
    """RFC 8446 §4.2.11: the server side of a resumption offer."""

    KEY = bytes(range(32))

    def test_a_selected_psk_skips_the_certificate(self, credentials: Credentials) -> None:
        """§2.2: the PSK authenticates the connection, so the server
        answers with selected_identity and sends no Certificate."""
        ticket = obtain_ticket(credentials, self.KEY)
        server = make_server(credentials, ticket_key=self.KEY)
        server.receive(EncryptionLevel.INITIAL, resuming_hello(credentials, ticket), 0.0)
        sends = [e for e in server.take_events() if isinstance(e, SendData)]
        server_hello = parse_flight(sends[0].data)[0]
        assert isinstance(server_hello, ServerHello)
        selected = next(
            e.data for e in server_hello.extensions if e.type == ExtensionType.PRE_SHARED_KEY
        )
        assert int.from_bytes(selected, "big") == 0
        assert [type(m) for m in parse_flight(sends[1].data)] == [EncryptedExtensions, Finished]
        assert server.state is ServerState.WAIT_FINISHED

    def test_the_psk_enters_the_early_secret(self, credentials: Credentials) -> None:
        """§7.1: the server's handshake secrets extract the ticket's PSK,
        checked against a schedule walked independently from the ticket."""
        ticket = obtain_ticket(credentials, self.KEY)
        client_key = X25519PrivateKey.generate()
        server_key = X25519PrivateKey.generate()
        client = make_resuming_client(credentials, ticket, key=client_key)
        server = make_server(credentials, ticket_key=self.KEY, key=server_key)
        client.start(0.0)
        hello = next(e for e in client.take_events() if isinstance(e, SendData)).data
        server.receive(EncryptionLevel.INITIAL, hello, 0.0)
        events = server.take_events()
        sends = [e for e in events if isinstance(e, SendData)]

        schedule = KeySchedule(psk=ticket.psk)
        schedule.update_transcript(hello)
        schedule.update_transcript(sends[0].data)
        schedule.add_ecdhe(server_key.exchange(client_key.public_key()))
        secrets = secrets_of(events)
        assert (
            secrets[(EncryptionLevel.HANDSHAKE, Direction.CLIENT)]
            == schedule.client_handshake_traffic_secret()
        )

    def test_an_unopenable_ticket_falls_back_to_a_full_handshake(
        self, credentials: Credentials
    ) -> None:
        """§4.2.11: declining is always allowed. A ticket sealed under
        another key draws an ordinary certificate handshake."""
        ticket = obtain_ticket(credentials, self.KEY)
        server = make_server(credentials, ticket_key=bytes(range(32, 64)))
        server.receive(EncryptionLevel.INITIAL, resuming_hello(credentials, ticket), 0.0)
        sends = [e for e in server.take_events() if isinstance(e, SendData)]
        server_hello = parse_flight(sends[0].data)[0]
        assert isinstance(server_hello, ServerHello)
        assert all(e.type != ExtensionType.PRE_SHARED_KEY for e in server_hello.extensions)
        assert [type(m) for m in parse_flight(sends[1].data)] == [
            EncryptedExtensions,
            Certificate,
            CertificateVerify,
            Finished,
        ]

    def test_a_bad_binder_aborts(self, credentials: Credentials) -> None:
        """§4.2.11.2: a binder that does not verify is fatal rather than
        a fallback, since it means the client does not hold the PSK."""
        ticket = obtain_ticket(credentials, self.KEY)
        forged = replace(ticket, psk=bytes(32))
        server = make_server(credentials, ticket_key=self.KEY)
        with pytest.raises(TlsAlert, match="binder") as excinfo:
            server.receive(EncryptionLevel.INITIAL, resuming_hello(credentials, forged), 0.0)
        assert excinfo.value.alert == DECRYPT_ERROR

    def test_psk_without_modes_aborts(self, credentials: Credentials) -> None:
        """§4.2.9: offering pre_shared_key without psk_key_exchange_modes
        is a protocol violation, not a fallback."""
        ticket = obtain_ticket(credentials, self.KEY)
        message, _ = parse_handshake_message(resuming_hello(credentials, ticket))
        assert isinstance(message, ClientHello)
        stripped = replace(
            message,
            extensions=[
                e for e in message.extensions if e.type != ExtensionType.PSK_KEY_EXCHANGE_MODES
            ],
        )
        server = make_server(credentials, ticket_key=self.KEY)
        with pytest.raises(TlsAlert, match="psk_key_exchange_modes") as excinfo:
            server.receive(EncryptionLevel.INITIAL, encode_client_hello(stripped), 0.0)
        assert excinfo.value.alert == MISSING_EXTENSION

    def test_pre_shared_key_must_be_last(self, credentials: Credentials) -> None:
        """§4.2.11: the binder covers everything before the extension, so
        an offer that is not the last extension is rejected."""
        ticket = obtain_ticket(credentials, self.KEY)
        message, _ = parse_handshake_message(resuming_hello(credentials, ticket))
        assert isinstance(message, ClientHello)
        reordered = replace(message, extensions=[message.extensions[-1], *message.extensions[:-1]])
        server = make_server(credentials, ticket_key=self.KEY)
        with pytest.raises(TlsAlert, match="last") as excinfo:
            server.receive(EncryptionLevel.INITIAL, encode_client_hello(reordered), 0.0)
        assert excinfo.value.alert == ILLEGAL_PARAMETER


# --- RFC 8446 §4.2.11: the client side of a resumption offer ------------------


def test_resumption_completes_without_a_certificate(credentials: Credentials) -> None:
    """The resumed handshake end to end: both sides reach CONNECTED on
    the same secrets, no Certificate crosses the wire (§2.2), and the
    resumed connection is itself issued a ticket (§4.6.1)."""
    key = bytes(range(32))
    ticket = obtain_ticket(credentials, key)
    client = make_resuming_client(credentials, ticket)
    server = make_server(credentials, ticket_key=key)
    client_events, server_events = pump(client, server)
    assert client.state is ClientState.CONNECTED
    assert server.state is ServerState.CONNECTED
    assert secrets_of(client_events) == secrets_of(server_events)
    sent = [type(m) for e in server_events if isinstance(e, SendData) for m in parse_flight(e.data)]
    assert Certificate not in sent
    assert NewSessionTicket in sent
    chained = client.session_tickets[0]
    assert open_ticket(key, chained.identity, now=0.0, lifetime=7200.0) == chained.psk
    done = next(e for e in client_events if isinstance(e, HandshakeComplete))
    assert done.alpn == "hq-interop"
    assert done.peer_transport_parameters == b"server-params"


def test_a_declined_offer_falls_back_to_a_full_handshake(credentials: Credentials) -> None:
    """§4.2.11: a server that cannot use the ticket answers without
    selected_identity, and the client reverts to the zero-PSK Early
    Secret (§7.1) and the certificate path."""
    ticket = obtain_ticket(credentials, bytes(range(32)))
    server = make_server(credentials)  # no ticket key, so every offer is declined
    client = make_resuming_client(credentials, ticket)
    client_events, server_events = pump(client, server)
    assert client.state is ClientState.CONNECTED
    assert server.state is ServerState.CONNECTED
    assert secrets_of(client_events) == secrets_of(server_events)
    sent = [type(m) for e in server_events if isinstance(e, SendData) for m in parse_flight(e.data)]
    assert Certificate in sent


def test_a_retried_hello_recomputes_its_binder(credentials: Credentials) -> None:
    """§4.1.4 and §4.2.11.2: the second ClientHello's binder covers the
    first hello's message_hash, the HelloRetryRequest, and the second
    hello truncated at its binders. The server declines a PSK offered
    after its own retry, so the handshake completes with a certificate.
    """
    key = bytes(range(32))
    ticket = obtain_ticket(credentials, key)
    client = TlsClient(
        ClientConfig(
            server_name="localhost",
            alpn=["hq-interop"],
            transport_parameters=b"client-params",
            ca_certificates=credentials.ca,
            verification_time=VERIFICATION_TIME,
            session_ticket=ticket,
            key_share_groups=[],
        )
    )
    server = make_server(credentials, ticket_key=key)
    client.start(0.0)
    hello1 = next(e for e in client.take_events() if isinstance(e, SendData)).data
    server.receive(EncryptionLevel.INITIAL, hello1, 0.0)
    retry = next(e for e in server.take_events() if isinstance(e, SendData)).data
    client.receive(EncryptionLevel.INITIAL, retry, 0.0)
    hello2 = next(e for e in client.take_events() if isinstance(e, SendData)).data

    message, _ = parse_handshake_message(hello2)
    assert isinstance(message, ClientHello)
    _, binders = parse_offered_psks(message.extensions[-1].data)
    message_hash = (
        bytes([MESSAGE_HASH_TYPE]) + (32).to_bytes(3, "big") + hashlib.sha256(hello1).digest()
    )
    transcript = hashlib.sha256(message_hash + retry + binder_transcript(hello2)).digest()
    expected = finished_verify_data(KeySchedule(psk=ticket.psk).binder_key(), transcript)
    assert binders == [expected]

    server.receive(EncryptionLevel.INITIAL, hello2, 0.0)
    pump(client, server)
    assert client.state is ClientState.CONNECTED
    assert server.state is ServerState.CONNECTED


def test_an_unsolicited_selected_identity_aborts(credentials: Credentials) -> None:
    """§4.2.11: a server may only answer an offer that was made."""
    client = make_client(credentials)
    server = make_server(credentials)
    client.start(0.0)
    hello = next(e for e in client.take_events() if isinstance(e, SendData)).data
    server.receive(EncryptionLevel.INITIAL, hello, 0.0)
    server_hello = next(e for e in server.take_events() if isinstance(e, SendData)).data
    message, _ = parse_handshake_message(server_hello)
    assert isinstance(message, ServerHello)
    forged = replace(
        message,
        extensions=[*message.extensions, Extension(ExtensionType.PRE_SHARED_KEY, b"\x00\x00")],
    )
    with pytest.raises(TlsAlert, match="never made") as excinfo:
        client.receive(EncryptionLevel.INITIAL, encode_server_hello(forged), 0.0)
    assert excinfo.value.alert == ILLEGAL_PARAMETER


def test_a_selected_identity_out_of_range_aborts(credentials: Credentials) -> None:
    """§4.2.11: selected_identity indexes the offered list, which held
    exactly one identity."""
    key = bytes(range(32))
    ticket = obtain_ticket(credentials, key)
    client = make_resuming_client(credentials, ticket)
    server = make_server(credentials, ticket_key=key)
    client.start(0.0)
    hello = next(e for e in client.take_events() if isinstance(e, SendData)).data
    server.receive(EncryptionLevel.INITIAL, hello, 0.0)
    server_hello = next(e for e in server.take_events() if isinstance(e, SendData)).data
    message, _ = parse_handshake_message(server_hello)
    assert isinstance(message, ServerHello)
    forged = replace(
        message,
        extensions=[
            e
            if e.type != ExtensionType.PRE_SHARED_KEY
            else Extension(ExtensionType.PRE_SHARED_KEY, (1).to_bytes(2, "big"))
            for e in message.extensions
        ],
    )
    with pytest.raises(TlsAlert, match="out of range") as excinfo:
        client.receive(EncryptionLevel.INITIAL, encode_server_hello(forged), 0.0)
    assert excinfo.value.alert == ILLEGAL_PARAMETER
