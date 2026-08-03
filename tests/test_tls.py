"""Tests for dsquic.tls: RFC 8448 trace vectors and the in-memory handshake."""

import datetime
from dataclasses import dataclass

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
    NO_APPLICATION_PROTOCOL,
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
    HandshakeParseError,
    KeySchedule,
    SecretAvailable,
    SendData,
    ServerConfig,
    ServerHello,
    ServerState,
    TlsAlert,
    TlsClient,
    TlsEvent,
    TlsServer,
    encode_certificate,
    encode_certificate_verify,
    encode_client_hello,
    encode_encrypted_extensions,
    encode_finished,
    encode_server_hello,
    finished_verify_data,
    hkdf_label,
    parse_handshake_message,
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
) -> TlsServer:
    config = ServerConfig(
        certificate_chain=credentials.chain,
        signing_key=credentials.key,
        alpn=alpn if alpn is not None else ["hq-interop"],
        transport_parameters=b"server-params",
    )
    return TlsServer(config, keylog=keylog.append if keylog is not None else None)


def pump(client: TlsClient, server: TlsServer) -> tuple[list[TlsEvent], list[TlsEvent]]:
    """Shuttle SendData between the machines until both go quiet."""
    client_events: list[TlsEvent] = []
    server_events: list[TlsEvent] = []
    client.start()
    for _ in range(10):
        moved = False
        for event in client.take_events():
            client_events.append(event)
            if isinstance(event, SendData):
                server.receive(event.level, event.data)
                moved = True
        for event in server.take_events():
            server_events.append(event)
            if isinstance(event, SendData):
                client.receive(event.level, event.data)
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
    client.start()
    for event in client.take_events():
        if isinstance(event, SendData):
            for i in range(len(event.data)):  # one byte at a time
                server.receive(event.level, event.data[i : i + 1])
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
    client.start()
    send = next(e for e in client.take_events() if isinstance(e, SendData))
    with pytest.raises(TlsAlert) as excinfo:
        server.receive(send.level, send.data)
    assert excinfo.value.alert == NO_APPLICATION_PROTOCOL


def test_tampered_server_finished_raises(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client.start()
    for event in client.take_events():
        if isinstance(event, SendData):
            server.receive(event.level, event.data)
    with pytest.raises(TlsAlert) as excinfo:
        for event in server.take_events():
            if isinstance(event, SendData):
                data = bytearray(event.data)
                data[-1] ^= 0x01  # last byte of the server Finished verify_data
                client.receive(event.level, bytes(data))
    assert excinfo.value.alert == DECRYPT_ERROR


def test_message_at_wrong_level_raises(credentials: Credentials) -> None:
    client = make_client(credentials)
    server = make_server(credentials)
    client.start()
    send = next(e for e in client.take_events() if isinstance(e, SendData))
    with pytest.raises(TlsAlert) as excinfo:
        server.receive(EncryptionLevel.HANDSHAKE, send.data)
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
        client.start()
        for event in client.take_events():
            if isinstance(event, SendData):
                server.receive(event.level, event.data)
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
            server.receive(EncryptionLevel.INITIAL, encode_client_hello(hello))
        assert excinfo.value.alert == HANDSHAKE_FAILURE

    def test_second_retry_is_refused(self, credentials: Credentials) -> None:
        """A client that retries still without a usable share is not sent
        a second HelloRetryRequest (§4.1.4 forbids the loop)."""
        client = self.make_withholding_client(credentials)
        server = make_server(credentials)
        client.start()
        first = next(e for e in client.take_events() if isinstance(e, SendData))
        server.receive(first.level, first.data)
        server.take_events()
        with pytest.raises(TlsAlert) as excinfo:
            server.receive(first.level, first.data)  # the same share-less hello again
        assert excinfo.value.alert == HANDSHAKE_FAILURE

    def test_client_refuses_a_pointless_retry(self, credentials: Credentials) -> None:
        """A retry asking for a group the client already shared would loop."""
        client = make_client(credentials)  # sends an x25519 share
        client.start()
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
            client.receive(EncryptionLevel.INITIAL, retry)
        assert excinfo.value.alert == ILLEGAL_PARAMETER

    def test_client_refuses_an_unoffered_group(self, credentials: Credentials) -> None:
        client = self.make_withholding_client(credentials)
        client.start()
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
            client.receive(EncryptionLevel.INITIAL, retry)
        assert excinfo.value.alert == ILLEGAL_PARAMETER


def test_unexpected_message_order_raises(credentials: Credentials) -> None:
    client = make_client(credentials)
    client.start()
    client.take_events()
    finished = encode_finished(Finished(verify_data=bytes(32)))
    with pytest.raises(TlsAlert) as excinfo:
        client.receive(EncryptionLevel.INITIAL, finished)
    assert excinfo.value.alert == UNEXPECTED_MESSAGE
