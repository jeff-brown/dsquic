"""Tests for dsquic.tls against the RFC 8448 simple 1-RTT handshake trace."""

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

import rfc8448_vectors as rfc8448
from dsquic.tls import (
    ECDSA_SECP256R1_SHA256,
    RSA_PSS_RSAE_SHA256,
    TLS_AES_128_GCM_SHA256,
    Certificate,
    CertificateVerify,
    ClientHello,
    EncryptedExtensions,
    ExtensionType,
    Finished,
    HandshakeParseError,
    KeySchedule,
    ServerHello,
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
