"""Shared fixtures for the endpoint tests: a PEM credential pair on disk."""

import datetime
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@dataclass(frozen=True)
class PemCredentials:
    ca_pem: Path
    certificate_pem: Path
    private_key_pem: Path


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


@pytest.fixture(scope="session")
def credentials(tmp_path_factory: pytest.TempPathFactory) -> PemCredentials:
    """A CA and a localhost leaf, written as PEM for the endpoint CLIs."""
    directory = tmp_path_factory.mktemp("pki")
    not_before = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    not_after = not_before + datetime.timedelta(days=365)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("dsquic test CA"))
        .issuer_name(_name("dsquic test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(_name("dsquic test CA"))
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = directory / "ca.pem"
    certificate_pem = directory / "certificate.pem"
    private_key_pem = directory / "key.pem"
    ca_pem.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_pem.write_bytes(leaf_certificate.public_bytes(serialization.Encoding.PEM))
    private_key_pem.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return PemCredentials(
        ca_pem=ca_pem, certificate_pem=certificate_pem, private_key_pem=private_key_pem
    )
