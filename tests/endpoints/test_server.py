"""Tests for dsquic.endpoints.server."""

from pathlib import Path

import pytest
from conftest import PemCredentials

from dsquic.endpoints.server import load_credentials, resolve


def test_load_credentials(credentials: PemCredentials) -> None:
    chain, key = load_credentials(credentials.certificate_pem, credentials.private_key_pem)
    assert len(chain) == 1
    assert chain[0][:1] == b"\x30"  # DER SEQUENCE
    assert key.key_size >= 256


def test_resolve_serves_files(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_bytes(b"<html>root</html>")
    assert resolve(tmp_path, "/index.html") == b"<html>root</html>"


def test_resolve_missing_file(tmp_path: Path) -> None:
    assert resolve(tmp_path, "/absent.bin") is None


def test_resolve_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "www"
    root.mkdir()
    (tmp_path / "secret.txt").write_bytes(b"private")
    # Even if a path slips past hq.parse_request, the document root is
    # the security boundary.
    assert resolve(root, "/../secret.txt") is None


def test_resolve_rejects_directory(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    assert resolve(tmp_path, "/subdir") is None


def test_load_credentials_rejects_bad_key(tmp_path: Path, credentials: PemCredentials) -> None:
    bogus = tmp_path / "bogus.pem"
    bogus.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
    with pytest.raises(ValueError):
        load_credentials(credentials.certificate_pem, bogus)
