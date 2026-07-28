"""Tests for dsquic.hq."""

import pytest

from dsquic.hq import HqError, encode_request, parse_request


def test_encode_request() -> None:
    assert encode_request("/index.html") == b"GET /index.html\r\n"


def test_encode_requires_leading_slash() -> None:
    with pytest.raises(ValueError, match="start with"):
        encode_request("index.html")


def test_roundtrip() -> None:
    assert parse_request(encode_request("/file.bin")) == "/file.bin"


@pytest.mark.parametrize("terminator", [b"\r\n", b"\n", b""])
def test_terminator_tolerance(terminator: bytes) -> None:
    # Implementations disagree on the line ending; all three occur in the wild.
    assert parse_request(b"GET /f" + terminator) == "/f"


@pytest.mark.parametrize(
    "request_line",
    [
        b"POST /f\r\n",
        b"get /f\r\n",
        b"GET \r\n",
        b"GET f\r\n",
        b"GET /a/../etc/passwd\r\n",
        b"GET /f\r\nGET /g\r\n",
        b"\xff\xfe",
    ],
)
def test_bad_requests_rejected(request_line: bytes) -> None:
    with pytest.raises(HqError):
        parse_request(request_line)
