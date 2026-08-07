"""Tests for dsquic.retry."""

import pytest

from dsquic import protection, retry
from dsquic.packet import HeaderParseError
from dsquic.retry import TokenError

KEY = bytes(range(32))
ADDRESS = b"192.0.2.1:443"


class TestRetry:
    """RFC 9001 §5.8 and RFC 9000 §17.2.5."""

    # RFC 9001 A.4: a Retry answering the Initial of A.2. The original
    # destination connection ID is covered by the tag and absent from
    # the wire.
    PACKET = bytes.fromhex(
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
    )
    ORIGINAL_DESTINATION_CID = bytes.fromhex("8394c8f03e515708")

    def test_integrity_tag_matches_the_spec_vector(self) -> None:
        tag = protection.retry_integrity_tag(
            self.ORIGINAL_DESTINATION_CID, self.PACKET[: -protection.AEAD_TAG_LENGTH]
        )
        assert tag == self.PACKET[-protection.AEAD_TAG_LENGTH :]

    def test_parses_the_spec_vector(self) -> None:
        packet = retry.parse_retry(self.PACKET, self.ORIGINAL_DESTINATION_CID)
        assert packet.destination_cid == b""
        assert packet.source_cid == bytes.fromhex("f067a5502a4262b5")
        assert packet.token == b"token"

    def test_builds_the_spec_vector(self) -> None:
        """Byte for byte apart from the first, whose low four bits are
        the Unused field of §17.2.5: the server sets them to an arbitrary
        value and a client ignores them. The vector has them set; this
        implementation leaves them clear, so the tag differs too, since
        the first byte is covered by it."""
        built = retry.build_retry(
            destination_cid=b"",
            source_cid=bytes.fromhex("f067a5502a4262b5"),
            token=b"token",
            original_destination_cid=self.ORIGINAL_DESTINATION_CID,
        )
        assert built[0] & 0xF0 == self.PACKET[0] & 0xF0
        assert built[1:-16] == self.PACKET[1:-16]
        assert retry.parse_retry(built, self.ORIGINAL_DESTINATION_CID).token == b"token"

    def test_a_wrong_original_cid_fails_the_tag(self) -> None:
        """§17.2.5.2: a client MUST discard a Retry whose tag does not
        verify, which is what an off-path injection looks like."""
        with pytest.raises(HeaderParseError, match="integrity tag"):
            retry.parse_retry(self.PACKET, b"\x00" * 8)

    def test_a_corrupted_token_fails_the_tag(self) -> None:
        corrupted = bytearray(self.PACKET)
        corrupted[16] ^= 0x01
        with pytest.raises(HeaderParseError, match="integrity tag"):
            retry.parse_retry(bytes(corrupted), self.ORIGINAL_DESTINATION_CID)


class TestTokens:
    """RFC 9000 §8.1.4."""

    def test_round_trip_returns_the_original_cid(self) -> None:
        token = retry.mint_token(
            KEY, original_destination_cid=b"\x01\x02\x03\x04", client_address=ADDRESS, now=100.0
        )
        recovered = retry.validate_token(
            KEY, token, client_address=ADDRESS, now=110.0, lifetime=60.0
        )
        assert recovered == b"\x01\x02\x03\x04"

    def test_another_address_is_rejected(self) -> None:
        """A token proves the address it was issued to, and no other."""
        token = retry.mint_token(
            KEY, original_destination_cid=b"\x01", client_address=ADDRESS, now=100.0
        )
        with pytest.raises(TokenError, match="another address"):
            retry.validate_token(
                KEY, token, client_address=b"198.51.100.9:443", now=100.0, lifetime=60.0
            )

    def test_an_expired_token_is_rejected(self) -> None:
        token = retry.mint_token(
            KEY, original_destination_cid=b"\x01", client_address=ADDRESS, now=100.0
        )
        with pytest.raises(TokenError, match="expired"):
            retry.validate_token(KEY, token, client_address=ADDRESS, now=200.0, lifetime=60.0)

    def test_a_forged_token_is_rejected(self) -> None:
        token = bytearray(
            retry.mint_token(
                KEY, original_destination_cid=b"\x01", client_address=ADDRESS, now=100.0
            )
        )
        token[-1] ^= 0x01
        with pytest.raises(TokenError, match="authenticate"):
            retry.validate_token(
                KEY, bytes(token), client_address=ADDRESS, now=100.0, lifetime=60.0
            )

    def test_a_token_of_another_kind_is_rejected(self) -> None:
        """§8.1.4: a NEW_TOKEN token does not prove this attempt's address,
        so the two kinds must not be confused."""
        with pytest.raises(TokenError, match="not a Retry token"):
            retry.validate_token(
                KEY, b"\x02rubbish", client_address=ADDRESS, now=100.0, lifetime=60.0
            )
