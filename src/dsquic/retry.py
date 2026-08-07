"""Retry packets and address validation tokens.

RFC 9000 §8.1.2 (address validation using Retry packets), §8.1.3
(validation for future connections), §8.1.4 (token integrity), and
§17.2.5 (the Retry packet). The Retry Integrity Tag itself is RFC 9001
§5.8 and lives in protection.py with the rest of the AEAD.

A server that wants to validate a client address answers the first
Initial with a Retry carrying an opaque token, and the client repeats its
Initial with the token attached. The token's contents are the server's
own business: §8.1.4 requires only that it be integrity protected and
that a server can tell a Retry token from a NEW_TOKEN one, since the two
are validated differently.

The client address is passed in as bytes the caller chooses. The core
never interprets an address, so how a socket address becomes bytes is the
endpoint's decision (design.md §4.6).
"""

import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dsquic.buffer import Buffer, encode_varint
from dsquic.packet import (
    FIXED_BIT,
    HEADER_FORM_LONG,
    MAX_CID_LENGTH,
    QUIC_V1,
    HeaderParseError,
    PacketType,
    Retry,
    UnsupportedVersion,
)
from dsquic.protection import AEAD_TAG_LENGTH, retry_integrity_tag

TOKEN_KEY_LENGTH = 32  # AES-256-GCM, the server's own key
NONCE_LENGTH = 12
VERSION_END = 5  # first byte plus the 32-bit version (§17.2)
# §8.1.4: a server must distinguish a token it sent in a Retry from one
# sent in NEW_TOKEN, because only the first proves the address of *this*
# connection attempt. The kind is authenticated, not merely prefixed.
RETRY_TOKEN = b"\x01"
NEW_TOKEN = b"\x02"


@dataclass(frozen=True)
class RetryContext:
    """What a server that answered with a Retry needs to remember.

    It kept no connection state (§8.1.2), so both come back from
    elsewhere: the original destination connection ID out of the token,
    and the source connection ID the server itself chose for the Retry.
    §7.3 has the server echo both as transport parameters.
    """

    original_destination_cid: bytes
    source_cid: bytes


class TokenError(Exception):
    """A token that does not validate (§8.1.4)."""


def is_retry(data: bytes) -> bool:
    """Whether a datagram begins with a version 1 Retry packet (§17.2.5).

    Checked before ordinary header parsing, because a Retry carries no
    Length or Packet Number field and so cannot be read as one.
    """
    if len(data) < VERSION_END or not data[0] & HEADER_FORM_LONG:
        return False
    if int.from_bytes(data[1:VERSION_END], "big") != QUIC_V1:
        return False
    return PacketType((data[0] & 0x30) >> 4) is PacketType.RETRY


def parse_retry(data: bytes, original_destination_cid: bytes) -> Retry:
    """Parse and authenticate a Retry packet (RFC 9000 §17.2.5).

    §17.2.5.2: a client MUST discard a Retry whose Retry Integrity Tag
    does not verify. That is what stops an off-path attacker injecting
    one: only an endpoint that saw the Initial knows the original
    destination connection ID the tag covers.
    """
    if len(data) < AEAD_TAG_LENGTH:
        raise HeaderParseError("Retry packet shorter than its integrity tag")
    buf = Buffer(data)
    first = buf.pull_uint8()
    if not first & HEADER_FORM_LONG:
        raise HeaderParseError("Retry packet without a long header")
    version = buf.pull_uint32()
    if version != QUIC_V1:
        raise UnsupportedVersion(version)
    if PacketType((first & 0x30) >> 4) is not PacketType.RETRY:
        raise HeaderParseError("not a Retry packet")
    destination_cid = buf.pull_bytes(buf.pull_uint8())
    source_cid = buf.pull_bytes(buf.pull_uint8())
    if len(destination_cid) > MAX_CID_LENGTH or len(source_cid) > MAX_CID_LENGTH:
        raise HeaderParseError("connection ID longer than 20 bytes")
    expected = retry_integrity_tag(original_destination_cid, data[:-AEAD_TAG_LENGTH])
    if not hmac.compare_digest(data[-AEAD_TAG_LENGTH:], expected):
        raise HeaderParseError("Retry integrity tag does not verify")
    return Retry(
        version=version,
        destination_cid=destination_cid,
        source_cid=source_cid,
        token=data[buf.position : -AEAD_TAG_LENGTH],
    )


def build_retry(
    *,
    destination_cid: bytes,
    source_cid: bytes,
    token: bytes,
    original_destination_cid: bytes,
) -> bytes:
    """Build a Retry packet with its integrity tag (RFC 9000 §17.2.5)."""
    header = bytearray([HEADER_FORM_LONG | FIXED_BIT | (PacketType.RETRY.value << 4)])
    header += QUIC_V1.to_bytes(4, "big")
    header += bytes([len(destination_cid)]) + destination_cid
    header += bytes([len(source_cid)]) + source_cid
    header += token
    return bytes(header) + retry_integrity_tag(original_destination_cid, bytes(header))


def mint_token(
    key: bytes,
    *,
    original_destination_cid: bytes,
    client_address: bytes,
    now: float,
) -> bytes:
    """A Retry token binding the client address and the original CID.

    §8.1.4: the token is integrity protected, so a client cannot forge
    one. The original destination connection ID is carried because §7.3
    makes the server echo it in a transport parameter, and after a Retry
    the server holds no state that remembers it.
    """
    nonce = os.urandom(NONCE_LENGTH)
    payload = (
        encode_varint(len(original_destination_cid))
        + original_destination_cid
        + encode_varint(len(client_address))
        + client_address
        + int(now).to_bytes(8, "big")
    )
    return RETRY_TOKEN + nonce + AESGCM(key).encrypt(nonce, payload, RETRY_TOKEN)


def validate_token(
    key: bytes,
    token: bytes,
    *,
    client_address: bytes,
    now: float,
    lifetime: float,
) -> bytes:
    """Check a Retry token and return the original destination CID.

    Raises TokenError unless the token authenticates, was issued to this
    address, and is younger than ``lifetime``. §8.1.4: an expired or
    misaddressed token proves nothing about the client in front of us.
    """
    if not token.startswith(RETRY_TOKEN):
        raise TokenError("not a Retry token")
    nonce = token[len(RETRY_TOKEN) : len(RETRY_TOKEN) + NONCE_LENGTH]
    sealed = token[len(RETRY_TOKEN) + NONCE_LENGTH :]
    try:
        payload = AESGCM(key).decrypt(nonce, sealed, RETRY_TOKEN)
    except InvalidTag as exc:
        raise TokenError("token does not authenticate") from exc
    buf = Buffer(payload)
    original_destination_cid = buf.pull_bytes(buf.pull_varint())
    address = buf.pull_bytes(buf.pull_varint())
    issued = int.from_bytes(buf.pull_bytes(8), "big")
    if not hmac.compare_digest(address, client_address):
        raise TokenError("token was issued to another address")
    if now - issued > lifetime:
        raise TokenError("token has expired")
    return original_destination_cid


def mint_new_token(key: bytes, *, client_address: bytes, now: float) -> bytes:
    """A token for a NEW_TOKEN frame, binding only the client address.

    §8.1.3: it will be presented on a connection the server has not
    seen yet, so unlike a Retry token it carries no connection ID and
    is validated against nothing but the address and its age.
    """
    nonce = os.urandom(NONCE_LENGTH)
    payload = encode_varint(len(client_address)) + client_address + int(now).to_bytes(8, "big")
    return NEW_TOKEN + nonce + AESGCM(key).encrypt(nonce, payload, NEW_TOKEN)


def validate_new_token(
    key: bytes,
    token: bytes,
    *,
    client_address: bytes,
    now: float,
    lifetime: float,
) -> None:
    """Check a NEW_TOKEN token, or raise TokenError (§8.1.3).

    Success means the address in front of us held this address when the
    token was minted, which lifts the §8.1 amplification limit without
    a Retry round trip.
    """
    if not token.startswith(NEW_TOKEN):
        raise TokenError("not a NEW_TOKEN token")
    nonce = token[len(NEW_TOKEN) : len(NEW_TOKEN) + NONCE_LENGTH]
    sealed = token[len(NEW_TOKEN) + NONCE_LENGTH :]
    try:
        payload = AESGCM(key).decrypt(nonce, sealed, NEW_TOKEN)
    except InvalidTag as exc:
        raise TokenError("token does not authenticate") from exc
    buf = Buffer(payload)
    address = buf.pull_bytes(buf.pull_varint())
    issued = int.from_bytes(buf.pull_bytes(8), "big")
    if not hmac.compare_digest(address, client_address):
        raise TokenError("token was issued to another address")
    if now - issued > lifetime:
        raise TokenError("token has expired")
