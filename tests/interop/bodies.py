"""The file bodies the interop document root serves.

A plain module rather than fixtures, so both the tests and the shared
conftest can name the same bytes.
"""

INDEX_BODY = b"<html><body>hello from dsquic</body></html>"
LARGE_BODY = bytes(range(256)) * 300  # 76800 bytes: many packets and ACKs
