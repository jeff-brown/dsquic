"""Variable-length integer encoding and byte buffers.

RFC 9000 §16 and Appendix A.1.

The two most significant bits of a varint's first byte encode its total
length (1, 2, 4, or 8 bytes); the remaining bits encode the value. This
module owns varint encoding and the read/write buffer types used by every
parser in the package.
"""
