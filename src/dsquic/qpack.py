"""QPACK field compression for HTTP/3.

RFC 9204.

Dynamic table updates travel on dedicated unidirectional encoder and
decoder streams, so header blocks on request streams never block on each
other. The initial implementation uses the static table and literal
encodings only.
"""
