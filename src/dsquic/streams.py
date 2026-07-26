"""Stream states, stream types, and flow control accounting.

RFC 9000 §2 (streams), §3 (stream states), §4 (flow control).

Sending and receiving stream state machines are explicit tables using the
state names of §3.1 and §3.2. Flow control is tracked per stream and per
connection in each direction; credit is advertised with MAX_DATA and
MAX_STREAM_DATA, and stream-count credit with MAX_STREAMS.
"""
