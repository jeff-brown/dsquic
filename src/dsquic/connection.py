"""Connection state machine.

RFC 9000 §5 (connections), §7 (handshake), §8 (address validation),
§9 (migration), §10 (termination), §7.4 and §18 (transport parameters).

A Connection consumes received datagrams and clock readings and produces
datagrams to send, timer deadlines, and application events. The caller
owns sockets and the clock. Packet numbers, ACK state, and CRYPTO
reassembly are tracked separately for each packet number space (Initial,
Handshake, Application).
"""
