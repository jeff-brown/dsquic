# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-07-26)

MVP implementation in progress, on phase gates per design.md §6.3.
Phases 1 and 2 are committed, pushed, and gate-verified. Phase 2
(packet.py: header parse/build, packet number encode/decode, RFC 8999
version layering with UnsupportedVersion; protection.py: Initial
secrets, packet keys, AEAD, header protection) passed byte-exact
against RFC 9001 Appendix A.1-A.3 and RFC 9000 Appendix A.2-A.3, and
the user independently verified the emitted client Initial in
Wireshark via text2pcap (keys derived, HP removed, PN 2 recovered,
ClientHello with SNI example.com dissected). Throwaway gate artifacts
client_initial.{bin,hex,pcap} may remain untracked in the repo root;
safe to delete.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy over
  src and tests, pytest. All checks pass: `uv run pytest -q`,
  `uv run ruff check`, `uv run ruff format --check .`, `uv run mypy`.
- Layout: flat sans-IO modules under `src/dsquic/` (buffer, packet, frames,
  streams, connection, tls, protection, recovery, congestion, new_reno, h3,
  qpack, masque, hq, qlog), each a docstring stub with RFC mapping, plus
  the `endpoints/` subpackage (client, server), the package's only I/O
  boundary. `tests/` mirrors the modules including the subpackage;
  `tests/test_scaffold.py` enforces the mirror.
- Docs: `README.md` (public overview), `docs/design.md` (rationale and open
  questions), `CLAUDE.md` (working rules), `interop/README.md` (Interop
  Runner shim placeholder).
- Working tree is clean; everything is committed and pushed (agent stages
  only, never commits or pushes, per CLAUDE.md).

## In-flight work

None.

## Next steps

The MVP sequence (design.md §6.3), each step verified per the ladder in
design.md §6.2:

1. Done: `buffer.py` varints (RFC 9000 §16, Appendix A vectors).
2. Done: `packet.py` headers plus `protection.py` packet protection,
   byte-exact against RFC 9001 Appendix A. Retry and Version
   Negotiation parsing intentionally raise HeaderParseError; non-v1
   versions raise UnsupportedVersion before type bits are interpreted.
3. In progress, split into checkpoints 3a/3b/3c.
   3a done, staged: handshake message codecs (RFC 8446 §4) and the
   KeySchedule (§7.1) in tls.py, verified against the RFC 8448 §3
   trace (vectors machine-extracted into tests/rfc8448_vectors.py;
   messages roundtrip byte-exact, key schedule and both Finished
   MACs match). HKDF primitives moved from protection.py to tls.py
   (context parameter added); buffer.py gained pull_uint24.
   3b done, staged: TlsClient/TlsServer state machines (states and
   expectation tables per RFC 8446 Appendix A), full six-message flow
   with real CertificateVerify signing and leaf-signature verification,
   per-level CRYPTO reassembly, ALPN and transport-parameter
   negotiation, alerts as TlsAlert. Events per the seam: SendData,
   SecretAvailable(level, direction, secret), HandshakeComplete. The
   in-memory dsquic-to-dsquic handshake completes with matching
   secrets on both sides (ladder rung 2 half-step).
   Done and committed (message codecs, key schedule, state machines,
   certificate policy, keylog).
4. In progress, split into checkpoints 4a-4e:
   4a done, staged: frames.py, the full RFC 9000 §19 vocabulary plus
   RFC 9221 DATAGRAM. One frozen dataclass per frame with encode();
   parse_frames() drives a frame-type dispatch table. PADDING
   coalesces; ACK ranges as inclusive (low, high) pairs highest-first
   with the §19.3.1 gap arithmetic; shortest-form frame types
   enforced; unknown types raise FrameParseError. buffer.py gained
   peek_uint8.
   4b done, staged: recovery.py (RttEstimator per §5.3; LossDetection
   with per-space sent tracking, ACK processing returning
   AckOutcome(acked, lost), packet/time-threshold loss, PTO with
   backoff and the §6.2.2.1 client anti-deadlock, space discard,
   persistent congestion span test); congestion.py now a
   runtime-checkable Protocol (adds bytes_in_flight and
   on_packets_discarded); new_reno.py implements §7/Appendix B (slow
   start, avoidance, one-reduction-per-recovery, minimum window).
   Spaces keyed by tls.EncryptionLevel; time is caller-supplied float
   seconds. SentPacket carries frames for connection re-bundling.
   4c done, staged: streams.py (SendStream/RecvStream carrying the
   §3.1/§3.2 state machines; RangeSet for reassembly and ack
   tracking; StreamManager with §2.1 ID sequencing, §4.6 stream-count
   limits, §4.1 connection-level flow control both directions, §4.2
   half-window credit updates; §18.2 limit naming preserved). hq.py
   (encode_request/parse_request; FIN-terminated, terminator-tolerant,
   traversal-rejecting). frames.py gained the §20.1 transport error
   code constants. RESET_STREAM/STOP_SENDING handling deferred, noted
   in the SendStream docstring.
   4d: connection.py composition; in-memory dsquic-to-dsquic
   connection test.
   4e: endpoints (sync UDP loop, SSLKEYLOGFILE, file serve/download);
   loopback transfer over real UDP; user Wireshark gate.
4. `connection.py`, `recovery.py`, `streams.py`, `hq.py`: loopback file
   transfer over real UDP via the endpoints.
5. Interop gate (MVP done): `handshake` and `transfer` against quic-go,
   both directions.

## Standing constraints for upcoming phases

MASQUE nesting readiness (design.md appendix): connection.py must be
transport-agnostic, no hardcoded MTU constants, endpoint loop handles N
connections, h3.py models long-lived CONNECT streams. Check before
declaring phase 4 or the h3 milestone done.

## Open decisions

See design.md §7. Settled this session: module layout (flat), tooling,
Python 3.12+, the edge-case convention (state inline, validation
quarantined, design.md §4.8), pluggable congestion control (interface in
congestion.py, NewReno baseline in new_reno.py, loss detection fixed),
hq-interop in core as hq.py, the endpoints/ subpackage as the structural
I/O boundary, and strict-by-default client certificate validation (path
plus hostname verification via cryptography, explicit insecure flag for
debugging only); recorded in the design.md appendix. Also settled: the
verification ladder (unit tests, loopback, interop both directions;
design.md §6.2) and the MVP sequence (design.md §6.3). MVP scoping is
complete; implementation starts with buffer.py.
