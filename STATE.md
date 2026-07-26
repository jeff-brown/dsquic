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
   3b next: client/server handshake state machines completing an
   in-memory handshake (X25519, TLS_AES_128_GCM_SHA256, transport
   parameters, ALPN); secrets/events surfaced per the module seam.
   3c after: certificates (sign and strict verify per the recorded
   decision), keylog callback (NSS format) for SSLKEYLOGFILE.
4. `connection.py`, `recovery.py`, `streams.py`, `hq.py`: loopback file
   transfer over real UDP via the endpoints.
5. Interop gate (MVP done): `handshake` and `transfer` against quic-go,
   both directions.

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
