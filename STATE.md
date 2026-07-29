# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-07-29)

**The MVP is complete.** dsquic completes QUIC handshakes and transfers
files over hq-interop against independent implementations, in both
directions, over real UDP. This is design.md §6.3 step 5, the recorded
definition of MVP done.

Interop verified against quic-go v0.61 and aioquic 1.3, each as both
client and server, for a small file and a 77KB file.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy,
  strict pyright (the Pylance engine; `pyrightconfig.json`), pytest.
  277 tests pass. Gates: `uv run pytest -q`, `uv run ruff check`,
  `uv run ruff format --check .`, `uv run mypy`, `uv run pyright`.
- Implemented in `src/dsquic/`: buffer, packet, frames, streams,
  connection, transport_parameters, tls, protection, recovery,
  congestion, new_reno, hq, and the `endpoints/` subpackage (the only
  I/O). Still docstring stubs: h3, qpack, masque, qlog.
- Interop harnesses live in `tests/interop/`: aioquic (a dev dependency)
  and quic-go (Go sources in `tests/interop/quicgo/`, built on demand
  into a temp dir, tests skipped when Go is absent; Go was installed via
  Homebrew). Only the harness wiring is ours.

## In-flight work

None. Everything is committed and pushed.

## What interop and the wire found that self-testing did not

Four bugs, each invisible while dsquic only talked to itself:

- §14.1 padding was appended after packets rather than carried as
  PADDING frames inside one, which corrupts any following short-header
  packet for a correct receiver.
- CRYPTO frame offsets were ignored, so a ClientHello spanning several
  frames was reassembled by concatenation. quic-go sends one; dsquic and
  aioquic do not.
- `min()` over `(deadline, EncryptionLevel)` tuples crashed on exact
  ties, which a real clock produces and a synthetic one does not.
- The §6.2.2.1 anti-deadlock PTO defaulted to time 0.0 with nothing in
  flight, firing immediately under a monotonic clock and putting a
  spurious PING on the wire.

## Next steps

1. Interop Runner shim in `interop/`: Dockerfile plus `run_endpoint.sh`
   honouring ROLE/TESTCASE/REQUESTS/WWW/DOWNLOADS/QLOGDIR/SSLKEYLOGFILE,
   exiting 127 for unsupported test cases. Wraps the endpoints and adds
   no endpoint logic.
2. The roadmap past the MVP (design.md §6.1), in order: retry,
   resumption, multiplexing, http3, keyupdate, ecn, zerortt. Each climbs
   all three rungs of the ladder (design.md §6.2).
3. `qlog.py`, which the design doc treats as first-class output and the
   foundation of the inspection-engine story.

## Standing constraints

- MASQUE nesting readiness (design.md appendix): connection.py stays
  transport-agnostic (satisfied), no hardcoded MTU constants
  (satisfied), the endpoint loop must handle N connections (**not yet**:
  `serve_one` handles one at a time), and h3.py must model long-lived
  CONNECT streams with DATAGRAM frames (**not yet**, h3.py is a stub).
- The server currently serves one connection at a time; a connection
  table keyed by destination connection ID is the next structural piece,
  and is also what an inner MASQUE connection would route through.

## Open decisions

See design.md §7. Still open: 0-RTT scope, whether to add an asyncio
transport over the sans-IO core, PyPI publication, and the v1 MASQUE
surface (CONNECT-UDP only vs. CONNECT-IP alongside). Everything settled
so far is recorded in the design.md appendix.
