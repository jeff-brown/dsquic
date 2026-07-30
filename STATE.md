# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-07-29)

**The MVP is complete.** dsquic completes QUIC handshakes and transfers
files over hq-interop against independent implementations, in both
directions, over real UDP. This is design.md §6.3 step 5, the recorded
definition of MVP done.

Verified against quic-go v0.61 and aioquic 1.3 by nine hand-written tests
in `tests/interop/`: each peer as both client and server, a small file and
a 77KB file, plus a HelloRetryRequest round trip driven by a real quic-go
client. This is our own harness against two implementations, not the
Interop Runner: **the runner has never been run against dsquic, so there
are no interop results to report.**

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy,
  strict pyright (the Pylance engine; `pyrightconfig.json`), pytest.
  292 tests pass. Gates: `uv run pytest -q`, `uv run ruff check`,
  `uv run ruff format --check .`, `uv run mypy`, `uv run pyright`.
- Implemented in `src/dsquic/`: buffer, packet, frames, streams,
  connection, transport_parameters, tls, protection, recovery,
  congestion, new_reno, hq, and the `endpoints/` subpackage (the only
  I/O). Still docstring stubs: h3, qpack, masque, qlog.
- `endpoints.server.Server` serves many connections over one socket,
  routing by Destination Connection ID via
  `packet.destination_connection_id` (RFC 8999 §5.1, version
  independent). The table holds two keys per connection: the client's
  original CID and the one we issue, since the client switches to ours
  (§7.2). `serve_one` is now `Server.serve(connection_limit=1)`.
- Interop harnesses live in `tests/interop/`: aioquic (a dev dependency)
  and quic-go (Go sources in `tests/interop/quicgo/`, built on demand
  into a temp dir, tests skipped when Go is absent; Go was installed via
  Homebrew). Only the harness wiring is ours.
- `interop/` holds the Interop Runner shim: a Dockerfile and
  `run_endpoint.sh` implementing the runner's endpoint contract. Verified
  by hand with Apple's `container` (installed via Homebrew; needs
  `container system start`, which downloads a Linux kernel once):
  unsupported test cases exit 127, a containerised server serves /www to
  a host client, and a containerised client parses REQUESTS URLs,
  validates against /certs/ca.pem, and writes to /downloads. Claims
  handshake and transfer only; interop/README.md tabulates why each of
  the runner's other 21 cases is not attempted. The runner itself has
  never been run against dsquic. Container DNS is set up properly (see
  the README): `sudo container system dns create test` plus
  `[dns] domain = "test"` in ~/.config/container/config.toml, since
  `--dns-domain` alone does not register names and 1.2.0 has no
  `dns default set` subcommand. Gaps: IPv4 only, no qlog, and the full
  runner matrix needs Linux.

## In-flight work

Staged, awaiting commit: the interop suite and the HelloRetryRequest
implementation.

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
- HelloRetryRequest was refused outright, so a peer that offered x25519
  without sending a share for it (the shape post-quantum defaults
  produce) could not connect. Now implemented on both sides, verified by
  a real quic-go client forced to prefer P-256.

## Next steps

1. **The roadmap past the MVP** (design.md §6.1), in order: retry,
   resumption, multiplexing, http3, keyupdate, ecn, zerortt. Each climbs
   all three rungs of the ladder (design.md §6.2).
2. **`qlog.py`**, which the design doc treats as first-class output and
   the foundation of the inspection-engine story. Also closes the
   `QLOGDIR` gap in the interop shim.
3. **MAX_STREAMS.** dsquic advertises 16 bidirectional streams and never
   raises the limit, so the seventeenth stream fails. This blocks the
   runner's `multiplexing` case and is a real gap for any peer that opens
   many streams.
4. **IPv6 in the endpoints.** Both open `AF_INET` sockets, so the runner's
   `ipv6` case cannot pass.
5. **Actually run the Interop Runner.** Blocked on three things, none of
   them protocol work: the image must derive from the quic-network-simulator
   endpoint base image so traffic routes through the simulator; the online
   runner wants linux/amd64; and the orchestration needs a Linux host or CI
   with Docker and docker-compose. The runner covers 17 registered
   implementations against 23 cases, which would be 31 pairings for dsquic
   (16 as client, 15 as server). Until that runs, the only interop evidence
   is the nine tests against two peers.

## Wire comparison, five pairings (2026-07-29)

Captured on loopback and decrypted via SSLKEYLOGFILE, with zero
decryption failures in any trace: dsquic to aioquic, aioquic to dsquic,
dsquic to quic-go, quic-go to dsquic, dsquic to dsquic. All five complete
in 8 or 9 datagrams and 4.2 to 6.1 KB with the same phase structure.
Observed divergences worth keeping:

- ClientHello sizes: dsquic 210B (1 CRYPTO frame), aioquic 474B (1),
  quic-go 1506B (4 frames over 2 datagrams) because of the PQ key_share.
- Padding: dsquic and quic-go use PADDING frames inside a packet; aioquic
  appends bytes after the packet, which Wireshark reports as "(Random)
  padding data appended to the datagram". Both are legal; the frame form
  is unambiguous, which is why we switched to it.
- Datagram size: quic-go sends 1280-byte payloads, dsquic and aioquic
  1200.
- Frames peers send that we do not: NEW_CONNECTION_ID (aioquic,
  quic-go), NEW_TOKEN and MAX_STREAMS (quic-go). All parsed and ignored,
  which is why interop works and why building the full §19 vocabulary in
  4a paid off.

## Standing constraints

- MASQUE nesting readiness (design.md appendix): connection.py stays
  transport-agnostic (satisfied), no hardcoded MTU constants
  (satisfied), the endpoint loop handles N connections (satisfied by
  endpoints.server.Server), and h3.py must model long-lived CONNECT
  streams with DATAGRAM frames (**not yet**, h3.py is a stub). Only the
  h3 constraint remains open.

## Open decisions

See design.md §7. Still open: 0-RTT scope, whether to add an asyncio
transport over the sans-IO core, PyPI publication, and the v1 MASQUE
surface (CONNECT-UDP only vs. CONNECT-IP alongside). Everything settled
so far is recorded in the design.md appendix.
