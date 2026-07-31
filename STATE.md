# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-07-30)

**The MVP is complete and the QUIC Interop Runner has been run against
it.** dsquic completes QUIC handshakes and transfers files over
hq-interop against independent implementations, in both directions, over
real UDP and through the runner's ns-3 simulator. This is design.md §6.3
step 5, the recorded definition of MVP done.

Runner results, locally hosted (see "Interop Runner results" below):
`handshake` and `transfer` pass in every pairing of dsquic, quic-go and
aioquic, in both roles. Against quic-go, dsquic also passes
`transferloss`, `transfercorruption`, `blackhole`, `longrtt` and
`amplificationlimit`, and `keyupdate` as server.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy,
  strict pyright (the Pylance engine; `pyrightconfig.json`), pytest.
  309 tests pass. Gates: `uv run pytest -q`, `uv run ruff check`,
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
  `run_endpoint.sh` implementing the runner's endpoint contract. The
  image derives from `martenseemann/quic-network-simulator-endpoint`, so
  `/setup.sh` routes traffic through the simulator; the script detects
  the simulator by the topology's 193.167.0.0/16 addressing rather than
  by probing for files, since the same image also runs on an ordinary
  bridge. `run_endpoint.sh` claims the seven cases listed under results
  below; interop/README.md tabulates why each of the runner's other cases
  is not attempted. Gaps: IPv4 only, no qlog, and no client-initiated key
  update.

## Running the Interop Runner locally

The runner drives `docker compose` with a fixed network topology, and it
hardcodes `/tmp` for its working directories.

- **Apple's `container` cannot drive it**, and this was established
  rather than assumed: it has no compose support (interop.py shells out
  to `docker compose` in five places), `--network` has no static-IP
  option while the topology pins 193.167.0.100 and friends, and it
  attaches one network per container where the simulator needs two.
- **colima is what works** (`colima start`). The runner is cloned and
  run *inside* the VM at `~/quic-interop-runner`, reached with
  `colima ssh`, because colima refuses to mount host `/tmp` ("must not
  be a system path") and the runner insists on it. A stale `mounts:`
  entry in `~/.colima/default/colima.yaml` had to be cleared by hand.
- pyshark needs the `tshark` binary present in the VM, otherwise every
  test fails with "Expected exactly one version. Got []". That failure
  reproduces for quic-go too, which is how it was identified as
  environmental rather than ours.
- Build and run:
  `colima ssh -- bash -lc 'docker build -f interop/Dockerfile -t dsquic-interop:latest .'`
  then
  `cd ~/quic-interop-runner && .venv/bin/python run.py -s dsquic -c quic-go -t handshake,transfer`.

## Interop Runner results (2026-07-30)

Every pairing of dsquic, quic-go and aioquic, each as both client and
server, passes `handshake` and `transfer` through the ns-3 simulator: a
full 3x3 matrix of `✓(H,DC)`.

Against quic-go, dsquic also passes the robustness cases in both roles:
`transferloss`, `transfercorruption`, `blackhole`, `longrtt` and
`amplificationlimit`. As server that is `✓(H,DC,L2,C2,B,LR,A)` in one
run. `keyupdate` passes with dsquic as server, `✓(U)`, which the runner
verifies by reading key phase bits out of the pcap with Wireshark.

Two cautions about reading these results:

- The cases are timing sensitive on a four-CPU VM. `transferloss` and
  `blackhole` failed once inside a long combined run and passed on their
  own and in a later combined run. Contention, not protocol, but it
  means a single red square is worth re-running before believing.
- `handshakeloss` and `handshakecorruption` are *not* run. Both use the
  name `multiconnect` for the client container: 50 sequential
  connections from one invocation. Our client makes one connection for
  all of `REQUESTS`, so the shim exits 127 rather than reporting a
  failure. This is the largest remaining hole in loss coverage, since
  those two are the cases that lose handshake packets rather than data
  packets.

## In-flight work

`origin/main` is at bc93c5a, "Add the Interop Runner shim; set up
container DNS properly". Staged and awaiting commit is everything the
runner forced: Version Negotiation, the PTO exemption from the
congestion window, verbatim retransmission of lost stream frames, key
update, and PTO probes that retransmit rather than PING, plus the doc
updates recording the results.

## What interop and the wire found that self-testing did not

Each rung of the ladder found bugs the rung below it could not reach.
The five below came from the wire and from hand-written interop; the
five after them came only from the runner, whose simulator drops and
reorders packets that a loopback never does.

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

Found only by the runner:

- **No Version Negotiation.** The simulator's `wait-for-it-quic` probe
  offers version 0x57414954 ("WAIT") specifically to elicit a VN packet,
  and dsquic discarded it silently. This blocked every test case in
  every pairing, before any protocol behaviour was exercised. Now
  `packet.version_negotiation_response` answers statelessly, and refuses
  to answer datagrams under 1200 bytes (§6.1 amplification).
- **PTO probes were blocked by the congestion window**, contrary to
  RFC 9002 §7.5. A connection that lost a full window deadlocked at
  `cwnd=4919 inflight=5655`: nothing could be sent, so nothing could be
  acknowledged. `_send_budget` now exempts a pending probe.
- **Retransmission corrupted stream offsets.** Lost frames were pushed
  back onto the new-data queue, so the resent bytes took whatever offset
  came next. Lost frames now sit in their own queue and are resent
  verbatim (§13.3), and connection flow control counts the highest
  offset sent rather than bytes handed to the sender (§4.1).
- **Key update was not implemented** (RFC 9001 §6), which §6.2 makes
  mandatory for a receiver. quic-go's interop build updates keys after
  100 packets, so a 10MB transfer stalled dead at ~125KB: every packet
  after the update failed to authenticate and was dropped silently, and
  the connection died on the idle timer. The give-away was `KeyPhase: 1`
  in quic-go's own debug log while our packet counter sat at 99.
- **PTO probes carried a bare PING instead of retransmitting**, contrary
  to RFC 9002 §6.2.4. Before any ACK arrives, PTO is the *only* loss
  signal, so a lost ClientHello was never resent and the handshake sat
  there until the idle timer. Found by `longrtt`, which requires at
  least two ClientHellos in the trace; the bug is worse than that case
  implies, since it meant a handshake could not survive losing its first
  flight at all. A probe now retransmits the oldest unacknowledged
  packet's frames when there is no new data to send.

## Next steps

1. **The roadmap past the MVP** (design.md §6.1), in order: retry,
   resumption, multiplexing, http3, ecn, zerortt. Each climbs all three
   rungs of the ladder (design.md §6.2). `keyupdate` has left the list
   for the server role and needs only a policy for the client role: when
   to call `Connection.initiate_key_update`. Deciding that a key update
   happens is core, but "after N packets" is a configuration choice, so
   it probably belongs in `ConnectionConfig` rather than in the endpoint
   or the shim script.
2. **`qlog.py`**, which the design doc treats as first-class output and
   the foundation of the inspection-engine story. Also closes the
   `QLOGDIR` gap in the interop shim.
3. **MAX_STREAMS.** dsquic advertises 16 bidirectional streams and never
   raises the limit, so the seventeenth stream fails. This blocks the
   runner's `multiplexing` case and is a real gap for any peer that opens
   many streams.
4. **IPv6 in the endpoints.** Both open `AF_INET` sockets, so the runner's
   `ipv6` case cannot pass.
5. **`multiconnect` in the client endpoint**: one connection per
   requested file rather than one connection for all of them. This is
   what `handshakeloss` and `handshakecorruption` actually run, so it is
   the difference between having tested loss of handshake packets and
   only having tested loss of data packets.
6. **Broaden the runner matrix.** Three implementations are exercised
   locally out of the 17 registered; each additional one is a `docker
   pull` and a row in the run. Submitting dsquic upstream additionally
   needs a linux/amd64 image, since the hosted runner builds for that
   architecture.

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
