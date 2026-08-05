# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-08-03)

**The MVP is complete and the QUIC Interop Runner has been run against
it.** dsquic completes QUIC handshakes and transfers files over
hq-interop against independent implementations, in both directions, over
real UDP and through the runner's ns-3 simulator. This is design.md §6.3
step 5, the recorded definition of MVP done.

Runner results, locally hosted (see "Interop Runner results" below):
`handshake` and `transfer` pass in every pairing of dsquic, quic-go and
aioquic, in both roles. As **server** dsquic passes every case it
attempts against quic-go, aioquic, picoquic and quiche, plus `keyupdate`.
As **client** it passes everything against picoquic and quiche, and all
but `handshakeloss` and `handshakecorruption` against aioquic, which are
the open item recorded below.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy,
  strict pyright (the Pylance engine; `pyrightconfig.json`), pytest.
  328 tests pass. Gates: `uv run pytest -q`, `uv run ruff check`,
  `uv run ruff format --check .`, `uv run mypy`, `uv run pyright`.
- Implemented in `src/dsquic/`: buffer, packet, frames, streams,
  connection, transport_parameters, tls, protection, recovery,
  congestion, new_reno, hq, qlog, and the `endpoints/` subpackage (the
  only I/O). Still docstring stubs: h3, qpack, masque.
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
  bridge. `run_endpoint.sh` claims the eight cases listed under results
  below; interop/README.md tabulates why each of the runner's other cases
  is not attempted. Gaps: IPv4 only and no client-initiated key update.

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

## qlog (2026-08-05)

`qlog.py` emits the sequential JSON-SEQ format,
`urn:ietf:params:qlog:file:sequential`, declaring
`urn:ietf:params:qlog:events:quic-13`. Both documents are still
Internet-Drafts; the rationale for the format and the event set is in the
design.md appendix. `endpoints/` writes one `.sqlog` per connection under
QLOGDIR, named for the group ID, which is the original destination
connection ID: quic-go names its own traces the same way, so the two
endpoints' files line up by filename.

Frame names follow the schema (`crypto`, `handshake_done`), not the
Python class names, since a trace no reader recognises is worth about as
much as none. A `handshakeloss` run as server produces 50 traces and
shows what the format is for. The drops it records are the two the receive path makes
silently: 50 `key_unavailable`, the client's late Handshake
retransmissions arriving after the server discarded those keys, and 10
`general`, the RFC 9001 §5.7 early-1-RTT drops. The §5.7 case is the bug
that cost most of a session to find from packet captures, because a
dropped packet leaves no trace on the wire. It is now a labelled line in
a log.

On readers, which took two rounds to get right. qvis rejected the first
traces outright: it requires the pre-URN `qlog_version` and `qlog_format`
header fields, which the current draft no longer mentions and which
quic-go still emits for exactly this reason. Both spellings now go out.
qvis then parses the file but renders little of it, because it
implements qlog draft-02 (`QlogSchema02.ts` is its newest) and so knows
`transport:packet_sent`, not the `quic:` namespace the drafts have used
since draft-12. That is a stale tool rather than a defect here:
pmeenan/waterfall-tools is maintained, reads both dialects and both
serializations, and consumes exactly the fields emitted here
(`header.packet_type`, `raw.length`, `initiator`), and renders these
traces: both vantage points parse, report `anchored: true`, and expose
RTT, congestion window and bytes-in-flight as series. A client and a
server trace of the same connection carry one group ID and anchor within
a millisecond of each other, so they lay over one timeline.

Two defects that only a consumer could find, both fixed: the header
lacked the pre-URI `qlog_version` and `qlog_format` fields, which readers
predating the URI scheme require and without which qvis refused the file;
and `parameters_set` and `connection_closed` used `owner` and
`connection_code` where events §5.3 and §4.3 say `initiator` and
`error_code`. Neither was reachable from the draft text alone or from
our own parser. Coverage is partial by choice: `packet_received` records no frames, and
`version_information`, `alpn_information`, `congestion_state_updated`,
`recovery_parameters_set` and `stream_data_moved` are unimplemented.
`parameters_set` logs the peer's parameters, not our own. The last of
those is why a waterfall shows no entries: request-level rows come from
`stream_data_moved` or HTTP/3 events.

## Reproducing loss locally, without the runner

An Interop Runner cycle is 90 seconds and yields a pcap. The three
server-side defects listed under "What interop and the wire found" were
found instead with a 60-line UDP relay that forwards between a real peer
and a dsquic endpoint while dropping
every third datagram in each direction, deterministically so a failure
repeats exactly. Point quic-go's `hq-client` at the relay and the relay
at `dsquic.endpoints.server`, and the runner's handshakeloss conditions
reproduce in seconds, with the server available for ordinary printf
debugging and unlimited restarts.

Two things that only that view showed: the reference server was dying of
an uncaught `ValueError` and taking every connection on the socket with
it, and the connection was terminating itself with PROTOCOL_VIOLATION
rather than stalling. Neither is visible in a capture, which shows only
that packets stopped.

Worth rebuilding rather than rediscovering. The pieces are a relay that
keys one upstream socket per client address, and a server harness that
prints per-connection state whenever it changes.

## Interop Runner results (2026-08-03)

Every pairing of dsquic, quic-go and aioquic, each as both client and
server, passes `handshake` and `transfer` through the ns-3 simulator: a
full 3x3 matrix of `✓(H,DC)`.

Against quic-go, dsquic as client passes `✓(H,DC,C1,L2,C2,LR,A,B)` and
as server `✓(H,DC,L1,C1,L2,C2,LR,A)`. `keyupdate` passes with dsquic as
server, `✓(U)`, which the runner verifies by reading key phase bits out
of the pcap with Wireshark.

Against aioquic, picoquic and quiche on `handshake`, `transfer`,
`handshakeloss`, `handshakecorruption` and `transferloss`, dsquic as
**server** passes all five against all three, `✓(H,DC,L1,C1,L2)` in every
column. That is four independent implementations behind the server-side
fixes, picoquic among them, which design.md picks as the conformance
ratchet. As **client** picoquic and quiche also pass all five; aioquic
does not, and that is the open item below.

Two cautions about reading these results:

- The cases are timing sensitive on a four-CPU VM. `transferloss` and
  `blackhole` have each failed inside a long combined run and passed on
  their own and in a later combined run. Contention, not protocol, but
  it means a single red square is worth re-running before believing.
- `handshakeloss` and `handshakecorruption` run as `multiconnect`: 50
  files, one connection each, which is what makes them the only cases
  that lose *handshake* packets. `endpoints.client.fetch_each` provides
  that, bounding the whole run rather than each connection so one slow
  handshake cannot spend a budget the remaining files still need. As
  server both pass; as client `handshakeloss` is intermittent, recorded
  below.

## Open: handshakeloss and handshakecorruption as client, vs aioquic

As **server** these are fixed and confirmed against four peers. As
**client** they fail consistently against aioquic, pass against picoquic
and quiche, and are intermittent against quic-go.

It is not the VM and it is not emulation. aioquic, picoquic and quiche
are all amd64 images running emulated on an aarch64 host, and two of the
three pass, so emulation is controlled for. It is also **not a
regression**: an image built from the previous commit fails the same two
cases against aioquic in the same way, so the three server-side fixes
revealed this rather than caused it. It had never been run before,
because client-versus-aioquic loss cases were not part of any earlier
matrix.

This pairing is hard across the ecosystem, which lowers the priority. In
the public run at
`https://interop.seemann.io/logs/quic/2026-08-03T17:17/result.json`,
aioquic as server is failed on `handshakeloss` by quic-go, ngtcp2, lsquic
and go-x-net, and on `handshakecorruption` by lsquic, quinn and
go-x-net. aioquic sits mid-pack among servers for these two cases, 4 of
14 and 3 of 14; mvfst fails 13 of 14 and quiche fails 9 of 14 on
corruption, while picoquic and neqo are clean. Note that dsquic passes
both against quiche, which most clients do not, and against picoquic.

That said, 10 of the 14 clients that attempt it do pass against aioquic,
so this is not an exoneration: most stacks handle whatever the
interaction is.

Nor is it reproducible with the loss relay: fifty sequential connections
complete 50/50, twice over, at a higher uniform loss rate than the runner
uses. Two differences worth chasing, in order:

- The runner drops three datagrams consecutively (`burst_to_server=3`)
  where the relay drops every third and so never drops two in a row. A
  PTO sends its two probes back-to-back, so a burst can take both, which
  is exactly the case two probes exist to survive. Teaching the relay to
  drop in bursts is the cheapest next experiment, and aioquic can be
  driven locally since it is already a dev dependency.
- dsquic does not coalesce a copy of the Finished ahead of its 1-RTT
  packets, which RFC 9001 §5.7 recommends "until one of the Handshake
  packets is acknowledged". Once our Finished is sent, a retransmitted
  request goes out as a bare 1-RTT datagram. Against a server enforcing
  §5.7 strictly that costs a round trip per attempt rather than
  breaking, but under burst loss the round trips compound.

## In-flight work

`origin/main` is at c24c855, "Add multiconnect; fix six defects it
uncovered under handshake loss". Staged and awaiting
commit are the three server-side defects: HANDSHAKE_DONE (and the
flow control frames) retransmitted on loss per §13.3, 1-RTT packets not
processed before the handshake completes per RFC 9001 §5.7, and Data
Read made terminal so a retransmitted final frame cannot report the end
of a stream twice.

## What interop and the wire found that self-testing did not

Each rung of the ladder found bugs the rung below it could not reach.
The five below came from the wire and from hand-written interop;
everything after them came only from the runner, whose simulator drops,
corrupts and reorders packets in ways a loopback never does.

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

Found by `handshakeloss` and `handshakecorruption`, once the client
could run them at all. These are the only cases that lose *handshake*
packets, and they surfaced four defects in a chain, each hidden behind
the one before it:

- **The idle deadline was frozen when the timer was armed** rather than
  computed from the current RTT estimate. It is now a property, derived
  on demand. Note that the floor deliberately uses the *unscaled* PTO;
  see "Bounding the PTO backoff" below for why that reading won.
- **Lost CRYPTO frames were spliced back into the pending byte buffer.**
  That buffer's first byte is by definition at `crypto_offset_sent`, so
  prepending earlier bytes mislabels every frame sent after them and the
  peer's TLS reassembles garbage: quic-go answered with CRYPTO_ERROR
  plus TLS alert 80, error code 336. This is the same defect fixed for
  streams and never applied to CRYPTO; lost frames now have their own
  queue and are resent verbatim, split on offset when they do not fit.
- **The client never discarded Initial keys on first sending a Handshake
  packet** (RFC 9001 §4.9.1, a MUST, which exists precisely to abandon
  Initial loss recovery). The server drops its Initial keys at that
  point and can never acknowledge another Initial packet, so the
  client's last Initial stayed in flight forever, won the PTO race every
  time, and every probe went to a level the peer could no longer read
  while the Handshake flight sat unsent.
- **The anti-deadlock PTO anchored on the last ack-eliciting packet.**
  A.8 says "Anti-deadlock PTO starts from the current time". A client
  that had only ever sent ACK-only Handshake packets had nothing to
  anchor to and so armed no timer at all. It now anchors on the last
  recovery event, which is the moment A.8 would have set the timer.

- **A PTO sent one probe, not two.** §6.2.4 permits up to two datagrams
  "to avoid an expensive consecutive PTO expiration due to a single lost
  datagram", and at 30% loss the difference is stark: one probe is lost
  30% of the time, two 9%. Because the PTO doubles on every expiry, an
  unlucky probe does not cost one round trip, it doubles the wait for
  every attempt after it. A captured connection probed at 12.4s, 13.4s,
  15.4s, 19.4s, 27.4s, 43.4s, 75.4s, 139.4s and 267.4s: ten attempts in
  four and a half minutes. Both probes now carry the lost CRYPTO rather
  than a copy plus a PING.

Three more came from running those cases with dsquic as *server*, which
had never been exercised before multiconnect existed. All three need
both loss and a peer that retransmits, so nothing below the runner could
have reached them:

- **A lost HANDSHAKE_DONE was never retransmitted**, against §13.3's
  "MUST be retransmitted until it is acknowledged". `_requeue_lost`
  handled CRYPTO and STREAM frames and silently dropped every other
  type. The client confirms the handshake on that frame and nothing
  else, so losing it left the client holding Handshake keys and probing
  a space the server had already discarded keys for. Those probes can
  never be acknowledged, so they accumulated in flight, 17 then 65 then
  129 packets, until the congestion window was full of them and the
  client could no longer send its actual request. MAX_DATA and
  MAX_STREAM_DATA were dropped the same way and are now re-sent with
  their current values, as §13.3 requires.
- **1-RTT packets were processed before the handshake completed**
  (RFC 9001 §5.7: "Endpoints in either role MUST NOT decrypt 1-RTT
  packets from their peer prior to completing the handshake", and "A
  server MUST NOT process incoming 1-RTT protected packets before the
  TLS handshake is complete"). A server holds 1-RTT keys from the moment
  it sends its own Finished, so a request that overtakes the client's
  Finished decrypts perfectly well. dsquic decrypted it, found a STREAM
  frame, had no stream manager yet, and killed its own connection with
  PROTOCOL_VIOLATION. Such packets are now dropped unacknowledged, which
  is the point: an acknowledgement claims the frames were handled.
- **A retransmitted final frame reopened a completed stream.**
  `RecvStream.on_stream_frame` set the receive state unconditionally, so
  a duplicate of a stream's last frame moved it from Data Read back to
  Data Recvd; the next read re-entered Data Read and reported the end of
  the stream a second time. RFC 9000 §3.2 Figure 3 makes Data Read
  terminal. The reference server answered the same request twice and
  died on "write after fin", an uncaught crash that took down every
  connection sharing the socket.

And the one that mattered most, also found this way:

- **The server treated the client's address as validated only once the
  handshake completed**, rather than on the first Handshake packet it
  processed (RFC 9000 §8.1: "Once an endpoint has successfully processed
  a Handshake packet from the peer, it can consider the peer address to
  have been validated"). Under §8.1's 3x limit that strands any server
  whose flight is larger than three times the client's Initial, which is
  every server with a real certificate chain. A 4KB-certificate
  handshake under one-in-three loss went from stalling for 80 seconds to
  completing in 0.08 seconds.

## Next steps

1. **The roadmap past the MVP** (design.md §6.1), in order: retry,
   resumption, multiplexing, http3, ecn, zerortt. Each climbs all three
   rungs of the ladder (design.md §6.2). `keyupdate` has left the list
   for the server role and needs only a policy for the client role: when
   to call `Connection.initiate_key_update`. Deciding that a key update
   happens is core, but "after N packets" is a configuration choice, so
   it probably belongs in `ConnectionConfig` rather than in the endpoint
   or the shim script.
2. **MAX_STREAMS.** dsquic advertises 16 bidirectional streams and never
   raises the limit, so the seventeenth stream fails. This blocks the
   runner's `multiplexing` case and is a real gap for any peer that opens
   many streams.
3. **IPv6 in the endpoints.** Both open `AF_INET` sockets, so the runner's
   `ipv6` case cannot pass.
4. **Broaden the runner matrix.** Three implementations are exercised
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

## Bounding the PTO backoff (settled 2026-08-03)

**Decision: the idle floor uses the unscaled PTO, and the backed-off PTO
is capped at 60 seconds.** Settled by surveying four implementations
after an interop connection was seen hanging for 268 seconds rather than
failing.

RFC 9000 §10.1 floors the idle timeout at "three times the current Probe
Timeout (PTO)", which reads as though it means the backed-off value.
Implementing it that way is what produced the hang: the PTO doubles on
every expiry, so the idle deadline recedes exactly as fast as the backoff
grows and the connection never dies. What was observed as a stall was
that connection probing at 128-second intervals.

What the ecosystem does:

| | PTO cap | Probes per PTO | Idle floor uses |
|---|---|---|---|
| quic-go v0.61 | 60s, citing RFC 8961 §4.4 | | `rttStats.PTO(true)*3`, unscaled |
| aioquic 1.3 | none | 1, plus all outstanding CRYPTO | `3 * get_probe_timeout()`, unscaled |
| quiche | none, but carries a `pto_overflow_reproduction` regression test | 2 (`MAX_PTO_PROBES_COUNT`) | |
| picoquic | bounds attempts, not time: `nb_retransmit > 9` abandons the path | | |

Both implementations that dsquic interops with read §10.1's "the PTO" as
the unscaled one, so dsquic now does too: `LossDetection.pto()` has no
backoff, and `_pto_duration` keeps the backoff for arming timers. The cap
comes from RFC 8961 §4, requirement 4, which quic-go cites for the same
constant: "A maximum value MAY be placed on the RTO. The maximum RTO MUST
NOT be less than 60 seconds." RFC 9002 sets no ceiling of its own.

picoquic's approach, bounding the number of retransmissions rather than
the interval, is a coherent alternative that was not taken: it needs more
state and has no QUIC-spec citation behind it.

## Open decisions

See design.md §7. Still open: 0-RTT scope, whether to add an asyncio
transport over the sans-IO core, PyPI publication, and the v1 MASQUE
surface (CONNECT-UDP only vs. CONNECT-IP alongside). Everything settled
so far is recorded in the design.md appendix.
