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
  364 tests pass. Gates: `uv run pytest -q`, `uv run ruff check`,
  `uv run ruff format --check .`, `uv run mypy`, `uv run pyright`.
- Implemented in `src/dsquic/`: buffer, packet, frames, streams,
  connection, transport_parameters, tls, protection, recovery,
  congestion, new_reno, retry, hq, qlog, and the `endpoints/` subpackage
  (the only I/O). Still docstring stubs: h3, qpack, masque.
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
  is not attempted.

## Running the Interop Runner locally

The runbook lives in `interop/README.md`: VM sizing, the container file
descriptor limit that has to go in `colima.yaml` rather than
`daemon.json`, the two-disk layout and log retention, and keeping macOS
from sleeping through a sweep. Only what is currently true of this
machine is recorded here.

- The VM runs at `--cpu 8 --memory 16` on a 10-core, 32GB host, with
  container `nofile` raised to 1048576 through colima's `docker:`
  passthrough. The host disk is small (256GB, and near full), so runner
  logs are pruned to the three most recent runs.
- **Apple's `container` cannot drive it**, established rather than
  assumed: no compose support (interop.py shells out to `docker compose`
  in five places), `--network` has no static-IP option while the topology
  pins 193.167.0.100 and friends, and it attaches one network per
  container where the simulator needs two.
- The runner is cloned and run *inside* the VM at `~/quic-interop-runner`
  because colima refuses to mount host `/tmp` ("must not be a system
  path") and the runner insists on it. A stale `mounts:` entry in
  `~/.colima/default/colima.yaml` had to be cleared by hand.
- pyshark needs the `tshark` binary present in the VM, otherwise every
  test fails with "Expected exactly one version. Got []". That failure
  reproduces for quic-go too, which is how it was identified as
  environmental rather than ours.

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

## Stream limits (2026-08-05)

`StreamManager` carries the cumulative stream counts of §4.6 as mutable
state beside the flow control byte counts: an allowance the peer raises
with MAX_STREAMS, and an advertisement extended as peer-initiated streams
reach Data Read. §4.6 leaves the policy open and suggests extending as
streams close, which is what `max_streams_update` does, keeping the count
available to the peer roughly constant.

`Connection.open_stream` raises `StreamLimitReached`, distinct from
`StreamError`, because a reached limit is expected rather than a
connection error; it queues STREAMS_BLOCKED on the way out (§4.6, a
SHOULD). `endpoints.client.fetch` opens requests as credit allows rather
than all at once, which is what the runner's `multiplexing` case needs:
1999 files on one connection against an initial limit far below that.

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

## Interop Runner results

**Server role, every claimed case against all four peers, 2026-08-06.**
Twelve cases (`handshake`, `transfer`, `multiplexing`, `transferloss`,
`transfercorruption`, `blackhole`, `longrtt`, `amplificationlimit`,
`ipv6`, `keyupdate`, `handshakeloss`, `handshakecorruption`) pass against
quic-go, aioquic, picoquic and quiche, with no failures:
`✓(H,DC,M,L2,C2,B,LR,A,6,U,L1,C1)` in three columns and the same minus
`U` against quiche, whose client does not implement key update and so
reports it unsupported rather than failed. This is the first full
server-role sweep since pacing, both PTO fixes, and the dual-stack bind,
all of which change the server's send path.

`keyupdate` is verified by the runner reading key phase bits out of the
pcap, and `amplificationlimit` and `blackhole` exercise the §8.1 and
recovery paths that earlier sessions found bugs in.

**Client role, same twelve cases, 2026-08-06.** All twelve pass against
quic-go, aioquic and picoquic. Against quiche, eleven pass and
`handshakeloss` failed in the combined sweep and passed on its own
re-run. That re-run is not the whole story: see the open item below.

Two cautions about reading any of this:

- The cases are timing sensitive. `transferloss` and `blackhole` have
  each failed inside a long combined run and passed on their own, and
  `handshakeloss` and `handshakecorruption` traded places across two
  consecutive runs while they sat near the time budget. A single red
  square is worth re-running alone before believing it.
- `handshakeloss` and `handshakecorruption` run as `multiconnect`: 50
  files, one connection each, which is what makes them the only cases
  that lose *handshake* packets. `endpoints.client.fetch_each` provides
  that, bounding the whole run rather than each connection so one slow
  handshake cannot spend a budget the remaining files still need.

## Retry (2026-08-06)

`retry` passes in both roles against quic-go, aioquic, picoquic and
quiche, `✓(S)` in every column. `retry.py` carries the Retry packet
(§17.2.5) and the address validation tokens (§8.1.2-§8.1.4); the Retry
Integrity Tag is RFC 9001 §5.8 and stays in `protection.py`. The design
rationale, including why the core never sees an address, is in the
design.md appendix.

The client accepts at most one Retry per attempt and none once the
server has sent a readable packet (§17.2.5.2), re-derives its Initial
keys from the Retry's source connection ID (RFC 9001 §5.2), keeps its
packet numbers running (§17.2.5.3), and checks
`retry_source_connection_id` against the Retry it saw, or against its
absence when it saw none (§7.3). The server mints a token binding the
client address and the original destination connection ID, keeps no
state, and recovers both from the token when the retried Initial
arrives. `endpoints.server.ServerOptions.retry` turns it on;
`--retry` on the reference server, and the shim passes it for this case.

Only Retry tokens exist. NEW_TOKEN (§8.1.3) is parsed and ignored: the
token format carries a kind byte so the two can be told apart, which
§8.1.4 requires because Retry tokens are validated more strictly, but
nothing issues or stores one yet. It belongs with resumption and 0-RTT,
which is what §8.1.3 exists to serve.

Three things this cost, all worth recording.

The RFC 9001 A.4 vector is reproduced exactly apart from the first byte's
low four bits, which §17.2.5 defines as Unused and a client ignores;
matching the vector there would mean copying a value the spec says
carries no meaning.

The first interop run failed as server against all four peers because
address validation ran *before* Version Negotiation, so the simulator's
readiness probe, which offers an unknown version precisely to elicit a VN
packet, was read as a v1 Initial and dropped. VN comes first, ahead of
everything, for the second time in this project's history.

A token that does not validate now draws a Retry rather than a dropped
packet, per §8.1.3: "the server SHOULD proceed as if the client did not
have a validated address, including potentially sending a Retry packet",
whose note gives the reason as a client holding a NEW_TOKEN token. It is
reachable without NEW_TOKEN existing at all, because the key that
authenticates these tokens is generated per process: a client that
reconnects across a server restart presents one this server cannot check,
and discarding it left that client hanging until its idle timer. The test
covering it runs the same crafted Initial against a server with address
validation on and off, so what it pins is the policy rather than some
unconditional reply.

## Connection stalls under handshake loss (2026-08-06)

A green square on `handshakeloss` means 50 connections finished inside
the budget, not that none of them stalled. Scanning per-connection
durations across the traces is what shows the difference, and it is
cheap now that every connection leaves a `.sqlog`:

    for each trace: last event time minus first event time

**One cause found and fixed.** The client coalesces its Finished and its
first request into one datagram (§12.2), so losing that datagram loses
both. The Handshake PTO resends the Finished, but nothing resends the
request: RFC 9002 A.6 arms no application PTO at a client until the
handshake is confirmed, and §4.1.2 confirmation waits on a
HANDSHAKE_DONE that can itself be lost. The peer, already in 1-RTT, sends
PING probes that the client acknowledges while waiting for a request it
never received. One connection against quiche sat still for 54 seconds
this way. `_resend_early_application_data` now puts unacknowledged 1-RTT
packets in the Handshake probe's datagram, where §12.2 coalescing places
the CRYPTO the peer is waiting for ahead of them, which is the ordering
RFC 9001 §5.7 describes. quic-go arms its PTO the same way dsquic does
(`getPTOTimeAndSpace` skips the application space until confirmation), so
this is not a rule the ecosystem has and dsquic lacked.

Client-role stall counts over 10 seconds, same pairings, before and
after:

| pairing, case | before | after |
|---|---|---|
| aioquic, `handshakeloss` | max 20.3s, 1 stall | max 5.6s, none |
| quiche, `handshakeloss` | max 20.4s, 4 stalls | max 10.1s, 1 |
| quiche, `handshakecorruption` | max 16.7s, 2 stalls | max 13.0s, 1 |
| aioquic, `handshakecorruption` | max 12.5s, 1 stall | max 11.6s, 1 |

Each run draws a fresh loss pattern, so one pairing improving could be
luck; four moving together is not.

**The residual stalls are not ours, and that was established rather
than assumed.** Stalls of 10 to 13 seconds survive the fix, and
`handshakecorruption` barely moved, so the obvious next step looked like
more debugging. Running the peers against each other instead settled it
in two runs:

| pairing | `handshakeloss` | `handshakecorruption` |
|---|---|---|
| quic-go client vs quiche server | fails | fails |
| dsquic client vs quiche server | passes | passes |
| quiche client vs quic-go server | fails, 35.3s stall | passes |
| quiche client vs aioquic server | fails, 30.4s and 27.1s | passes, 85.8s stall |
| quiche client vs dsquic server | passes | passes |

quic-go's client also stalls 12.3s against aioquic on
`handshakecorruption`, where dsquic stalls 11.6s. So the stalls travel
with quiche and aioquic under handshake loss, against every peer, and
dsquic currently handles both better than quic-go and aioquic do: our
client passes against quiche's server where quic-go's does not, and our
server is passed by quiche's client where quic-go's and aioquic's servers
are not. Further chasing would be debugging other implementations.

Worth keeping as method: a stall inside a *passing* square is invisible
to the runner's pass/fail and obvious in one scan of connection
durations, and the question "is this us?" is answered by running a peer
against a peer, not by reading more of our own code.

## Pacing (2026-08-05)

Sending is paced per RFC 9002 §7.7: a leaky bucket in `connection.py`
filled at `CongestionController.pacing_rate(smoothed_rtt)` and capped at
ten datagrams. The core withholds datagrams and publishes the release
time through `next_timer()`; the endpoints already wake on that deadline
and send afterwards, so neither loop needed a change. Rationale and the
choice not to stamp `txtime` are in the design.md appendix.

Implementing it found a second defect: ACK-only datagrams were blocked by
a full congestion window. RFC 9002 §2 does not count an ACK-only packet
as in flight, and §7.7 exempts it from pacing, so a cwnd-blocked
connection had stopped acknowledging exactly when its peer needed the
acknowledgements to open the window. `_send_budget(ack_only=True)` now
skips the window while keeping the §8.1 anti-amplification limit.

The reference client is deliberately **not** bounded in concurrent
requests. It issues all 1999 of the `multiplexing` case at once, which is
what quic-go's interop client (an `errgroup` goroutine per URL) and
aioquic's (`asyncio.gather` over every URL) also do.

## The file descriptor limit that looked like a protocol bug (2026-08-05)

`multiplexing` failed with dsquic as client against an aioquic server,
and a bound of 64 concurrent requests in `endpoints/client.py` made it
pass. That bound was wrong, and the reasoning behind it was wrong twice
over. What the aioquic server's own log said was
`OSError: [Errno 24] Too many open files`, 773 times, which is exactly
the number of the 1999 streams it never answered. It answers a request by
opening a file and does not bound its own handlers.

The discriminating experiment is to run **another client** against the
same server: quic-go's client fails the same case in this environment,
482 times over. The cause is that the Interop Runner's `docker-compose.yml`
sets only `memlock`, so the file descriptor limit is whatever the Docker
daemon defaults to, and in the colima VM that is 1024. Upstream hosts,
where all 15 clients pass against aioquic, default far higher.

Both directions of `multiplexing` were affected: quiche as client
against a dsquic server failed the same way, since the reference server
also opens a file per request. It is fixed in the VM rather than in the
runner's compose file, since the limit is a property of this machine and
not of the test; `interop/README.md` carries the setting and the reason
it has to go in `colima.yaml` rather than `daemon.json`. With it in place
`multiplexing` passes in **all eight pairings**, dsquic in both roles
against quic-go, aioquic, picoquic and quiche, with the client unbounded.
The dsquic image was identical across the failing and passing runs; only
the daemon setting changed.

Worth remembering as a method: when one implementation appears uniquely
broken against a peer, run a known-good implementation against that peer
in the same environment before believing it. Two of the three conclusions
drawn here before that experiment were wrong.

## handshakeloss and handshakecorruption as client (2026-08-05)

Three defects, each hidden behind the one before it, found by pointing
the qlog at the case rather than by reading captures. All three are
client-side and all three need loss during the handshake, so nothing
below the runner reached them.

- **The second PTO probe carried a bare PING.** §6.2.4 allows two probe
  datagrams; `_prepare_probe` requeued the outstanding flight once, so
  the first probe carried the lost CRYPTO and the second fell back to a
  PING. When the ClientHello is lost, that probe is the first Initial
  the server sees, and RFC 9000 §17.2.2 says "The first packet sent by a
  client always includes a CRYPTO frame": aioquic answered it with
  PROTOCOL_VIOLATION, `Error: 10, reason: Packet contains no CRYPTO
  frame`, killing the connection a millisecond after creating it. The
  probe fallback is now a copy of the oldest unacknowledged CRYPTO frame
  and a PING only when none is outstanding.
- **A PTO doubled the outstanding flight.** `_prepare_probe` requeued
  *every* unacknowledged packet, and the send loop transmitted all of
  them, so each expiry sent twice what the last one did: 2, 3, 6, 12, 24
  and 48 datagrams were observed, against §6.2.4's limit of two. The
  congestion window never braked it because retransmitted CRYPTO
  fragments are small, roughly 160 bytes, so a flight of 48 of them
  still fits in the initial window. A PTO now requeues at most one
  packet per probe; loss detection retransmits the rest.
- **Application data waited on handshake confirmation.** RFC 9001 §4.1.1
  makes 1-RTT data sendable once the handshake is *complete*; §4.1.2
  confirmation is a later event that governs discarding Handshake keys
  and initiating key updates. The client emitted only
  `HandshakeConfirmed`, on HANDSHAKE_DONE, and `endpoints.client.fetch`
  gated requests on it. HANDSHAKE_DONE can be lost, and when it was, the
  client sat retransmitting Handshake CRYPTO for 38 seconds into a space
  the server had already discarded keys for, while the server, long since
  in 1-RTT, waited for a request that the client refused to send. The
  connection now emits `HandshakeCompleted` (§4.1.1) as well, and the
  endpoints gate on that.

The qlog earned its keep here, but only after `acked_ranges` was added
(events §8): without the ranges an ACK says nothing about which packets
a peer confirmed, and two rounds of analysis were guesswork because of
it.

With all three fixed, `handshakeloss` and `handshakecorruption` pass as
client against all four peers, `✓(L1,C1)` in every column. quic-go passes
both in this environment, which is what identified the fault as ours
rather than an aioquic quirk: the same discriminating experiment that
settled the file descriptor question.

## IPv6 and client-initiated key update (2026-08-06)

Both endpoints take their address family from the name they are given,
via `getaddrinfo`, rather than hardcoding `AF_INET`. A server given an
IPv6 bind address sets `IPV6_V6ONLY` off, so one socket serves IPv4
peers too, arriving as `::ffff:a.b.c.d`. `Address` covers both sockaddr
shapes, since IPv6 adds flow info and scope id. The runner's `ipv6` case
passes in both roles against quic-go and aioquic, `✓(6)`.

`ConnectionConfig.key_update_interval` is the client-side key update
policy: packets sent in a phase before starting the next (§6.1).
Deciding that an update happens is core, which is why the check lives in
the send path and defers to `initiate_key_update`, whose §6.1
preconditions can still refuse it; how often is policy, which is why the
number is configuration. The reference client exposes it as
`--key-update-interval` and the shim passes 100 for the `keyupdate`
case, the same figure quic-go's interop client uses.

## In-flight work

`origin/main` is at d01af35, "Add Retry packet parsing and integrity tag
(RFC 9001 §5.8)". Staged and awaiting commit: Retry itself, both roles,
including the address validation tokens in `retry.py`, the client and
server halves in `connection.py` and `endpoints/server.py`,
`retry_source_connection_id`, and `ServerOptions`.

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

1. **Finish the QUIC protocol work before starting HTTP/3.** Remaining
   runner cases: `resumption`, `zerortt`, `ecn`, `chacha20`,
   `connectionmigration`, and `versionnegotiation`, where dsquic sends
   VN but a client does not react to receiving one by retrying with a
   supported version. `resumption` is the natural next one: it needs
   session tickets in `tls.py` and is the prerequisite for `zerortt`,
   which in turn is what makes NEW_TOKEN (§8.1.3) worth having.
2. **HTTP/3 after that** (design.md §6.1). The largest piece and the one
   that unblocks MASQUE, since `h3.py` is a stub and carries the last
   open MASQUE readiness constraint.
3. **Broaden the runner matrix.** Four implementations are exercised
   locally out of the 18 registered; each additional one is a `docker
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
