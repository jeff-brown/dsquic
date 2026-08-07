# What testing found, rung by rung

Defects each rung of the verification ladder (design.md §6.2) caught
that the rung below could not, and the investigations behind them.
History rather than current state: `STATE.md` says where the project
is now, and this says what it cost to get there. Kept because the
failures are the pedagogical payload, and because the methods that
found them are worth reusing.

## Three servers issued no tickets to a modes-less client (2026-08-07)

The first `resumption` sweep as client passed only against quic-go;
aioquic, picoquic and quiche all sent a Certificate in the second
handshake. The pcap showed why in one line: the second ClientHello
carried no `pre_shared_key` at all, so the first connection had never
been given a ticket to offer.

The client sent `psk_key_exchange_modes` only alongside an offer, and
RFC 8446 §4.2.9 gives the extension a second job: it "restricts both
the use of PSKs offered in this ClientHello and those which the server
might supply via NewSessionTicket", and servers SHOULD NOT issue
tickets incompatible with the advertised modes. aioquic reads a hello
with no modes as "issue nothing" (its server gates NewSessionTicket on
a negotiated mode), and picoquic and quiche behave the same. quic-go
issues tickets regardless, which both §4.6.1 permits and is why it
alone resumed. The fix: advertise `psk_dhe_ke` in every ClientHello,
offer `pre_shared_key` only with a ticket; the server got the matching
SHOULD and issues nothing to a client that advertised no usable mode.

Two lessons beyond the fix. The unit and loopback rungs could not have
caught it, because dsquic agreed with itself on both halves of the
mistake; it took a peer that implements the SHOULD. And the local
reproduction was two orders of magnitude faster than the runner: an
aioquic server is a dev dependency, and wiring its session-ticket
store into the interop harness turned a 90-second simulator cycle
into a 0.4-second pytest case, `test_resumption` in
`tests/interop/test_aioquic.py`, which now pins the behaviour.

The same sweep's one server-role failure, quiche as client, was
`wait-for-it: timeout ... sim:57832`: the simulator never came up and
no QUIC packet was sent. Re-run alone, it passed, as the standing
caution about single red squares predicts.

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

