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
every claimed case, now including `resumption`, passes in both roles
against quic-go, aioquic, picoquic and quiche.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy,
  strict pyright (the Pylance engine; `pyrightconfig.json`), pytest.
  434 tests pass. Gates: `uv run pytest -q`, `uv run ruff check`,
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
  bridge. `run_endpoint.sh` claims the twelve cases listed in
  interop/README.md, which also tabulates why each of the runner's
  other cases is not attempted.

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

**Resumption, both roles, 2026-08-07.** `✓(R)` against all four peers
in both directions, run as its own case. The first sweep failed as
client against everyone but quic-go, which was a real §4.2.9 defect
(docs/findings.md), and once as server against quiche's client, which
was the simulator failing to start (`wait-for-it: timeout` before any
QUIC packet), passing on re-run.

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

## What testing found

Moved to `docs/findings.md`: the defects each rung of the ladder caught,
the handshake-loss investigation, the container file descriptor limit
that looked like a protocol bug, and the connection stalls that turned
out to belong to other implementations. History, retrievable when
wanted, rather than resident in every session.

## Resumption (2026-08-07)

`resumption` passes in both roles against quic-go, aioquic, picoquic
and quiche, `✓(R)` in every column: exactly two handshakes, a
Certificate in the first and none in the second, verified by the
runner from the pcap. Every rung is done except the independent wire
capture check the phase gates assign to the human; the runner's pcaps
and SSLKEYLOGFILE logs from these runs are retained in the VM for it.

How it is built, briefly. Session tickets are sealed with a per-process
AES-256-GCM key (`ServerConfig.ticket_key`; `Server.__init__` generates
one when unset), so the server keeps no per-ticket state. Every
derivation is pinned to RFC 8448 vectors in `tests/rfc8448_vectors.py`.
The client carries a zero-PSK fallback schedule beside the PSK schedule
until the ServerHello resolves the offer, recomputes its binder over
message_hash + HelloRetryRequest + truncated hello after a retry
(§4.2.11.2), and validates `selected_identity`. The server verifies
binders from a `KeySchedule(psk=...)`, declines unusable tickets to a
full handshake, aborts on a bad binder (DECRYPT_ERROR), and after its
own HelloRetryRequest declines PSKs rather than rebuilding a transcript
it no longer holds. `fetch` takes a caller-owned ticket store;
`fetch_each` threads it under `ClientOptions.resume` (`--resume`,
requiring `--connection-per-request`); `Server.connections_resumed`
counts PSK handshakes for tests and logs.

The defect the runner found, recorded in docs/findings.md: the client
sent `psk_key_exchange_modes` only when offering a ticket, and
spec-following servers (aioquic, picoquic, quiche) issue no
NewSessionTicket to a client that advertised no modes (§4.2.9). The
extension now goes out on every ClientHello, and the server got the
matching SHOULD: no ticket for a client without `psk_dhe_ke`. The
aioquic interop harness now wires a session-ticket store, so
`test_resumption` in tests/interop/test_aioquic.py reproduces in 0.4
seconds what took a runner cycle to see.

The pieces resumption deliberately left out, `early_data`, ticket age
freshness, and NEW_TOKEN issuance, are now the 0-RTT plan below.

## 0-RTT, next (2026-08-07)

Decided in scope with freshness-based anti-replay; rationale and the
sub-decisions are in the design.md appendix.

**Acceptance criterion**, read from the runner's `TestCaseZeroRTT`:
40 files of 32 bytes with 250-octet names, exactly 2 handshakes, some
0-RTT payload from the client, and at most half the total request
bytes (0.5 x 250 x 40 = 5000) in client 1-RTT packets. So the client
fetches one file on a full connection, then the remaining 39 on one
resumed connection with every request sent as early data. That is a
new client mode, not `--connection-per-request`: one resumed
connection carrying many early requests.

**Order of work, each step gated on the one before:**

1. Done: `KeySchedule.client_early_traffic_secret`, pinned to the RFC
   8448 §4 resumed 0-RTT trace in `tests/rfc8448_vectors.py`.
2. Done: `early_data` in NewSessionTicket (the mandatory 0xffffffff,
   RFC 9001 §4.6.1, any other value aborts), offered in the
   ClientHello under `ClientConfig.early_data` (dropped on a second
   hello, §4.1.4), echoed in EncryptedExtensions on acceptance. The
   sealed ticket became `TicketState`: psk, `age_add` (for the §8.3
   freshness check, still todo), ALPN and transport parameters, and
   the server accepts only when the first identity was selected and
   neither remembered value would change (§4.2.10, RFC 9001 §7.4.1).
   Both machines expose `early_data_accepted`. Secrets and events are
   step 4, where the packet space lands.
3. Done with step 2: `SessionTicket` on the client grew
   `max_early_data_size`, the ALPN, and the server's remembered
   transport parameters.
4. Done: 0-RTT in `connection.py`, deliberately not a fourth `_Space`:
   it shares the application space's packet numbers, recovery, and
   flow control (§12.3), holding early send/recv keys beside the 1-RTT
   ones. The client builds long-header 0x1 packets until 1-RTT send
   keys exist, under stream state created at `connect()` from the
   ticket's remembered parameters; the server installs early receive
   keys and its stream state the moment TLS accepts, so 0-RTT stream
   frames are served before its handshake completes. Reject requeues
   everything 0-RTT carried into 1-RTT (RFC 9001 §4.6.2); acceptance
   with reduced limits aborts (§7.4.1, `reduces_zero_rtt_limits` in
   transport_parameters.py, also the server's acceptance test, since
   the CID-authentication fields differ per connection and byte
   equality of encoded parameters never holds). Frames §12.4 bars from
   0-RTT are rejected; both sides keylog CLIENT_EARLY_TRAFFIC_SECRET;
   qlog says "0RTT". Early keys drop at completion (client) and
   confirmation (server, §4.9.3). A resuming client that hits a
   HelloRetryRequest keeps its pre-retry 0-RTT data only via the
   handshake-probe resend path, which is slow but converges.
5. Done: the §8.3 freshness window, `TlsServer._ticket_is_fresh`: the
   claimed age (obfuscated_ticket_age minus the sealed age_add) must
   sit within 10 seconds of the actual age (now minus the sealed issue
   time); outside it the PSK still resumes and only the early data is
   refused. The replay test feeds one ClientHello to two servers, 5
   and 30 seconds after issue. Consequence callers inherit: ticket age
   is measured on the client's monotonic clock, so offering a ticket
   under a clock that runs backwards (or a different process's clock
   without care) makes the claim stale and 0-RTT quietly downgrade.
6. Done, core half: `retry.py` mints and validates NEW_TOKEN-kind
   tokens (address plus age, no connection ID, kind b"\x02"; each
   validator refuses the other kind, §8.1.4); the core carries them:
   `Connection.send_new_token` queues the frame (the endpoint mints,
   since the core never sees an address), a client keeps arrivals in
   `Connection.new_tokens`, and `ConnectionConfig.token` rides the
   next connection's Initials, with a Retry's token taking precedence
   (§17.2.5.3). A server receiving NEW_TOKEN errors (§19.7); lost
   frames are resent verbatim (§13.3). Endpoint minting on
   HandshakeCompleted, validation in `Server._validate_address`
   (accept either kind as validating; per-process token key decoupled
   from `--retry`), and the client-side store belong to step 7.
7. Done: `SessionStore` in endpoints/client.py holds tickets and
   tokens per server; `fetch` offers the newest ticket, spends a
   stored token into `ConnectionConfig.token`, harvests both, and
   with `ClientOptions.early_data` issues requests as soon as stream
   state exists, which before completion means 0-RTT. `fetch_zero_rtt`
   (CLI `--zero-rtt`) does the runner split: first path full, the rest
   on one resumed early-data connection. The server endpoint always
   holds a token key now (Retry stays opt-in via `--retry`), mints a
   NEW_TOKEN on every HandshakeCompleted, accepts either token kind in
   `_validate_address` (a NEW_TOKEN one validates without a
   RetryContext, since no Retry happened and §7.3 must not echo one),
   and counts `connections_early_data`. The shim claims `zerortt`.
   Known conservatism: a token-validated connection still waits for
   the first Handshake packet before lifting the §8.1 limit.
8. Done. Unit (RFC 8448 vectors), loopback (`test_loopback_zero_rtt`),
   aioquic interop (`test_zero_rtt`: aioquic reports our 0-RTT
   accepted), and the runner: `zerortt` passes in both roles against
   quic-go, aioquic, picoquic and quiche, `resumption` re-verified
   after the change below. The runner's pcap check caught two defects
   every lower rung missed, written up in docs/findings.md: `fetch`
   queued requests after the first pump, so nothing actually rode
   0-RTT; and the server's `initial_max_streams_bidi=16` capped a
   resuming client's early burst at 16 requests, so the default is
   now 100. What remains is the human wire check: the latest three
   log directories in the VM hold the passing pcaps and keylogs.

## Migration cluster, next (2026-08-08)

**Criteria, read from the runner's source, which reshaped the plan.**
`rebind-port` and `rebind-addr` are server-side: a 10MB transfer while
the simulator rebinds the client's apparent port (and address) every 5
seconds from t=1s; the checker requires the server's first packet on
each new path to carry a PATH_CHALLENGE frame, and the transfer to
finish. `connectionmigration` is the `preferred_address` case: the
server container gets the testcase and must offer a preferred address
(2MB transfer, host server46), while the client container is told
plain "transfer" and is expected to migrate to the offered address and
validate it. That settles yesterday's open question by evidence:
preferred_address is the centerpiece, recorded in design.md §7.

**Order of work, each step gated on the one before:**

1. Done: path validation (§8.2). PATH_CHALLENGE is answered with the
   same eight bytes (§8.2.2); `Connection.validate_path()` issues a
   challenge and clears the public `path_validated` flag, which only
   a matching response restores (§8.2.3); a stray response is
   ignored, since one can outlive the path that asked. Lost
   challenges are resent verbatim; lost responses deliberately are
   not (§8.2.2, the peer re-challenges). The handshake path counts
   as validated from the start (§8.1). Datagram expansion for
   challenges (§8.2.1's SHOULD) is deferred to step 2, where the new
   path's amplification limit makes the decision real.
2. Server passive path change (§9.3): a higher-numbered packet from a
   new source moves the connection's destination, the first packet
   sent there carries PATH_CHALLENGE, and congestion and RTT reset
   unless the address was only a port rebinding is a §9.4 subtlety to
   read closely. The endpoint already routes by connection ID, so the
   change is core-side: the destination is opaque to the core but
   comparable, which is what lets the core notice the change without
   interpreting addresses. Rungs: a loopback test that rebinds a
   client socket mid-transfer, then `rebind-port` and `rebind-addr`.
3. NEW_CONNECTION_ID issuance (§5.1.1), the minimum migration needs:
   preferred_address carries a CID with sequence 1 and a stateless
   reset token, and §9.5 wants fresh CIDs on new paths. Issue a small
   pool; handle RETIRE_CONNECTION_ID.
4. preferred_address (§9.6): the TransportParameters field, server
   config to populate it (the shim must learn which addresses the
   container owns), and the client side: after handshake
   confirmation, validate the preferred path and migrate, abandoning
   it if validation fails (§9.6.2). Rungs: loopback with a
   dual-socket server, then `connectionmigration` in both roles.

## Version negotiation, client side (2026-08-08)

The client can now force and honour Version Negotiation: dialled with
a reserved version (`ConnectionConfig.version`, §15), it validates the
server's answer per §6.2 (ignored after any processed server packet,
if it lists the version in use, or if the connection IDs do not
mirror ours), surfaces `VersionNegotiationReceived`, and dies for the
caller to redial; `fetch_negotiating` (CLI `--negotiate-version`)
does the redial with v1. packet.py grew the parser beside the
long-standing stateless responder.

The runner rung is not applicable, established rather than assumed:
upstream keeps `TestCaseVersionNegotiation` but dropped it from
`TESTCASES_QUIC`, so no runner invocation can name it and the public
matrix has no column for it. Verification therefore tops out at the
loopback rung, the full force-and-redial flow over real UDP through
both reference endpoints. The shim still claims the case for any
runner that reinstates it. The same registry check surfaced two
runner cases the plans here had not tracked: `rebind-port` and
`rebind-addr`, which belong with `connectionmigration`.

## ChaCha20 (2026-08-08)

`chacha20` passes in both roles against quic-go, aioquic and picoquic,
`✓(C20)` each way. The quiche server pairing fails only in this VM:
its BoringSSL ChaCha20 misbehaves under qemu emulation (the
investigation and the diagnostic order worth reusing are in
docs/findings.md), and quiche's client does not attempt the case,
matching the public matrix.

How it is built: TLS_CHACHA20_POLY1305_SHA256 negotiation in tls.py
(both suites hash SHA-256, so one KeySchedule serves and tickets
resume across suites), suite-carrying `PacketKeys` in protection.py
with ChaCha20-Poly1305 AEAD and the §5.4.4 header protection mask
(sample as little-endian counter plus nonce), pinned to the RFC 9001
A.5 vectors including the key update secret. Initials stay AES
(§5.2). Tickets seal their suite, and early data is offered and
accepted only under it (§4.2.10). `ClientConfig.cipher_suites` is the
offer in preference order; the server takes the client's first suite
it speaks. `--chacha20` restricts the reference client, which is what
the shim passes for the case.

## ECN (2026-08-08)

**Acceptance criterion**, read from the runner's `TestCaseECN`: a
handshake plus one 100KB transfer; from the pcap, every QUIC packet
each side sends is marked ECT(0) or ECT(1) consistently, none is CE
(the simulator's path does not mark), and each side sends at least one
ACK-ECN frame. SSLKEYLOGFILE is required or the case reports
unsupported. frames.py already parses and encodes ACK-ECN
(`Ack.ecn: EcnCounts`, type 0x03), so the work is counting, marking,
validation, and the sockets.

**Order of work, each step gated on the one before:**

1. Done: `datagram_received` grew an `ecn` codepoint argument
   (endpoint-supplied; the core never reads IP headers). Each space
   counts ECT(0), ECT(1) and CE per successfully processed packet
   (§13.4.1, coalesced packets each count under their datagram's
   codepoint), `_build_ack` echoes nonzero counts through `Ack.ecn`,
   and qlog flattens the counts onto ack frame details (events §8.5),
   which is what the test observes.
2. Done: every `OutgoingDatagram` carries ECT(0) until validation
   fails (`_ecn_enabled`, per connection). `_validate_ecn` on each
   ACK: marking stops when a new acknowledgement carries no counts,
   when reported counts regress, or when ECT(1) appears, which
   nothing here sends; a CE increase calls the controller's new
   `on_ecn_ce` (RFC 9002 §7.1, once per recovery period per B.6).
   Deliberately not implemented: the ect0-plus-ce-versus-newly-acked
   comparison, which needs per-packet mark bookkeeping and defends
   against a peer inflating counts, not against bleaching; noted here
   so the omission is a decision rather than an accident.
3. Done: `enable_ecn` turns on IP_RECVTOS / IPV6_RECVTCLASS,
   `wait_for_readable` reads the codepoint from recvmsg ancillary
   data into `datagram_received`, and `send_pending` stamps each
   datagram's `OutgoingDatagram.ecn` via IP_TOS / IPV6_TCLASS before
   sendto. Platform findings, probed before writing: macOS loopback
   carries TOS both ways in both families (IPv4 delivers one byte,
   IPv6 a native-endian int, so `_ecn_of` handles both shapes), but
   macOS refuses the IPv4 options on a dual-stack AF_INET6 socket
   while Linux accepts and needs them for v4-mapped peers, so the
   dual-stack path sets them EAFP. The loopback test proves marks
   cross the kernel: ACK-ECN counts in the qlog traces of a real UDP
   fetch, which stay zero unless the marks arrived.
4. Done: the shim claims `ecn`, and the runner passes it in both
   roles against picoquic, `✓(E)` each way, the checker reading ECT
   marks and ACK-ECN frames of both directions from the pcap. quic-go,
   aioquic and quiche report `?(E)`: their interop images do not mark,
   so the runner deems those pairings unsupported rather than failed,
   matching the public matrix. The runner keeps no logs for
   unsupported verdicts, so only the picoquic pcaps exist for the
   wire check.

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

## Next steps

1. **Finish the QUIC protocol work before starting HTTP/3.** Remaining
   runner cases: `connectionmigration`, plus the `rebind-port` and
   `rebind-addr` pair that exercises the same path machinery from the
   server side. Version negotiation's client side is done to its
   applicable rung. That migration cluster is what stands between
   here and HTTP/3.
2. **HTTP/3 after that** (design.md §6.1). The largest piece and the one
   that unblocks MASQUE, since `h3.py` is a stub and carries the last
   open MASQUE readiness constraint. `h3.py` is written against a
   transport `typing.Protocol` rather than against `Connection` (see the
   design.md appendix), which specifies three gaps to close first:
   `open_stream` cannot ask for a unidirectional stream, there is no
   `reset_stream` or `stop_sending` for request cancellation (RFC 9114
   §4.1), and there is no datagram send for RFC 9221.
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

## Open decisions

See design.md §7. Still open: whether to add an asyncio transport over
the sans-IO core, PyPI publication, the v1 MASQUE surface (CONNECT-UDP
only vs. CONNECT-IP alongside), and SNI-selected certificate chains
(decide in the MASQUE phase). preferred_address was settled in scope
on 2026-08-08 by the runner's own definition of connectionmigration. 0-RTT was settled in scope
on 2026-08-07 with freshness-based anti-replay; everything settled so
far is recorded in the design.md appendix.
