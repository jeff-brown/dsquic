# dsquic: Design Guidelines

*A readable, spec-faithful QUIC / MASQUE / HTTP-3 implementation in pure Python.*

---

## 1. Name

**`dsquic`**: repo, import name, and (probable) distribution name.

- Rejected `pydsq`. The `py` prefix conventionally signals *bindings to a non-Python thing* (`pycurl`, `pyserial`, `pyOpenSSL`, `pylibsrtp`). A native implementation has nothing to disambiguate from, so the prefix is noise. Compare Jeremy Lainé's own split: `pylibsrtp` (bindings) vs. `aioquic` (native, no prefix).
- Rejected bare `dsq`: taken on PyPI (baverman's Redis task queue, which also imports as `dsq`). Also unpronounceable.
- `dsquic` reads as a word, keeps the "dead simple QUIC" derivation, and avoids the collision.

---

## 2. Thesis and motivation

**Primary goal: understanding.** The spec teaches what the protocol *is*; implementing by hand teaches what the spec *doesn't say*: how to structure bookkeeping across three packet number spaces, where PTO arming logic wants to live, why CRYPTO reassembly is independent of stream reassembly. That knowledge is the actual deliverable, and it's the prerequisite for credibly arguing about QUIC adoption in a WIT-area room.

**Secondary thesis: QUIC adoption is limited by complexity and opacity.** Worth keeping two kinds of opacity distinct:

| | What it means | What dsquic does about it |
|---|---|---|
| **Source opacity** | Five-RFC braid; dense implementations | Directly addressed: readability *is* the product |
| **Wire opacity** | No `tcpdump` readability, no `ss -i` for live cwnd/RTT, CID-aware LBs, UDP-hostile firewalls | Addressed only indirectly, via tooling built *on* dsquic later |

Ops people read captures and dashboards, not implementations. The long-term payoff is dsquic as an **inspection engine**: pcap + keylog in, RFC-section-cited narrative out ("this packet was dropped by the amplification limit"; "this ACK range triggered this retransmit"). Wireshark shows fields; a readable implementation can show *reasoning*.

**Why Python:** ops are already comfortable in it. `quic-go`, `quiche`, and `picoquic` are not languages the target audience will read casually.

---

## 3. Positioning vs. aioquic

The first question anyone will ask. Defensible differentiators:

- **Pure Python in the entire protocol path**, including buffers and packet number handling; accept an order of magnitude in performance. aioquic leans on a C extension in the packet path, so the parts most worth reading are the parts you can't.
- **An explicit RFC-to-module mapping** (flat modules, one concern per module, every docstring citing the sections it implements), rather than the mapping being left as an exercise.
- **MASQUE (CONNECT-UDP, CONNECT-IP) as a day-one design input**, not a layer bolted onto an H3 stack that never anticipated it.
- **Explicit state machine tables** rather than conditionals scattered across thousand-line files.

Checked in August 2026, and stronger than expected on the first point. Python has no standalone sans-IO HTTP/3 or QPACK library: the options are aioquic and qh3, and qh3 is a fork of aioquic, so it is one lineage rather than two. Neither packages h3 separately from the transport; qh3's package is `quic/`, `h3/`, `tls.py` and `asyncio/`, so taking its h3 means taking its QUIC, its TLS and its event model.

Nor is QPACK packaged by anyone, which is the telling asymmetry: HTTP/2 has `hpack`, a pure-Python sans-IO header codec, and HTTP/3 has no equivalent. aioquic delegates QPACK to `pylsqpack`, a C binding to ls-qpack; its own issue on the question framed the choice as wrapping C or writing pure Python, called the latter "more debugable but probably more work", and took the wrapper (https://github.com/aiortc/aioquic/issues/15). qh3 goes further in the same direction: a Rust extension holds not only crypto but `packet.rs`, `buffer.rs`, `rangeset.rs`, `recovery.rs`, `stream_sender.rs` and `headers.rs`, which is to say packet parsing, buffers, ACK ranges, loss recovery and header compression.

The direction of travel in that lineage is therefore *more* compiled code in the protocol path, not less, and the modules it has moved out of Python are precisely the ones this project writes out longhand. A readable pure-Python QPACK is a gap in the ecosystem rather than a wheel being reinvented, and it is the part of HTTP/3 a Python reader is least able to inspect today.

---

## 4. Core design principles

1. **Readability > completeness > spec adherence > performance.** Performance is an explicit non-goal. Reference implementation in the picoquic tradition.
2. **Sans-IO core.** The protocol engine takes bytes and returns bytes. No I/O in the state machines.
3. **No asyncio initially.** asyncio is the main way Python becomes unreadable. A reader should follow a packet from parse to frame handling to state change without ever chasing an event loop. An async transport layer can wrap the core later.
4. **qlog as a first-class output**, not an afterthought. This is what buys the tooling and dashboard story later.
5. **Explicit RFC citation in code.** Section references in docstrings/comments; the mapping is part of the pedagogy.
6. **Reference client and server are part of the deliverable.** The library alone is not the product; `endpoints/client.py` and `endpoints/server.py` are reference endpoints that exercise every protocol code path and interop cleanly with other QUIC implementations. The `endpoints/` subpackage is the package's only I/O boundary, kept synchronous and readable, and it is the surface the Interop Runner drives. A protocol feature is not done until it is reachable from both endpoints.
7. **Don't optimize, but don't foreclose optimization.** Performance is a non-goal; unoptimizability is not. Optimizing makes the code worse: keep refusing it. Not foreclosing optimization is nearly free at the type and interface level. The rule: if it determines the bytes, or when they are due, it is core; if it determines how those bytes reach the kernel, it is I/O. Expanded in §4.7 below.
8. **Edge-case convention (decided): state inline, validation quarantined.** The spec's complexity lives in loss recovery, ACK range coalescing, flow control accounting, key update, stateless reset, and ECN validation: exactly the parts that turn readable code into a thicket. The convention, applied consistently everywhere: any edge case that mutates state or changes subsequent behavior (RTT sampling conditions, ACK-delay capping, loss thresholds, key-phase transitions) is handled *inline*, in spec order, with its RFC citation; interacting state is the pedagogical payload and is never hidden behind a name. Pure reject-and-raise validation (ACK of an unsent packet number, a frame type illegal in its packet type, malformed encodings) may be *quarantined* into named, cited validators. The rule is testable at review time: if handling it can only raise, it may be extracted; if it changes what happens next, it stays inline. Consistency is worth more than any individual module.

### 4.7 Don't optimize, but don't foreclose optimization

There is a difference between optimizing (makes code worse: keep refusing) and not foreclosing optimization (nearly free at the type and interface level). The distinction that matters:

> If it determines the bytes, or when they're due, it's core. If it determines how those bytes reach the kernel, it's I/O.

The structural reason: AEAD sealing plus header protection make a datagram byte-final. Once the core emits it, the transport cannot repack, resize, split, or coalesce it, unlike TCP, where the kernel is free to re-segment whatever you write. So every decision affecting batchability is unavoidably a core decision.

Core / library design decisions:

| Decision | Why it can't be deferred |
|---|---|
| Packet sizing and padding policy | Byte-final datagrams; transport can't resize. UDP GSO needs N segments of identical size plus optionally a smaller tail; a natural mix of sizes makes GSO unusable no matter how clever the transport is |
| Packet coalescing into datagrams | Decided at build time or not at all |
| ECN codepoint on send; per-datagram ECN on receive | Correctness, not performance. ECN is per-datagram on send and arrives via cmsg on receive; QUIC's ECN validation logic is core. Without it in the interface from commit one, dsquic can say nothing about L4S |
| Send output as an extensible record | Adding dataclass fields is backward compatible; changing tuple arity is a refactor across every call site |
| Receive input as a list of datagrams, each independently marked | Lets a GRO-capable transport split a coalesced buffer without the core knowing GRO exists |
| Timer deadline API (`next_timer() -> float \| None`) | A deadline lets the transport coalesce timers across connections and sleep properly. A polling model burns syscalls no transport can claw back |
| Pacing rate from the CC | Core computes it; transport chooses sleeps vs. `SO_TXTIME` |
| CID parsing exposed for demux | Transport needs it to route; the sharding itself is I/O |
| Buffer ownership seam | Only item with a real readability cost. Allocate freely for now, but do it in one place so the seam exists even if never used |

Minimum viable shape for the send record:

```python
@dataclass
class OutgoingDatagram:
    data: bytes
    destination: Address
    ecn: ECNCodepoint  # required from day one
    txtime: int | None = None  # SO_TXTIME / pacing offload
    segment_size: int | None = None  # GSO hint
```

Safe to leave entirely in the I/O layer: socket setup and sockopts (`UDP_SEGMENT`, `IP_TOS` / `IPV6_TCLASS`, GRO, `SO_TXTIME`); `sendmmsg` / `recvmmsg` batching; io_uring, SQPOLL, registered buffers; buffer pooling and recycling; thread/process model and `SO_REUSEPORT` sharding; kernel feature detection and fallback.

None of that should ever appear in a file with "frame" or "packet" in the name. If it starts to, that's a design smell rather than an optimization.

Note on Python io_uring options (should a fast transport ever be wanted): no stdlib support; CPython GH-88901, proposing an io_uring backend for selectors/asyncio, has been open since 2021 and gone nowhere; uvloop doesn't help (libuv uses io_uring for filesystem ops, not sockets). Available: `liburing` on PyPI (CFFI wrapper, low-level, stable since 2020) and `uringcore` (Rust/PyO3 drop-in asyncio loop, Linux 5.11+, but 0.9.x and very new). Note also that for QUIC the bigger syscall wins are usually UDP GSO/GRO and `sendmmsg`/`recvmmsg`, reachable from plain `socket.sendmsg` with cmsgs, and that io_uring has a poor kernel-security record (disabled on Android/ChromeOS, restricted on GKE), which is likely a conversation before it's a deployment.

---

## 5. Crypto and the TLS boundary

### 5.1 What to delegate

Use **`cryptography`** for raw primitives: AEAD (AES-GCM, ChaCha20-Poly1305), HKDF, signatures, X.509 path validation. The internals of AES-GCM teach nothing about QUIC.

**`pyOpenSSL` cannot be used for the TLS handshake.** QUIC requires a TLS stack exposing a non-record-layer interface: hand me handshake bytes, notify me when a secret is available at each epoch (BoringSSL's `SSL_set_quic_method`, or OpenSSL's QUIC-TLS API for external stacks). pyOpenSSL wraps the BIO-based connection API and exposes none of it. `cryptography` does no TLS at all. This is precisely why aioquic ships a hand-written `tls.py`.

### 5.2 Consequence: hand-written TLS 1.3, tightly scoped

Forced, but smaller than it sounds once scoped to what QUIC actually needs:

- No record layer, no renegotiation, no version fallback, minimal cipher suite set
- 1-RTT, plus 0-RTT if/when in scope
- A message-level state machine over ~6 handshake messages
- Everything cryptographic delegated to `cryptography`

The TLS that gets written is the TLS that's pedagogically load-bearing anyway.

### 5.3 The seam (the module to point an ops person at first)

> **TLS 1.3 supplies the handshake transcript, authentication, and key schedule. QUIC supplies its own record layer.**

The interface is small:

```
QUIC -> TLS:  handshake bytes received at encryption level L (from CRYPTO frames)
              peer's transport parameters extension

TLS  -> QUIC: handshake bytes to send at level L (into CRYPTO frames)
              secret available: (level, direction, secret, cipher_suite)
              handshake complete / handshake confirmed
              alert -> CONNECTION_CLOSE 0x0100 + alert
```

**The handoff point is exact.** TLS's key schedule runs identically to TCP and produces the same traffic secrets (`client_handshake_traffic_secret`, `server_application_traffic_secret_0`, ...). Over TCP those feed HKDF-Expand-Label with `"key"` / `"iv"` to key the record layer. QUIC intercepts one step earlier and derives its own with `"quic key"`, `"quic iv"`, and a third with no TLS analogue: `"quic hp"`. Same secrets, different labels; everything downstream is QUIC's.

### 5.4 Four things to write out longhand

- **Initial keys don't come from TLS at all.** `HKDF-Extract(fixed_salt, client_DCID)`, then `"client in"` / `"server in"`. Anyone on path can compute them: Initial protection is anti-ossification and integrity, *not* confidentiality. Worth a comment block; it surprises ops people every time.
- **Nonce is `iv XOR packet_number`**, left-padded. Not an implicit AEAD counter. Packet numbers are explicit, monotonic per space, and may skip, which is why QUIC retransmits *data* without retransmitting a packet number.
- **AAD is the full header including the unprotected PN**, then header protection is applied over the result, sampling 16 bytes of ciphertext. Encrypt = AEAD-then-HP; decrypt = HP-then-AEAD. The PN can't be parsed until HP is removed, which is why the sampling offset assumes a 4-byte PN field. This ordering dependency is the most confusing thing in RFC 9001 and is roughly forty lines when nothing hides it.
- **Key update is QUIC's, not TLS's.** `"quic ku"` applied to the old secret, signalled by the key phase bit. TLS's own KeyUpdate message is forbidden. The hp key deliberately does *not* rotate.

---

## 6. Interoperability strategy

Interop is a design input, not a validation phase. Build client and server incrementally to the point where a `quic-go` client talks to a `dsquic` server and vice versa.

**Sequence: `quic-go` to get it working, `picoquic` to find out what you got wrong.**

- **quic-go (Marten Seemann)**: best *first* target. Legible failures: precise transport error codes with reasons, first-class qlog on both ends. Marten maintains the QUIC Interop Runner, making quic-go the de facto reference point. Test suite recently rewritten from Ginkgo to standard Go testing, so it's approachable when you need to read what quic-go expects of you.
- **picoquic (Christian Huitema)**: the conformance ratchet, and the more spec-*pure* of the two. Purpose-built as a reference and used to validate spec text as it was written; covers corners production stacks skip (migration, path validation, spin bit, key update, stateless reset, ECN) and is strict about them. Caveat: it's a research vehicle and therefore a *superset* of the RFCs, with experimental extensions and draft implementations well ahead of publication.
- **aioquic**: the debugging superpower. When stuck, breakpoint both endpoints in the same language and debugger.

**Where quic-go and picoquic disagree, that's the paper.** Two high-quality implementations by spec authors diverging on the same RFC text is far stronger evidence for the complexity thesis than any assertion about ops comfort.

### 6.1 Roadmap = the Interop Runner test cases

Wire into the runner's client/server interface early (a thin shim). Every milestone then gets validated against a dozen stacks rather than one:

`handshake` -> `transfer` -> `retry` -> `resumption` -> `multiplexing` -> `http3` -> `keyupdate` -> `ecn` -> `zerortt`

HelloRetryRequest is not one of the runner's cases but is inserted after `transfer`, for the reason given below.

Two milestones arrived out of this order because interop forced them, which is the roadmap working as intended rather than a departure from it. Version Negotiation came first of all: the simulator's readiness probe offers an unknown version specifically to elicit a VN packet, so nothing at all ran until dsquic answered it. `keyupdate` came next, because RFC 9001 §6.2 makes responding to a peer's key update mandatory, and quic-go updates keys mid-transfer; without it `transfer` itself could not pass. Responding is implemented and validated, and initiating followed: `ConnectionConfig.key_update_interval` starts a new phase after so many packets, which is what the `keyupdate` case needs for the client role.

Also note ECN validation is one of QUIC's more commonly botched corners: a trustworthy reference for correct ECN counting has value well beyond the pedagogical case.

Added after the first interop run: **HelloRetryRequest, and the post-quantum ClientHello.** Go 1.24 and later enable the hybrid group `X25519MLKEM768` by default, so quic-go's ClientHello carries a 1258-byte key_share and runs 1506 bytes in total, spanning four CRYPTO frames across two datagrams. Chrome and Firefox default to the same group. Two consequences:

- A multi-packet ClientHello is now ordinary traffic rather than an edge case. For QUIC's entire pre-PQ history a ClientHello fit in one Initial, which is why ignoring the CRYPTO frame offset was a bug that could survive every other form of testing. This is the strongest single argument for interop as a design input rather than a validation phase.
- HelloRetryRequest is closer than the MVP scope assumed. Refusing it is safe while dsquic offers only x25519 as a client, and safe as a server against peers that speculatively send an x25519 share alongside their PQ one (quic-go does). A client offering *only* a PQ group would need an HRR from us and would fail. HelloRetryRequest therefore moves onto the roadmap ahead of the remaining interop cases, since it is a correctness gap against real deployed defaults rather than a missing feature.

### 6.2 Verification ladder

Every protocol milestone climbs three rungs, in order:

1. **Unit tests**, including spec-derived vectors wherever the RFC provides them (varint examples in RFC 9000 Appendix A; the complete packet protection vectors in RFC 9001 Appendix A).
2. **Loopback**: dsquic against dsquic through `endpoints/client.py` and `endpoints/server.py` over real UDP. In-memory driving of the sans-IO core is a permitted half-step for state machines that predate the working transport (the TLS handshake).
3. **Interop, in both directions**: dsquic client against another stack's server and that stack's client against the dsquic server, via the Interop Runner test case for the feature.

A rung is skippable only while it is not yet applicable (wire encoding has no loopback story; nothing interops before the stack can complete a handshake), never because it is inconvenient. Once applicable, a rung is mandatory, and results are reported by the rung they reached: loopback success is loopback success, never interop.

### 6.3 MVP sequence

1. `buffer.py` varints (RFC 9000 §16, Appendix A vectors)
2. `packet.py` header parse/serialize plus `protection.py` Initial keys, verified byte-exact against RFC 9001 Appendix A
3. `tls.py` handshake, dsquic against dsquic in memory
4. `connection.py`, `recovery.py`, `streams.py`, `hq.py`: loopback file transfer over real UDP via the endpoints
5. Interop gate, the definition of MVP done: `handshake` and `transfer` against quic-go, both directions

Each step is a gate: the next phase starts only after the previous phase passes every applicable rung of §6.2, the work is committed, and, for the wire-facing phases (3 onward), the wire format has been independently verified from a capture (tcpdump/Wireshark, decrypted via SSLKEYLOGFILE).

---

## 7. Open questions

- [x] Edge-case convention: decided, state inline / validation quarantined (§4.8)
- [x] Module layout: decided, flat modules; the TLS-shim/packet-protection line is drawn as `tls.py` / `protection.py` (see appendix)
- [x] 0-RTT: decided 2026-08-07, in scope; freshness-based anti-replay
      (see appendix)
- [ ] When (and whether) to add an asyncio transport layer over the sans-IO core
- [ ] PyPI distribution name: publish as `dsquic`, or stay git-install only for the academic phase?
- [ ] Whether `h3.py` and `qpack.py` ever ship as separate artifacts usable with other QUIC implementations. Only the packaging is open: the dependency discipline that keeps it possible is settled and enforced (see appendix).
- [ ] MASQUE surface for v1: CONNECT-UDP only, or CONNECT-IP alongside?
- [x] `preferred_address` (RFC 9000 §9.6): decided 2026-08-08, in scope, settled by reading the runner's source: its `connectionmigration` case tells the *server* to offer a preferred address and expects an ordinary client to follow it with path validation, so the feature is the migration phase's centerpiece rather than an optional extension.
- [ ] Multiple certificate chains, selected by SNI: an endpoints/ServerConfig feature, not handshake work. Becomes real when one server fronts several origins, so decide in the MASQUE phase. HTTP-layer secondary certificate authentication (RFC 9261 exported authenticators) stays out of scope unless CONNECT work demands multi-origin authority proofs.

---

## Appendix: decisions taken at scaffold time (2026-07-26)

Recorded here so the open questions above stay honest:

- **Module layout: flat modules** (aioquic-style), one module per concern under
  `src/dsquic/`, RFC mapping in each module's docstring and in the package
  docstring. This partially answers the "module layout" open question; the
  TLS-shim/packet-protection line is drawn as `tls.py` (secrets out) /
  `protection.py` (QUIC key derivation and AEAD/HP in), per §5.3.
- **Packaging**: `pyproject.toml` with hatchling; `uv` for environments and
  locking; `ruff` (lint + format, including pylint rules), strict `mypy`,
  `pytest`.
- **Python**: 3.12+.
- **Full skeleton stubbed day one**: every planned module exists with a
  docstring stating its RFC sections; `tests/` mirrors the module tree and
  `tests/test_scaffold.py` enforces the mirror.
- **Working conventions live in `CLAUDE.md`** (style, engineering, and
  typing rules); session-to-session status lives in `STATE.md` at the repo
  root, updated at the end of every session.
- **Reference endpoints live in the package** under the `endpoints/`
  subpackage (`endpoints/client.py`, `endpoints/server.py`), the package's
  only I/O boundary (§4.6). Revised 2026-07-26 from flat placement so the
  sans-IO seam is structural rather than a named-file exception. The
  `interop/` shim wraps them rather than implementing its own endpoints.
- **hq-interop lives in core (2026-07-26)** as `hq.py`: sans-IO request and
  response semantics for the Interop Runner's `hq-interop` ALPN (HTTP/0.9
  lineage, no RFC). Endpoints select the application protocol by negotiated
  ALPN (`hq.py` now, `h3.py` later); file and socket handling stay in
  `endpoints/`.
- **SSLKEYLOGFILE support is a phase requirement, not a later feature
  (2026-07-26)**: `tls.py` exposes a keylog callback emitting NSS Key Log
  Format lines; the endpoints write them to the path named by the
  `SSLKEYLOGFILE` environment variable, the same contract the Interop
  Runner uses. Required from the TLS phase (§6.3 step 3) onward so wire
  captures can be decrypted in Wireshark for independent verification
  between phases.
- **Version handling is layered per RFC 8999 (2026-07-26)**: parsing reads
  only the version-independent prefix (first bit, version, connection IDs)
  before checking the version; anything else, notably the type bits that
  RFC 9369 remaps for v2, is interpreted only for v1. Unknown and greased
  versions (RFC 9000 §15) raise `UnsupportedVersion`, the hook a server
  uses to send Version Negotiation. Grease tolerated from peers as the
  relevant parsers land: reserved transport parameters and frame types
  (31N+27) are ignored, never rejected. RFC 9287 (greasing the fixed bit)
  is post-MVP; the fixed bit is required until then. full
  X.509 path validation plus hostname verification (RFC 9525 DNS-ID
  matching against SNI), both delegated to `cryptography`'s verification
  API per §5.1. An explicit insecure flag on the client endpoint disables
  validation for debugging; it is never the default and never used in
  interop or conformance claims.
- **Edge-case convention settled (2026-07-26)**: state inline, validation
  quarantined (§4.8), chosen over fully-inline and fully-quarantined.
- **MVP interop reached (2026-07-29)**: `handshake` and `transfer` pass
  against quic-go v0.61 in both directions, and against aioquic 1.3 in
  both directions, over hq-interop on real UDP. This is §6.3 step 5, the
  recorded definition of MVP done. The peers are driven by thin harnesses
  in `tests/interop/`; all protocol behaviour on the far side is theirs.
  Interop found one bug that four layers of self-testing had not: CRYPTO
  frame offsets were ignored, so a ClientHello spanning several frames
  was reassembled by concatenation. dsquic and aioquic both send small,
  in-order ClientHellos; quic-go does not.
- **MASQUE nesting readiness (2026-07-26)**: MASQUE tunnels a complete
  inner QUIC connection (with its own ordinary TLS handshake) through an
  outer connection as HTTP Datagrams; the nesting is at the QUIC packet
  layer, and the proxy never terminates inner TLS. Four commitments keep
  this from requiring a later refactor, checked before `connection.py`,
  the endpoint loop, and the `h3.py` API are considered done:
  1. `connection.py` is transport-agnostic: consumes datagrams, emits
     `OutgoingDatagram` with an abstract destination, never assumes a
     socket; an inner connection's transport can be an outer
     connection's datagram surface.
  2. No hardcoded MTU or payload-size constants in the core; packet
     sizing is per-connection configuration (tunneled connections have
     reduced effective MTU; the client Initial 1200-byte floor
     interacts with outer datagram capacity).
  3. The endpoint loop handles N concurrent connections, including
     connections whose sends route into another connection rather than
     the socket. **Satisfied 2026-07-29** by `endpoints.server.Server`,
     which routes on the Destination Connection ID read by
     `packet.destination_connection_id`. That function is the "CID
     parsing exposed for demux" commitment of §4.7, and reads only the
     version-independent fields of RFC 8999 §5.1, so routing works even
     for versions the stack cannot speak.
  4. `h3.py` models long-lived Extended CONNECT streams with associated
     datagram flows, not request/response calls; DATAGRAM frames
     (RFC 9221) are in the frame vocabulary and transport parameter
     set, parse-side at minimum, from first implementation.
  Already satisfied by construction: tls/protection/packet are
  instance-scoped and nesting-neutral; the §4.7 interfaces (abstract
  destinations, per-datagram receive, deadline timers) are the enablers.
- **Congestion control is pluggable (2026-07-26)**: `congestion.py` defines
  the controller interface using the RFC 9002 §7 event vocabulary (packet
  sent, packets acked, packets lost, persistent congestion) plus congestion
  window and pacing rate (per §4.7). Implementations get one module each,
  `new_reno.py` (RFC 9002 §7, Appendix B) being the baseline and the MVP
  implementation; no stub controllers. Loss detection (§5-§6, `recovery.py`)
  is fixed and not pluggable.
- **PTO backoff is capped, and the idle floor uses the unscaled PTO
  (2026-08-03)**: RFC 9000 §10.1 floors the idle timeout at "three times
  the current Probe Timeout (PTO)". Read as the backed-off value, that
  floor recedes exactly as fast as the backoff grows and a connection
  that keeps losing probes never times out; one was observed probing at
  128-second intervals for over four minutes rather than failing. Both
  implementations dsquic interops with read it as the unscaled PTO
  (quic-go `rttStats.PTO(true)*3`, aioquic `3 * get_probe_timeout()`),
  so `LossDetection.pto()` carries no backoff and is what §10.1 and
  §10.2 multiply by three. The backoff is kept for arming timers and
  truncated at 60 seconds, per RFC 8961 §4 requirement 4 ("A maximum
  value MAY be placed on the RTO. The maximum RTO MUST NOT be less than
  60 seconds"), the same citation and constant quic-go uses. RFC 9002
  sets no ceiling of its own. picoquic instead bounds the number of
  retransmissions rather than the interval; that needs more state and
  has no QUIC-spec citation, so it was not taken.
- **h3.py and qpack.py stay liftable (2026-08-06)**: they import nothing
  from this package but `buffer`, the RFC 9000 §16 varint codec that
  RFC 9114 and RFC 9204 both build on. The transport reaches them through
  the Protocol above, and arriving data through method calls on the H3
  connection rather than as dsquic event types, so neither direction is
  an import. `qpack.py` needs no transport at all: it is a codec taking
  bytes and returning bytes, which is why §3 identifies it as the gap
  nobody in Python fills.
  Packaging is *not* decided and deliberately left alone (§7): there are
  no users, and splitting distributions would collide with the flat
  module layout. What is decided is the discipline that keeps the choice
  available, because the cost of adopting it now is nothing and the cost
  of retrofitting it is every call site. `tests/test_scaffold.py` asserts
  it, so the constraint fails a test rather than eroding quietly; an
  import of `connection.py` there is what ties every other Python HTTP/3
  stack to one QUIC implementation.
  Weigh against it, when the packaging question is finally answered: a
  published artifact acquires stability promises, which is the opposite
  of §4's "refactor over backward compatibility". A split promise, stable
  for the two codecs and fluid for the transport core, is coherent but is
  a commitment rather than a detail.
- **h3.py is generic over the transport, from before it exists
  (2026-08-06)**: `h3.py` is written against a `typing.Protocol` naming
  what HTTP/3 requires of a QUIC transport, not against `Connection`.
  Three things follow. The reader sees HTTP/3's whole demand on QUIC in
  one screen, which is the layering stated rather than implied. A test
  satisfies it with a dictionary of buffers, so h3 is testable without a
  handshake. And a second transport, QMux over TCP being the case in
  view, is another implementation of the Protocol rather than a fork,
  which is how every Python HTTP/3 stack has ended up entangled with one
  QUIC implementation (see §3).
  The surface is `open_stream(bidirectional=)`, `send_stream_data`,
  `reset_stream`, `stop_sending`, `send_datagram`, `close`, and
  `max_datagram_size`. Each entry cites the RFC 9114 clause that demands
  it, and nothing enters without one: a Protocol that mirrors whatever
  `Connection` happens to offer would buy nothing.
  Two things deliberately stay out. Incoming stream data and datagrams
  are events, a data vocabulary the h3 layer is fed, not calls it makes,
  which is what keeps a fake transport to a dictionary. And whether a
  stream ID is unidirectional or peer-initiated is arithmetic on the ID
  (RFC 9000 §2.1), so it lives in h3 as pure helpers rather than making
  every transport reimplement it.
  Writing it first turned out to specify work rather than describe it:
  `Connection.open_stream()` cannot express a unidirectional stream, and
  there is no request cancellation and no datagram send. Those are the
  transport gaps h3 needs closed.
  The open question is whether a transport without QUIC's stream model
  can satisfy it honestly. Unidirectional streams can be emulated over a
  bidirectional mux, but datagrams cannot be made unreliable over TCP, so
  `send_datagram` is where the abstraction either earns its keep or
  leaks. Recording it now so the answer is designed rather than
  discovered.
- **Retry lives in its own module, and the address never reaches the
  core (2026-08-06)**: `retry.py` holds the Retry packet (RFC 9000
  §17.2.5) and the address validation tokens (§8.1.2-§8.1.4); the Retry
  Integrity Tag stays in `protection.py`, since it is RFC 9001 §5.8 and
  AEAD is that module's concern. `packet.py` keeps the Retry dataclass
  but cannot read or write one: doing so needs the tag, and
  `protection.py` already imports `packet.py`, so the dependency runs one
  way only.
  A token binds the client's address, but the core never learns what an
  address is: `mint_token` and `validate_token` take opaque bytes and the
  endpoint decides how a socket address becomes them, which keeps §4.6's
  sans-IO line intact and leaves a MASQUE-tunnelled connection free to
  use something that is not an IP address at all. The token also carries
  the original destination connection ID, because a server that answers
  with a Retry keeps no state and §7.3 still requires it to echo that ID
  as a transport parameter; `ConnectionConfig.retry` is how the endpoint
  hands both back when the retried Initial arrives.
  Deciding to validate an address is policy and lives in the endpoint
  (`ServerOptions.retry`), because only the endpoint knows addresses;
  minting, checking, and the §7.3 comparison are protocol and live in the
  core.
- **Completion and confirmation are separate events (2026-08-06)**:
  RFC 9001 §4.1.1 makes 1-RTT data sendable once the TLS handshake is
  complete, while §4.1.2 confirmation is a later event that governs
  discarding Handshake keys (§4.9.2) and initiating a key update (§6.1).
  `connection.py` emits `HandshakeCompleted` and `HandshakeConfirmed`
  for the two, and the endpoints gate application data on the former.
  Collapsing them, which is what the code did first, made a client wait
  on HANDSHAKE_DONE before sending anything: that frame can be lost, and
  when it was, the client retransmitted Handshake CRYPTO for 38 seconds
  into a space the server had already discarded keys for while the
  server waited in 1-RTT for a request. Keeping the RFC's two names is
  also the clearer teaching artifact, since the distinction is one of
  the easier things to get wrong.
- **Address family follows the name (2026-08-06)**: both endpoints take
  the family from `getaddrinfo` rather than hardcoding `AF_INET`, so an
  AAAA-only host is reached over IPv6 with no flag. A server given an
  IPv6 bind address turns `IPV6_V6ONLY` off, serving IPv4 peers on the
  same socket as `::ffff:a.b.c.d`, rather than running two listeners:
  one socket keeps the demux path (§4.7's CID parsing for routing)
  single. Family selection is socket mechanics and stays in
  `endpoints/`; the core's destinations remain opaque.
- **Key update policy is configuration, the update itself is core
  (2026-08-06)**: `ConnectionConfig.key_update_interval` names how many
  packets a phase lasts, and the send path consults it and calls
  `initiate_key_update`, whose §6.1 preconditions (handshake confirmed,
  and the current phase acknowledged) can still refuse. That split
  follows §4.7's rule for what has to be core: *whether* an update
  happens changes the bytes on the wire, while *how often* is a
  deployment choice. The reference client exposes it as
  `--key-update-interval`; the interop shim passes 100 for the
  `keyupdate` case, the figure quic-go's interop client uses.
- **Sending is paced, and acknowledgements are exempt (2026-08-05)**:
  RFC 9002 §7.7 requires a sender to either pace or limit bursts; dsquic
  did neither, and emitted everything the congestion window allowed as
  fast as the loop could build it. `connection.py` now holds a leaky
  bucket filled at the rate the controller computes
  (`CongestionController.pacing_rate(smoothed_rtt)`, which NewReno
  derives as §7.7's `N * congestion_window / smoothed_rtt` with
  N = 1.25) and capped at ten datagrams, the initial congestion window
  (§7.7 "Senders SHOULD limit bursts to the initial congestion window",
  sized by B.1). The RTT is passed in because recovery owns it while the
  formula belongs to the controller: a rate-based controller derives it
  differently. The core withholds datagrams and reports the release time
  through `next_timer()` rather than stamping `txtime` on them; the §4.7
  table permits either, and withholding keeps the transport a plain
  sleep loop with no pacing logic of its own.
  §7.7 exempts packets carrying only ACK frames ("Timely delivery of ACK
  frames is important for efficient loss recovery"), so the builders take
  an `ack_only` path that stops after the ACK. That path also skips the
  congestion window, which fixed a separate defect: ACK-only datagrams
  were being suppressed by a full window, though RFC 9002 §2 does not
  count such a packet as in flight and §7 does not congestion-control it.
  A cwnd-blocked connection therefore stopped acknowledging exactly when
  its peer most needed acknowledgements to make progress.
- **qlog is emitted in the sequential JSON-SEQ format (2026-08-05)**:
  `qlog.py` writes `urn:ietf:params:qlog:file:sequential`, media type
  `application/qlog+json-seq`, declaring the event schema as
  `urn:ietf:params:qlog:events:quic-13` (both documents are still
  Internet-Drafts: main-schema-14 and quic-events-13, and events §2.1
  requires the draft number to be appended until publication). The
  sequential form was chosen over the contained one because it streams:
  a record is appended and flushed per event, so a stalled connection can
  be read while it is still stalled, and nothing has to be buffered until
  close. quic-go emits the same family, and design.md §6.1 already treats
  it as the reference point; aioquic still emits the legacy contained
  0.3 format. The Interop Runner reads qlog for no test case, so this
  choice is driven by the inspection-engine goal of §2 rather than by
  interop. The event set is chosen for debugging value, not coverage:
  `packet_dropped` first, because a silently discarded packet leaves no
  trace on the wire, and every drop path in the receive loop reports one
  with the §5.7 trigger that names its reason. Following §4.2, the core
  emits and the `endpoints/` subpackage owns the files named by QLOGDIR,
  the same split SSLKEYLOGFILE uses; `ConnectionConfig.qlog` is a factory
  rather than a trace because the group ID is the original destination
  connection ID, which a server only learns from the client's first
  Initial. On tooling: qvis implements qlog draft-02 only (its schema
  files stop at `QlogSchema02.ts`) and so understands the older
  `transport:`/`recovery:`/`security:` event names, not the `quic:`
  namespace the current drafts define; it parses our traces but renders
  little of them. pmeenan/waterfall-tools, which is maintained, reads
  both dialects and both serializations, and consumes exactly the fields
  emitted here (`header.packet_type`, `raw.length`, `initiator`). The
  current names are therefore kept: matching a stale tool would mean
  emitting a vocabulary no draft has defined since 2021, and quic-go's
  own traces are already inconsistent on this point, declaring
  `events:quic-12` while emitting draft-02 names. Two further points
  live here rather than in the code. The header carries the pre-URI
  `qlog_version` and `qlog_format` fields alongside the current ones,
  because readers that predate the URI scheme reject a file without
  them outright, which is how qvis first refused these traces. And the
  reference time carries a `wall_clock_time`: a monotonic clock has no
  meaningful epoch, so without an anchor a reader cannot place the
  trace on a real timeline or lay a client trace over a server one.
  Supplying it is I/O, so it comes from `endpoints/`.

- **0-RTT is in scope, with freshness-based anti-replay (2026-08-07).**
  Settled when resumption passed the Interop Runner in both roles.
  Scope: early application data on resumption (RFC 9001 §4.6): the
  ticket announces `early_data` with the mandatory 0xffffffff (§4.6.1),
  the client remembers the server's transport parameters alongside the
  ticket and observes the remembered limits until the handshake
  delivers fresh ones (RFC 9001 §7.4.1), 0-RTT packets are protected
  with `client_early_traffic_secret`, and the server accepts or rejects
  with the client falling back to resending the same data in 1-RTT.
  NEW_TOKEN (RFC 9000 §8.1.3) rides along, so a resuming client also
  presents an address validation token. Anti-replay is the freshness
  check of RFC 8446 §8.3, the only mechanism of §8 compatible with the
  stateless sealed-ticket design: the sealed ticket carries its issue
  time and `age_add`, the server compares the client's claimed ticket
  age against the actual age, and a claim outside the window downgrades
  0-RTT to 1-RTT rather than aborting. Single-use tickets (§8.1) and
  ClientHello recording (§8.2) are deliberately not used because both
  reintroduce the per-ticket server state the sealed-ticket decision
  removed. The teaching note, which belongs in module docstrings where
  it applies: stateless 0-RTT accepts bounded replay, which is why only
  idempotent application data (hq GETs) is ever sent early, and why
  RFC 9001 §9.2 forbids carrying anything replay-sensitive in it.
