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
- **One module per RFC section**, with the mapping made explicit rather than left as an exercise.
- **MASQUE (CONNECT-UDP, CONNECT-IP) as a day-one design input**, not a layer bolted onto an H3 stack that never anticipated it.
- **Explicit state machine tables** rather than conditionals scattered across thousand-line files.

---

## 4. Core design principles

1. **Readability > completeness > spec adherence > performance.** Performance is an explicit non-goal. Reference implementation in the picoquic tradition.
2. **Sans-IO core.** The protocol engine takes bytes and returns bytes. No I/O in the state machines.
3. **No asyncio initially.** asyncio is the main way Python becomes unreadable. A reader should follow a packet from parse to frame handling to state change without ever chasing an event loop. An async transport layer can wrap the core later.
4. **qlog as a first-class output**, not an afterthought. This is what buys the tooling and dashboard story later.
5. **Explicit RFC citation in code.** Section references in docstrings/comments; the mapping is part of the pedagogy.
6. **Decide the edge-case convention once, up front.** The spec's complexity lives in loss recovery, ACK range coalescing, flow control accounting, key update, stateless reset, and ECN validation: exactly the parts that turn readable code into a thicket. Every edge case is either handled *inline* (readable but noisy) or *quarantined behind a well-named boundary* (clean but hides what the reader came for). Pick one convention and apply it consistently; this is worth more than any individual module.

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

Also note ECN validation is one of QUIC's more commonly botched corners: a trustworthy reference for correct ECN counting has value well beyond the pedagogical case.

---

## 7. Open questions

- [ ] Edge-case convention: inline vs. quarantined behind a boundary (§4.6); decide before writing loss recovery
- [ ] Module layout, specifically the line between the TLS shim and the packet protection layer; hardest decision to walk back
- [ ] 0-RTT: in the MVP scope, or deferred?
- [ ] When (and whether) to add an asyncio transport layer over the sans-IO core
- [ ] PyPI distribution name: publish as `dsquic`, or stay git-install only for the academic phase?
- [ ] MASQUE surface for v1: CONNECT-UDP only, or CONNECT-IP alongside?

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
