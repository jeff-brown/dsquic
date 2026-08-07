# dsquic

A readable, spec-faithful QUIC / MASQUE / HTTP-3 reference implementation in
pure Python. The name derives from "dead simple QUIC".

dsquic exists to teach. The QUIC RFCs describe what the protocol is; a
readable implementation shows what the spec leaves unsaid: how bookkeeping is
structured across three packet number spaces, where PTO arming logic lives,
why CRYPTO reassembly is independent of stream reassembly. The code is the
deliverable, in the picoquic tradition of reference implementations, written
in the language operations people already read.

**Status: pre-alpha.** The package layout, tooling, and RFC-to-module mapping
are in place; protocol logic is not yet implemented.

## Design principles

Priorities, in order: readability > completeness > spec adherence >
performance. Performance is an explicit non-goal.

- **Sans-IO core.** The protocol engine takes bytes and clock readings in and
  returns bytes, deadlines, and events out. No sockets, threads, or asyncio
  in the protocol path. A reader follows a packet from parse to frame
  handling to state change without chasing an event loop.
- **Pure Python end to end.** No C extensions anywhere in the protocol path,
  including buffers and packet number handling. The only dependency is
  `cryptography`, used for raw primitives (AEAD, HKDF, signatures, X.509).
  The TLS 1.3 handshake itself is hand-written and tightly scoped, because
  QUIC requires a TLS stack with a non-record-layer interface that no
  existing Python TLS binding exposes.
- **Explicit RFC citation.** Every module docstring states the RFC sections
  it implements; nontrivial functions cite the section they encode. The
  RFC-to-code mapping is part of the product.
- **Explicit state machines.** Named state tables and enums, not conditionals
  scattered across thousand-line files.
- **qlog as first-class output.** Protocol modules emit structured events as
  they happen. This is the foundation for the longer-term goal: dsquic as an
  inspection engine that turns a capture and keylog into an RFC-section-cited
  narrative of what happened on the wire.
- **MASQUE as a day-one design input.** CONNECT-UDP proxying is part of the
  HTTP/3 layer's contract from the start, not a later bolt-on.
- **Reference client and server are part of the deliverable.**
  `endpoints/client.py` and `endpoints/server.py` are synchronous endpoints
  that drive the sans-IO core, exercise every protocol code path, and
  interop cleanly with other QUIC implementations. The `endpoints/`
  subpackage is the only I/O code in the package, and it is what the
  Interop Runner drives.

## Module map

Flat sans-IO modules under `src/dsquic/`, one concern per module; the
`endpoints/` subpackage is the only place I/O exists:

| Module          | Covers                                          | RFC                  |
|-----------------|-------------------------------------------------|----------------------|
| `buffer.py`     | Varints and wire encoding                       | 9000 §16             |
| `packet.py`     | Packet formats and header parsing               | 9000 §17             |
| `frames.py`     | Frame types, encoding, decoding                 | 9000 §12.4, §19      |
| `streams.py`    | Stream states and flow control                  | 9000 §2-§4           |
| `connection.py` | Connection state machine                        | 9000 §5, §7, §10     |
| `tls.py`        | TLS 1.3 handshake, scoped to QUIC               | 8446, 9001 §4        |
| `protection.py` | Packet protection keys, AEAD, header protection | 9001                 |
| `recovery.py`   | Loss detection, RTT estimation, PTO             | 9002 §5-§6           |
| `congestion.py` | Congestion controller interface (pluggable)     | 9002 §7              |
| `new_reno.py`   | NewReno congestion controller                   | 9002 §7, Appendix B  |
| `h3.py`         | HTTP/3                                          | 9114, 9220           |
| `qpack.py`      | QPACK field compression                         | 9204                 |
| `masque.py`     | CONNECT-UDP proxying                            | 9298, 9297, 9221     |
| `hq.py`         | hq-interop application protocol                 | none (Interop Runner) |
| `qlog.py`       | Structured event output                         | draft-ietf-quic-qlog |
| `endpoints/client.py` | Reference client endpoint (I/O)           | n/a                  |
| `endpoints/server.py` | Reference server endpoint (I/O)           | n/a                  |

## Relationship to aioquic

[aioquic](https://github.com/aiortc/aioquic) is the production-quality Python
QUIC stack; use it if you want to ship something. dsquic differs on purpose:

- Pure Python in the entire protocol path. aioquic accelerates its packet
  path with a C extension, which makes the most-traversed code the code you
  cannot read.
- The RFC-to-module mapping is explicit and structural.
- MASQUE is designed in from the start.
- State machines are explicit tables.

An order of magnitude in performance is the accepted price. Slow and
unoptimizable are different claims, and dsquic is only the former: the
sans-IO boundary makes the transport a swappable backend, so plain sockets,
asyncio, io_uring, or anything else can move the bytes without touching
protocol logic, and the core's interfaces (extensible send records,
per-datagram ECN, deadline-based timers, pacing rates from the congestion
controller) are shaped so a fast transport is never foreclosed.

## Interoperability

Interop is a design input, not a validation phase. The roadmap is the
[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
test sequence:

`handshake` -> `transfer` -> `retry` -> `resumption` -> `multiplexing` ->
`http3` -> `keyupdate` -> `ecn` -> `zerortt`

Primary interop targets are quic-go first, then picoquic as the conformance
ratchet. See `interop/` for the runner shim and current results.

The runner has been run locally against quic-go, aioquic, picoquic and
quiche through its ns-3 simulator. As client, `handshake`, `transfer`,
`multiplexing`, `handshakeloss`, `handshakecorruption`, `ipv6`,
`keyupdate` and `retry` pass against all four; as server, every case attempted
passes against all four. `interop/README.md` tabulates the cases that
are not attempted yet and why, and `STATE.md` records what each rung of
the ladder found.

## Development

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run pytest -q
uv run ruff check
uv run mypy
```

All three checks must pass; mypy runs strict over both `src` and `tests`.

## Documentation

- `docs/design.md`: design rationale, the TLS boundary, interop strategy,
  and open questions
- `CLAUDE.md`: working conventions for code, style, and tooling
- `STATE.md`: current implementation status and next steps
