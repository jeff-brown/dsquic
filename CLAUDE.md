# dsquic

A readable, spec-faithful QUIC / MASQUE / HTTP-3 reference implementation in
pure Python. Read `docs/design.md` before making design decisions; it is the
authoritative rationale. This file is the working summary.

## Commands

Everything runs through uv:

- `uv run pytest -q` (tests)
- `uv run ruff check` and `uv run ruff format` (lint, format)
- `uv run mypy` (strict type check, src and tests)

All three must pass before any change is considered done. Run them as separate
commands, not one `&&` chain.

## Priorities (in order)

Readability > completeness > spec adherence > performance. Performance is an
explicit non-goal; never trade clarity for speed. The code is the deliverable:
it exists to teach QUIC.

## Style rules (pedantic, non-negotiable)

- No em dashes and no emojis, anywhere, for any reason: not in code,
  docstrings, comments, tests, docs, or commit messages. Use commas, colons,
  parentheses, or separate sentences. Use plain hyphens for ranges.
- Docstrings and comments are terse and technical: state what the code does
  and cite the RFC section. No editorializing, no design history, no
  references to design decisions or conversations. Rationale lives in
  `docs/design.md`, not in the code.
- Always prefer readability over abstraction. Do not introduce helpers, base
  classes, or indirection to deduplicate code unless the duplication actively
  obscures meaning. Three similar explicit blocks beat one clever one.
- Always choose the pythonic way when given a choice: EAFP, iteration
  protocols, dataclasses and enums, stdlib over hand-rolled, no Java-isms
  (getters/setters, interface-per-class, manager/factory patterns).

## Engineering rules

- Refactor over backward compatibility. Pre-1.0 there are no users: when a
  design changes, change every call site and delete the old path in the same
  change. Never keep parallel code paths, shims, aliases, or deprecated
  wrappers from a mid-project refactor.
- No faking end-to-end validation. If a behavior requires end-to-end or
  interop validation, run it for real (interop shim, real peer, real vectors).
  Never mock the result of an end-to-end check and call it done. Unit tests
  may stub internals; interop and conformance claims may not.
- Verification ladder (design.md §6.2). Every protocol feature is verified,
  in order, by: unit tests (spec vectors where the RFC provides them),
  loopback through the reference endpoints over real UDP, and the feature's
  Interop Runner test case in both directions. A rung is skippable only
  while it is not yet applicable, never for convenience. Report results by
  the rung reached: loopback success is never reported as interop.
- Phase gates (design.md §6.3). Work proceeds phase by phase. Do not start
  a phase until the previous one passes every applicable ladder rung, is
  committed, and the user has independently verified the wire format from a
  capture (tcpdump/Wireshark) for wire-facing phases. From the TLS phase
  onward the stack must support SSLKEYLOGFILE (NSS Key Log Format; keylog
  callback in tls.py, file writing in endpoints/) so captures decrypt.
- Sans-IO core. No sockets, threads, files, or asyncio anywhere in
  `src/dsquic/` except the `endpoints/` subpackage, the package's only I/O
  boundary. State machines take bytes and clock readings in, return bytes,
  deadlines, and events out; endpoint code owns sockets, files, and the
  clock and contains no protocol logic.
- Don't optimize, but don't foreclose optimization (design.md §4.7). If it
  determines the bytes or when they are due, it is core; if it determines
  how bytes reach the kernel, it is I/O. Packet sizing, coalescing,
  per-datagram ECN, timer deadlines, and pacing rate are core interface
  concerns from the start; send output is an extensible record
  (`OutgoingDatagram`), never a bare tuple. Socket mechanics (GSO/GRO,
  `sendmmsg`/`recvmmsg`, io_uring, sockopts, buffer pooling) never appear
  in protocol modules; their presence in a file with "frame" or "packet"
  in the name is a design smell.
- Reference endpoints are deliverables, not demos. `endpoints/client.py`
  and `endpoints/server.py` must exercise every protocol code path and
  interop cleanly with other QUIC implementations. A protocol feature is
  not done until it is reachable from both endpoints and validated by the
  corresponding Interop Runner test case.
- Pure Python in the protocol path. No C extensions, no dependencies beyond
  `cryptography`, which is used for raw primitives only (AEAD, HKDF,
  signatures, X.509). The TLS 1.3 handshake is hand-written in
  `dsquic/tls.py`; do not reach for pyOpenSSL or ssl.
- RFC citations are required. Every module docstring states the RFC sections
  it implements; nontrivial functions cite the section they encode (e.g.
  `RFC 9000 §17.1`). The RFC-to-code mapping is part of the product.
- Explicit state machines. Prefer named state tables and enums over
  conditionals scattered through large classes.
- Edge-case convention: state inline, validation quarantined (design.md
  §4.8). An edge case that mutates state or changes subsequent behavior is
  handled inline, in spec order, with its RFC citation. Pure reject-and-raise
  validation may be extracted into a named, cited validator. Review test: if
  handling it can only raise, it may be extracted; if it changes what happens
  next, it stays inline.
- Strict typing. mypy strict must pass; fully annotate all defs, including
  tests. No `Any` unless forced by a third-party boundary; no bare
  `# type: ignore` (always `# type: ignore[code]`).

## Layout conventions

- Flat sans-IO protocol modules under `src/dsquic/`, one concern per
  module; I/O code lives only in the `endpoints/` subpackage. The package
  docstring in `__init__.py` is the module map. Keep it current.
- `tests/` mirrors the module tree: every `dsquic/foo.py` has a
  `tests/test_foo.py`, and subpackage modules mirror as
  `tests/<subpackage>/test_<name>.py`. `tests/test_scaffold.py` enforces
  this; do not weaken it.
- New modules need: RFC-mapping docstring, mirror test file, entry in the
  `__init__.py` module map.
- Text is ASCII except the section sign (§) in RFC citations.

## Git

- Read access is unrestricted: status, log, diff, show, blame, fetch.
- Staging is allowed: `git add`, `git restore --staged`.
- Never commit and never push, for any reason. No history writes of any kind:
  no `git commit`, no merges, no rebases, no amends, no tags. No remote
  writes of any kind: no `git push`, no remote branch or tag operations, no
  PR creation. Stage the work, report what is staged, and stop; the human
  makes every commit.
- Staging and committing are asynchronous: the agent stages, the human
  commits and pushes on their own schedule. Periodically verify the actual
  git state (`git status`, `git log`, `git fetch` plus `origin/main`), at
  minimum at session start, before staging new work, and before updating
  `STATE.md`. Previously staged changes may since have been committed,
  pushed, or modified; reconcile against what git reports, never against
  the last remembered state.

## Session state and context retrieval

- `STATE.md` at the repo root is the session state file. Read it at the start
  of every session before doing anything else. Update it at the end of every
  coding session: current milestone, work completed, in-flight work with file
  references, next steps, and newly settled or newly opened decisions. It
  describes current state only; it is not a log. Prune entries that are no
  longer true.
- Keep context retrievable, not resident (RAG). This file stays a compact
  index of pointers: rationale in `docs/design.md`, current status in
  `STATE.md`, RFC mapping in module docstrings. When working, search for and
  read only the modules and tests relevant to the task; do not load the whole
  tree. As the project grows, split documentation into focused, descriptively
  named files under `docs/` and reference them here so they can be retrieved
  on demand instead of held in context.

## Sync discipline

- Clean beats fast. When thoroughness and speed conflict, choose
  thoroughness; a smaller amount of coherent work beats a larger amount of
  drifting work.
- Ruthlessly resync at every major checkpoint: a settled decision, a
  completed milestone, a new module, or any change to `docs/design.md`.
  Verify that `docs/design.md`, `README.md`, this file, `STATE.md`, the
  module map in `__init__.py`, and the code all agree, including section
  number cross-references. Fix every discrepancy immediately; a stale claim
  in any of these files is a defect, not a doc chore.
- Actively raise ambiguities and concerns. When the design, a spec, or an
  instruction admits more than one reading, or new work creates tension with
  a recorded decision, surface the question rather than silently picking a
  side. Recorded decisions change by raising them, never by drift.

## Open decisions

Check `docs/design.md` §7 before touching related areas. Still open: 0-RTT
scope, the asyncio transport layer, PyPI publication, and the v1 MASQUE
surface (CONNECT-UDP only vs. CONNECT-IP alongside). Record newly settled
decisions in the appendix of `docs/design.md`.
