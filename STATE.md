# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-07-26)

Scaffold and working conventions complete, committed, and pushed to
origin/main. No protocol logic implemented yet.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy over
  src and tests, pytest. All checks pass: `uv run pytest -q`,
  `uv run ruff check`, `uv run ruff format --check .`, `uv run mypy`.
- Layout: flat sans-IO modules under `src/dsquic/` (buffer, packet, frames,
  streams, connection, tls, protection, recovery, congestion, new_reno, h3,
  qpack, masque, hq, qlog), each a docstring stub with RFC mapping, plus
  the `endpoints/` subpackage (client, server), the package's only I/O
  boundary. `tests/` mirrors the modules including the subpackage;
  `tests/test_scaffold.py` enforces the mirror.
- Docs: `README.md` (public overview), `docs/design.md` (rationale and open
  questions), `CLAUDE.md` (working rules), `interop/README.md` (Interop
  Runner shim placeholder).
- Working tree is clean; everything is committed and pushed (agent stages
  only, never commits or pushes, per CLAUDE.md).

## In-flight work

None.

## Next steps

1. Implement `buffer.py` (varints, RFC 9000 §16) with real tests.
2. Then `packet.py` header parsing and `protection.py` Initial keys, toward
   the Interop Runner `handshake` test case.

## Open decisions

See design.md §7. Settled this session: module layout (flat), tooling,
Python 3.12+, the edge-case convention (state inline, validation
quarantined, design.md §4.8), pluggable congestion control (interface in
congestion.py, NewReno baseline in new_reno.py, loss detection fixed),
hq-interop in core as hq.py, and the endpoints/ subpackage as the
structural I/O boundary; recorded in the design.md appendix. MVP scoping
discussion in progress: still to settle are client cert validation
strictness and milestone ordering.
