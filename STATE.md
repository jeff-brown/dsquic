# STATE

Session state file. Read at session start; updated at session end. Current
state only, no history.

## Status (2026-07-26)

Scaffold complete. No protocol logic implemented yet.

- Tooling: uv, hatchling build, ruff (E/F/I/UP/B/PL/RUF), strict mypy over
  src and tests, pytest. All checks pass: `uv run pytest -q`,
  `uv run ruff check`, `uv run ruff format --check .`, `uv run mypy`.
- Layout: flat modules under `src/dsquic/` (buffer, packet, frames, streams,
  connection, tls, protection, recovery, h3, qpack, masque, qlog), each a
  docstring stub with RFC mapping, plus the reference endpoints (client,
  server), the only modules permitted I/O. `tests/` mirrors the modules;
  `tests/test_scaffold.py` enforces the mirror.
- Docs: `docs/design.md` (rationale and open questions), `CLAUDE.md`
  (working rules), `interop/README.md` (Interop Runner shim placeholder).
- Nothing committed to git yet; all scaffold work is staged on `main`
  awaiting the initial commit (agent never commits or pushes, per CLAUDE.md).

## In-flight work

None.

## Next steps

1. Decide the edge-case convention (design.md §4.8); required before
   `recovery.py`.
2. Implement `buffer.py` (varints, RFC 9000 §16) with real tests.
3. Then `packet.py` header parsing and `protection.py` Initial keys, toward
   the Interop Runner `handshake` test case.

## Open decisions

See design.md §7. Settled this session: module layout (flat), tooling,
Python 3.12+; recorded in the design.md appendix.
