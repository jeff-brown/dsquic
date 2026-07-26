# Interop Runner shim

Placeholder for the thin shim that wires dsquic into the
[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
client/server interface (design doc §6.1).

The runner drives implementations via a Docker image honoring a small
contract: `ROLE` (client/server), `TESTCASE` (exit 127 if unsupported),
`REQUESTS`/`www` file serving, `SSLKEYLOGFILE`, and qlog output under
`QLOGDIR`. The roadmap is the runner's test-case sequence:

`handshake` -> `transfer` -> `retry` -> `resumption` -> `multiplexing` ->
`http3` -> `keyupdate` -> `ecn` -> `zerortt`

To be added here once the sans-IO core can complete a handshake:

- `run_endpoint.sh` + Dockerfile per the runner's interface
- a minimal synchronous UDP client/server wrapping `dsquic.connection`
