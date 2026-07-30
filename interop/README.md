# Interop Runner shim

Wires dsquic into the
[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
endpoint interface. The shim adapts the environment and nothing else: it
starts `dsquic.endpoints.client` and `dsquic.endpoints.server` and adds no
protocol or application behaviour of its own.

- `Dockerfile` builds the endpoint image. Standard syntax, so it works with
  docker, podman, or Apple's `container`.
- `run_endpoint.sh` is the entrypoint and implements the contract below.

## The contract

| Input | Meaning |
|---|---|
| `ROLE` | `client` or `server` |
| `TESTCASE` | the case to run; exit **127** if unsupported |
| `REQUESTS` | client: space separated URLs to download |
| `/downloads` | client: where bodies must be written |
| `/www` | server: document root, served on port 443 |
| `/certs` | `cert.pem`, `priv.key` for the server; `ca.pem` for both |
| `SSLKEYLOGFILE` | NSS key log, so the runner's pcaps decrypt |
| `QLOGDIR` | qlog output directory (not yet emitted) |

`/certs` is mounted into both containers, so the client validates the
server certificate against `ca.pem` with the SNI taken from the request
URL. The insecure flag is never used here, per the certificate decision
recorded in `docs/design.md`.

## Test cases this image attempts

`handshake` and `transfer`. Everything else exits 127.

This list is a declaration of what to *attempt*, not a result: the runner
decides pass or fail. **The Interop Runner has never been run against
dsquic, so there are no interop results to report.** What exists is the
image contract verified by hand (below) and the hand-written tests in
`tests/interop/` against quic-go and aioquic.

## Before a real runner submission

Two things this image does not yet do:

- **Simulator routing.** Runner endpoints are expected to derive from the
  quic-network-simulator endpoint base image, which provides `/setup.sh`
  and the routes that send traffic through the simulator. This image only
  sources those files if they happen to exist, which is enough to run it
  standalone and not enough to run under the runner.
- **linux/amd64.** The online runner requires amd64 images. Building on
  Apple silicon needs `--platform linux/amd64`, or a multi-arch push.

## What is not attempted yet, and why

| Case | Reason |
|---|---|
| `multiplexing` | Needs MAX_STREAMS to raise limits; dsquic advertises 16 bidirectional streams and never increases them |
| `retry`, `versionnegotiation`, `v2` | Retry and Version Negotiation packets are not generated or parsed |
| `resumption`, `zerortt` | No session tickets, no 0-RTT |
| `keyupdate` | The "quic ku" ratchet is not implemented |
| `chacha20` | AES-128-GCM only |
| `ecn` | No ECN codepoints on send, no ECN validation |
| `http3` | `h3.py` and `qpack.py` are stubs |
| `connectionmigration` | No path validation or migration |
| `ipv6` | Both endpoints open `AF_INET` sockets |
| `handshakeloss`, `transferloss`, `handshakecorruption`, `transfercorruption`, `blackhole`, `longrtt` | Loss recovery and PTO exist, but nothing has been exercised under real loss; attempting these before the simulator works would produce noise, not evidence |
| `amplificationlimit` | The 3x limit is implemented and unit tested, but never checked against the runner's pcap inspection |
| `goodput`, `crosstraffic` | Measurements rather than pass/fail, and performance is an explicit non-goal |

## Scale, for reference

The runner enumerates 17 registered implementations (14 that act as both
client and server, plus chrome as a client and haproxy and nginx as
servers) against 23 test cases. Adding dsquic would mean 16 pairings as a
client and 15 as a server, 31 in total, each across the case list.

## Known gaps

- **No qlog.** `QLOGDIR` is accepted and ignored until `qlog.py` exists.
- **The full runner needs Linux.** It orchestrates with docker-compose and
  an ns-3 network simulator. The image contract can be verified by hand on
  macOS, as below, but the test matrix wants a Linux host or CI.

## Verifying by hand

With Apple's `container` (`brew install container`). Containers must
resolve each other by name, because the URL host has to match a
certificate SAN and so cannot be an IP address. That needs two one-time
steps: register the domain with the macOS resolver, and make it the
runtime default. `--dns-domain` on `container run` is not sufficient on
its own.

```sh
sudo container system dns create test            # writes /etc/resolver/...
container system stop
mkdir -p ~/.config/container
printf '[dns]\ndomain = "test"\n' > ~/.config/container/config.toml
container system start                           # first run downloads a kernel
```

Check it took effect; all three should answer:

```sh
container system property ls | grep -A1 '\[dns\]'   # domain = "test"
dig @127.0.0.1 -p 2053 <container-name>.test +short
dscacheutil -q host -a name <container-name>.test
```

Then:

```sh
container build -t dsquic-interop -f interop/Dockerfile .

# Unsupported test cases must exit 127.
container run --rm -e ROLE=server -e TESTCASE=zerortt dsquic-interop; echo $?

# Server, with runner-shaped certs and document root. The container name
# has to match a SAN in the certificate.
container run -d --name server -e ROLE=server -e TESTCASE=transfer \
    -v "$PWD/certs:/certs:ro" -v "$PWD/www:/www:ro" dsquic-interop

# Client. `server` resolves through the runtime's DNS.
container run --rm -e ROLE=client -e TESTCASE=transfer \
    -e REQUESTS="https://server:443/file.txt" \
    -v "$PWD/certs:/certs:ro" -v "$PWD/downloads:/downloads" \
    dsquic-interop
```

The domain registration is dropped when macOS restarts, so
`container system dns create test` may need re-running after a reboot.

The certificate must carry the runner's subject alternative names
(`server`, `server4`, `server6`, `server46`) for hostname verification to
succeed; `certs.sh` in the runner repository generates them.
