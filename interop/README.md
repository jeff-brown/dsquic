# Interop Runner shim

Wires dsquic into the
[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
endpoint interface. The shim adapts the environment and nothing else: it
starts `dsquic.endpoints.client` and `dsquic.endpoints.server` and adds no
protocol or application behaviour of its own.

- `Dockerfile` builds the endpoint image on top of
  `martenseemann/quic-network-simulator-endpoint`, which supplies the
  `/setup.sh` that routes traffic through the simulator.
- `run_endpoint.sh` is the entrypoint and implements the contract below.
  It detects the simulator by the runner's 193.167.0.0/16 addressing, so
  the same image also runs on an ordinary bridge, where there is no
  simulator to route to or wait for.

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

`handshake`, `transfer`, `transferloss`, `transfercorruption`,
`blackhole`, `longrtt`, and `amplificationlimit`. Everything else exits
127.

This list is a declaration of what to *attempt*, not a result: the runner
decides pass or fail. Every case listed has been run and passed; see
"Results" below.

## Running it locally

The runner drives `docker compose` and hardcodes `/tmp` for its working
directories.

**Apple's `container` cannot drive it.** This was established rather than
assumed: it has no compose support, and `interop.py` shells out to
`docker compose` in five places; `--network` has no static-IP option
while the topology pins 193.167.0.100 and friends; and it attaches one
network per container where the simulator needs two.

**colima works.** Clone and run the runner *inside* the VM, because
colima refuses to mount host `/tmp` ("must not be a system path") and the
runner insists on it:

```
colima start
colima ssh -- bash -lc 'docker build -f interop/Dockerfile -t dsquic-interop:latest .'
colima ssh -- bash -lc 'cd ~/quic-interop-runner && .venv/bin/python run.py -s quic-go -c dsquic -t handshake,transfer'
```

`tshark` must be installed in the VM: pyshark shells out to it, and
without it every case fails with "Expected exactly one version. Got []".
That failure reproduces for quic-go as well, which is how it was
identified as environmental rather than ours.

Cases are timing sensitive on a four-CPU VM. A case that fails in a long
combined run and passes on its own is usually contention, not a protocol
bug, but it is worth re-running rather than assuming.

## Results

Against quic-go and aioquic through the ns-3 simulator, in both roles:
`handshake` and `transfer` pass in every pairing of dsquic, quic-go and
aioquic. `transferloss`, `transfercorruption`, `blackhole`, `longrtt`
and `amplificationlimit` pass against quic-go in both roles.
`keyupdate` passes with dsquic as server, which the runner verifies by
reading key phase bits out of the pcap.

## Before a real runner submission

**linux/amd64.** The online runner requires amd64 images. Building on
Apple silicon needs `--platform linux/amd64`, or a multi-arch push.

## What is not attempted yet, and why

| Case | Reason |
|---|---|
| `multiplexing` | Needs MAX_STREAMS to raise limits; dsquic advertises 16 bidirectional streams and never increases them |
| `handshakeloss`, `handshakecorruption` | Both run as `multiconnect`, which asks the client for 50 sequential connections on one invocation; the client makes one connection for all of `REQUESTS` |
| `retry`, `v2` | Retry packets are not generated or parsed, and only QUIC v1 is offered |
| `versionnegotiation` | dsquic *sends* Version Negotiation, which is what unblocked every other case, but the client does not react to receiving one by retrying with a supported version |
| `resumption`, `zerortt` | No session tickets, no 0-RTT |
| `keyupdate` | Passes as server. Not claimed as client: the runner's server container runs this case under the name `transfer`, so the server side needs only to respond, while the client side must start an update and nothing calls `Connection.initiate_key_update` yet |
| `chacha20` | AES-128-GCM only |
| `ecn` | No ECN codepoints on send, no ECN validation |
| `http3` | `h3.py` and `qpack.py` are stubs |
| `connectionmigration` | No path validation or migration |
| `ipv6` | Both endpoints open `AF_INET` sockets |
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
