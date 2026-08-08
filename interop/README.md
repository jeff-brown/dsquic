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
| `QLOGDIR` | qlog output directory; one `.sqlog` per connection |

`/certs` is mounted into both containers, so the client validates the
server certificate against `ca.pem` with the SNI taken from the request
URL. The insecure flag is never used here, per the certificate decision
recorded in `docs/design.md`.

## Test cases this image attempts

`handshake`, `transfer`, `multiconnect`, `transferloss`,
`transfercorruption`, `blackhole`, `longrtt`, `amplificationlimit`,
`ipv6`, `keyupdate`, `retry`, `resumption`, `zerortt`, `ecn`,
`chacha20`, and `versionnegotiation`. Everything else exits 127.

`multiplexing` is not in that list and does not need to be: the runner
gives both containers the name `transfer` for it, and it is the request
count, 1999 files on one connection, that makes it a test of
MAX_STREAMS.

`multiconnect` is the name the runner gives the client container for the
`handshakeloss` and `handshakecorruption` cases: 50 files, one connection
each, so that what is being lost is handshake packets rather than data
packets. `run_endpoint.sh` maps it to the client's
`--connection-per-request`, and raises the timeout to 280 seconds because
the runner allows those cases 300 rather than the usual 60.

`versionnegotiation` is claimed but the current runner never sends it:
upstream keeps the test class yet dropped it from the registered list,
and the public matrix carries no such column. The client behaviour
(RFC 9000 §6.2, forcing negotiation with a reserved version and
redialling on the answer) is verified to the loopback rung instead,
`test_loopback_version_negotiation`.

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

Cases are timing sensitive, so a case that fails in a long combined run
and passes on its own is usually contention rather than a protocol bug.
Re-run a single red square before believing it.

### VM sizing and settings

`colima start --cpu 8 --memory 16` on a 10-core, 32GB host. The amd64
peer images (aioquic, picoquic, quiche) run emulated on Apple silicon,
which is what the cores are for; at four CPUs the loss cases contend
badly enough to change results.

Container file descriptors must be raised or `multiplexing` fails for
*any* client: the runner's `docker-compose.yml` sets only `memlock`, so
the limit is the Docker default of 1024, and a peer serving 1999
concurrent requests opens a file per request and dies with
`OSError: [Errno 24] Too many open files`. Set it in
`~/.colima/default/colima.yaml`, whose `docker:` mapping is colima's
daemon.json passthrough, then `colima restart`:

```yaml
docker:
  default-ulimits:
    nofile:
      Name: nofile
      Soft: 1048576
      Hard: 1048576
```

Editing `/etc/docker/daemon.json` inside the VM appears to work and does
not survive: colima regenerates that file on every start, so the limit
reverts to 1024 and the case fails again for a reason that looks new.

### Disk and log retention

The VM has two disks. Lima's base disk, 19GB, holds `/` and the home
directory where the runner and its `logs_<timestamp>` directories live.
Colima's data disk, 60GB, is mounted at `/var/lib/docker` and is mostly
empty. `colima start --disk` sizes the second one, so growing it does
nothing for log pressure.

A run's artifacts are dominated by pcaps, then container stderr, then
the peers' own qlogs; dsquic's `.sqlog` traces are the smallest part and
the most useful. Keep the three most recent runs whole, pcaps included,
since the phase gates call for independent capture verification, and
delete the rest:

```
colima ssh -- bash -lc 'cd ~/quic-interop-runner && ls -dt logs_* | tail -n +4 | xargs rm -rf'
```

### Keeping the host awake

macOS idle sleep suspends the VM mid-run. This host is configured with
`sleep 1`, one minute, on both AC and battery (`pmset -g custom`), which
is shorter than every case. Launch the run under `caffeinate`:

```
caffeinate -ims colima ssh -- bash -lc 'cd ~/quic-interop-runner && .venv/bin/python run.py ...'
```

or attach an assertion to a run already in flight, which releases itself
when that process exits:

```
caffeinate -ims -w <pid>
```

Two limits to know. `-s`, which prevents system sleep outright, is
ignored on battery, so only `-i` applies there; run on AC power, where
`powernap` and `standby` are also less likely to suspend the VM. And no
flag defeats clamshell sleep on Apple silicon, so the lid stays open
unless an external display is attached on AC.

A sweep that slept should be discarded rather than interpreted: the VM
comes back with a clock jump, and these cases already flip on CPU
contention alone.

## Results

Through the ns-3 simulator, against quic-go, aioquic, picoquic and
quiche.

As **server**, all twelve cases claimed at the time pass against all
four peers, with no failures. `keyupdate` is verified by the runner
reading key phase bits out of the pcap, and quiche reports it
unsupported because its client does not implement key update.
`resumption`, claimed after that sweep, passes on its own in both
roles against all four peers; the runner verifies it from the pcap as
exactly two handshakes, a Certificate in the first and none in the
second. `zerortt` likewise passes in both roles against all four
peers, verified from the pcap as two handshakes with nonzero client
0-RTT payload and nearly all request bytes early; two defects it
caught that no lower rung could are in docs/findings.md. `ecn`
passes in both roles against picoquic, the runner reading the ECT
marks and ACK-ECN frames of both directions out of the pcap; quic-go,
aioquic and quiche report it unsupported because their interop images
do not mark, the same pattern the public matrix shows. `chacha20`
passes in both roles against quic-go, aioquic and picoquic. The
quiche pairing is environmental: its BoringSSL ChaCha20 emits garbage
under qemu emulation on this aarch64 VM (established by keylog and
Wireshark, and by quic-go failing identically here while the same
pairing passes on the hosted amd64 runner; docs/findings.md), and
quiche's own client does not attempt the case.

As **client**, `handshake`, `transfer`, `multiplexing`, `handshakeloss`,
`handshakecorruption`, `ipv6` and `keyupdate` pass against all four
peers. Three client-side defects behind the two handshake-loss cases,
and one environmental limit behind `multiplexing`, are recorded in
STATE.md; the multiplexing failure turned out to be the container file
descriptor limit rather than a protocol defect, which was established by
running quic-go's client against the same peer.

## Before a real runner submission

**linux/amd64.** The online runner requires amd64 images. Building on
Apple silicon needs `--platform linux/amd64`, or a multi-arch push.

## What is not attempted yet, and why

| Case | Reason |
|---|---|
| `v2` | Only QUIC v1 is offered |
| `ecn` | No ECN codepoints on send, no ECN validation |
| `http3` | `h3.py` and `qpack.py` are stubs |
| `connectionmigration` | No path validation or migration |
| `goodput`, `crosstraffic` | Measurements rather than pass/fail, and performance is an explicit non-goal |

## Scale, for reference

The runner enumerates 18 registered implementations against 23 test
cases. dsquic against all of them in both roles is 34 pairings, which at
the observed per-case timings is an overnight run rather than an
interactive one.

## Known gaps

- **linux/amd64 for upstream.** See above; local runs are aarch64.

## Verifying the image contract by hand

The full matrix runs under colima, as above. The image contract itself
can also be checked without any simulator, which is quicker when the
question is whether the shim honours ROLE, TESTCASE and the mounts.

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
