#!/bin/bash
# The QUIC Interop Runner endpoint contract.
#
# Inputs, from https://github.com/quic-interop/quic-interop-runner:
#   ROLE           "client" or "server"
#   TESTCASE       the test case to run; exit 127 if unsupported
#   REQUESTS       client: space separated URLs to download
#   /downloads     client: where downloaded bodies must be written
#   /www           server: the document root, served on port 443
#   /certs         server: cert.pem and priv.key
#   SSLKEYLOGFILE  NSS key log, for decrypting the runner's pcaps
#   QLOGDIR        qlog output directory (dsquic does not emit qlog yet)
#
# This script adapts the environment and nothing else: it starts the
# reference endpoints in dsquic.endpoints and adds no protocol or
# application behaviour of its own (design.md appendix).
set -e

# Test cases dsquic implements. Anything else exits 127 so the runner
# records "unsupported" rather than a failure, and so new cases can be
# added upstream without breaking this image.
#
# multiplexing is deliberately absent: it transfers thousands of files
# over one connection and expects the server to raise stream limits with
# MAX_STREAMS, which dsquic does not send yet. It advertises 16
# bidirectional streams and the seventeenth fails.
SUPPORTED="handshake transfer transferloss transfercorruption blackhole longrtt amplificationlimit"

case " $SUPPORTED " in
    *" $TESTCASE "*) ;;
    *)
        echo "dsquic does not implement test case '$TESTCASE'" >&2
        exit 127
        ;;
esac

# The base image always ships /setup.sh and /wait-for-it.sh, but they only
# apply when this container sits on the simulator's network, which the
# runner's compose topology fixes at 193.167.0.0/16. Running the image by
# hand puts it on an ordinary bridge, where adding those routes and waiting
# for a simulator that does not exist would both fail.
if hostname -I | grep -qE '(^| )193\.167\.'; then
    IN_SIMULATOR=yes
else
    IN_SIMULATOR=no
fi

if [ "$IN_SIMULATOR" == "yes" ]; then
    # Disables TX checksum offload, which ns-3 requires, and routes
    # traffic through the simulator.
    # shellcheck disable=SC1091
    /setup.sh
fi

if [ "$ROLE" == "client" ]; then
    if [ "$IN_SIMULATOR" == "yes" ]; then
        /wait-for-it.sh sim:57832 -s -t 30
    fi
    # REQUESTS holds absolute URLs; the endpoint takes a host, a port,
    # and paths. Every request in a test case targets one server, so the
    # authority comes from the first URL and the paths from all of them.
    first="${REQUESTS%% *}"
    authority="${first#*://}"
    authority="${authority%%/*}"
    host="${authority%%:*}"
    port="${authority##*:}"
    if [ "$port" == "$host" ]; then
        port=443
    fi
    paths=""
    for url in $REQUESTS; do
        rest="${url#*://}"
        paths="$paths /${rest#*/}"
    done
    echo "dsquic client: $TESTCASE, host=$host port=$port paths=$paths" >&2
    # The runner gives a test case 60 seconds and its transfer cases move
    # 10MB over a 10Mbps link, so give up just short of its deadline to
    # produce a clean error rather than being killed mid-flight.
    # shellcheck disable=SC2086
    exec python -m dsquic.endpoints.client \
        "$host" "$port" $paths \
        --ca /certs/ca.pem \
        --server-name "$host" \
        --output-dir /downloads \
        --timeout 55
else
    echo "dsquic server: $TESTCASE, serving /www on port 443" >&2
    exec python -m dsquic.endpoints.server \
        --host 0.0.0.0 \
        --port 443 \
        --certificate /certs/cert.pem \
        --private-key /certs/priv.key \
        --www /www
fi
