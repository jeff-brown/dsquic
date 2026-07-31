# The dsquic endpoint image for the QUIC Interop Runner.
#
# Derived from the network simulator's endpoint base image, which is
# ubuntu:24.04 plus the tools and /setup.sh the simulator needs: it
# disables TX checksum offload, which ns-3 requires, and adds the routes
# that send traffic through the simulator. Building on anything else
# produces an image that runs standalone but not under the runner.
#
# The online runner requires linux/amd64:
#   docker build --platform linux/amd64 -t dsquic -f interop/Dockerfile .

FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu marks its Python as externally managed (PEP 668), so install
# into a virtual environment rather than fighting the system packages.
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /dsquic
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Replaces the base image's placeholder entrypoint script.
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
