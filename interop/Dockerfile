# The dsquic endpoint image for the QUIC Interop Runner.
#
# Standard Dockerfile syntax, so it builds with docker, podman, or
# Apple's container tool. The runner expects the entrypoint to honour the
# environment contract described in run_endpoint.sh.

FROM python:3.12-slim

# The runner's base images provide /setup.sh to configure simulator
# routing. It is absent when the image is run standalone, so
# run_endpoint.sh sources it only if present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /dsquic
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
