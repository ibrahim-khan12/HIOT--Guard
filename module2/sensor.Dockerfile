ARG ZEEK_BASE
FROM ${ZEEK_BASE}
ARG TSHARK_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends tshark=${TSHARK_VERSION} && rm -rf /var/lib/apt/lists/*
WORKDIR /work
