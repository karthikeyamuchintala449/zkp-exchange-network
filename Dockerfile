# syntax=docker/dockerfile:1.4
FROM rust:slim-bookworm AS builder

# Install system dependencies and Node.js 22
RUN apt-get update && apt-get install -y \
    ca-certificates curl gnupg build-essential git python3 pkg-config libssl-dev \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Build Circom 2.2.3 from source
RUN git clone --branch v2.2.3 --depth 1 https://github.com/iden3/circom.git /tmp/circom \
    && cd /tmp/circom && cargo build --release \
    && cp target/release/circom /usr/local/bin/circom \
    && rm -rf /tmp/circom

# Install snarkjs to a fixed, explicit prefix so the location is always known
RUN npm install -g --prefix /app-npm snarkjs@0.7.6 \
    && cp /app-npm/bin/snarkjs /app-snarkjs-bin \
    && chmod +x /app-snarkjs-bin

WORKDIR /app

# Copy dependency manifests
COPY Cargo.toml ./
COPY zkp-exchange-network/Cargo.toml ./zkp-exchange-network/

# Build project dependencies using the source files
COPY zkp-exchange-network/src ./zkp-exchange-network/src
RUN cargo build --release -p zkp-exchange-network

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl libssl3 nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zkp-cli     /usr/local/bin/zkp-cli
COPY --from=builder /usr/local/bin/circom           /usr/local/bin/circom
COPY --from=builder /app-npm/lib/node_modules       /usr/local/lib/node_modules
COPY --from=builder /app-snarkjs-bin                /usr/local/bin/snarkjs
COPY --from=builder /app                            /app

WORKDIR /app
# Replace the snarkjs bin with a simple wrapper script
RUN printf '#!/bin/sh\nexec node /usr/local/lib/node_modules/snarkjs/cli.js "$@"\n' > /usr/local/bin/snarkjs \
    && chmod +x /usr/local/bin/snarkjs

ENV NODE_PATH=/usr/local/lib/node_modules:/usr/local/lib/node_modules/snarkjs/node_modules
ENTRYPOINT ["zkp-cli"]
CMD ["--help"]