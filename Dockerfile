# syntax=docker/dockerfile:1.7

ARG RUST_TOOLCHAIN=nightly-2025-11-05

FROM rust:bookworm AS builder
ARG RUST_TOOLCHAIN
ARG CARGO_FEATURES=""

RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    libssl-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal \
  && rustup default "${RUST_TOOLCHAIN}"

WORKDIR /workspace

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY c ./c
COPY include ./include
COPY generated ./generated
COPY xtask ./xtask
COPY db ./db
COPY atlas.hcl ./atlas.hcl

RUN if [ -n "${CARGO_FEATURES}" ]; then \
    cargo build --locked --release -p aegaeon-server --bins --features "${CARGO_FEATURES}"; \
  else \
    cargo build --locked --release -p aegaeon-server --bins; \
  fi

FROM arigaio/atlas:latest AS atlas

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
    ca-certificates \
    curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --home-dir /home/aegaeon --shell /usr/sbin/nologin --uid 10001 aegaeon

WORKDIR /app

COPY --from=builder /workspace/target/release/aegaeon-server /usr/local/bin/aegaeon-server
COPY --from=builder /workspace/target/release/aegaeon-hosted-bootstrap /usr/local/bin/aegaeon-hosted-bootstrap
COPY db ./db
COPY atlas.hcl ./atlas.hcl

USER aegaeon

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/aegaeon-server"]
CMD ["--host", "0.0.0.0", "--port", "8080"]

FROM debian:bookworm-slim AS migrate

RUN apt-get update \
  && apt-get install --yes --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --home-dir /home/aegaeon --shell /usr/sbin/nologin --uid 10001 aegaeon

WORKDIR /app

COPY --from=atlas /atlas /usr/local/bin/atlas
COPY db ./db
COPY atlas.hcl ./atlas.hcl

USER aegaeon

ENTRYPOINT ["/usr/local/bin/atlas"]
CMD ["migrate", "apply", "--env", "local"]
