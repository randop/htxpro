FROM rust:bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake clang perl pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
COPY config.yaml ./config.yaml
COPY public ./public
COPY sites ./sites
COPY LICENSE-MIT ./LICENSE-MIT
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home websrv
WORKDIR /app
COPY --from=builder /build/target/release/websrv /app/websrv
COPY --from=builder /build/public /app/public
COPY --from=builder /build/sites /app/sites
COPY deploy/config.docker.yaml /app/config.yaml
RUN mkdir -p /run/secrets
USER 10001:10001
EXPOSE 8443/udp
EXPOSE 8443/tcp
EXPOSE 8080/tcp
ENTRYPOINT ["/app/websrv"]
