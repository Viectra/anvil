FROM rust:1-bookworm AS chef
WORKDIR /app
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates/anvil-core/Cargo.toml crates/anvil-core/Cargo.toml
COPY crates/anvil-server/Cargo.toml crates/anvil-server/Cargo.toml
COPY crates/anvil-core/src crates/anvil-core/src
COPY crates/anvil-server/src crates/anvil-server/src
COPY crates/anvil-server/migrations crates/anvil-server/migrations
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p anvil-server

COPY Cargo.toml Cargo.lock ./
COPY crates/anvil-core crates/anvil-core
COPY crates/anvil-server crates/anvil-server
RUN cargo build --release --locked --bin anvil-server && mkdir -p /data && chmod 700 /data

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/target/release/anvil-server /usr/local/bin/anvil-server
COPY --from=builder --chown=65532:65532 /data /data

USER 65532:65532
ENV ANVIL_BIND_ADDR=0.0.0.0:8080 \
    ANVIL_LOG_FORMAT=json \
    RUST_LOG=anvil_server=info,tower_http=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/anvil-server", "healthcheck", "--url", "http://127.0.0.1:8080/api/v1/health"]

ENTRYPOINT ["/usr/local/bin/anvil-server"]
CMD ["serve"]
