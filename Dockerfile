# syntax=docker/dockerfile:1

# ---- build ---------------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Cache mounts keep the crate registry and build artifacts between deploys.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p zashu-mint \
 && cp target/release/zashu-mint /usr/local/bin/zashu-mint

# ---- run -----------------------------------------------------------------
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 zashu
COPY --from=build /usr/local/bin/zashu-mint /usr/local/bin/zashu-mint
USER zashu
EXPOSE 8080
ENV RUST_LOG=info
# Pages and mascot PNGs are compiled into the binary; no files to ship.
CMD ["zashu-mint", "--bind", "0.0.0.0:8080"]
