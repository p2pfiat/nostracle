FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/nostracle nostracle
COPY --from=build /src/target/release/nostracle /usr/local/bin/nostracle
USER nostracle
WORKDIR /var/lib/nostracle
VOLUME /var/lib/nostracle
# expects /var/lib/nostracle/config.toml with key_file/db_file under data/
HEALTHCHECK --interval=5m --timeout=30s CMD nostracle -c config.toml status > /dev/null || exit 1
ENTRYPOINT ["nostracle", "-c", "config.toml"]
CMD ["run"]
