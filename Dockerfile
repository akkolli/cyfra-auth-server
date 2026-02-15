FROM rust:1.90-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY server/ server/
COPY shared/ shared/
RUN cargo build -p server --release
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get upgrade -y
COPY --from=builder /app/target/release/server /app/server_bin
EXPOSE 3000
CMD ["/app/server_bin"]