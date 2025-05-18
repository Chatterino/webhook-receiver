FROM rust:1-alpine as build
ENV SQLX_OFFLINE=true
WORKDIR /src
RUN apk add --no-cache musl-dev
COPY . .
RUN cargo build --release

FROM alpine:latest
WORKDIR /app
COPY --from=build /src/target/release/webhook-receiver /app/
COPY --from=build /src/migrations /app/
CMD ["./webhook-receiver"]
