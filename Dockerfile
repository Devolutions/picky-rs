# build container

FROM rust:1.34-stretch as rust-build
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/work/build

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./picky-core ./picky-core
COPY ./picky-server ./picky-server

RUN cargo build --release

# dist container

FROM debian:stretch-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/work/dist

RUN apt-get update
RUN apt-get install -y --no-install-recommends libssl1.1 ca-certificates libcurl4-openssl-dev
RUN rm -rf /var/lib/apt/lists/*

# copy artifacts from build container
COPY --from=rust-build /opt/work/build/target/release/picky-server .

EXPOSE 12345

ENTRYPOINT [ "./picky-server" ]

