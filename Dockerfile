# build container

FROM devolutions/waykbuilder:rust as rust-build
LABEL maintainer "Devolutions Inc."

USER wayk
WORKDIR /opt/wayk/build

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./picky-core ./picky-core
COPY ./picky-server ./picky-server

RUN cargo build --release

# dist container

FROM debian:stretch-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/wayk/dist

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates
RUN rm -rf /var/lib/apt/lists/*

# copy artifacts from build container
COPY --from=rust-build /opt/wayk/build/target/release/picky-server .

EXPOSE 12345

ENTRYPOINT [ "./picky-server" ]
