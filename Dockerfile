FROM debian:stretch-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/wayk

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates curl
RUN rm -rf /var/lib/apt/lists/*

COPY picky-server .

EXPOSE 12345

ENTRYPOINT ["./picky-server"]
