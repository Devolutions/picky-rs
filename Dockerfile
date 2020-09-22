FROM debian:buster-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/wayk

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl lsb-release
RUN rm -rf /var/lib/apt/lists/*

COPY picky-server .

RUN groupadd -r picky && useradd --no-log-init -r -g picky picky
RUN chown -R picky /opt/wayk
USER picky

EXPOSE 12345

ENTRYPOINT ["./picky-server"]
