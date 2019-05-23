ARG FROM_IMAGE=mcr.microsoft.com/windows/servercore:ltsc2019
FROM ${FROM_IMAGE}

LABEL maintainer "Devolutions Inc."

WORKDIR "C:\\wayk"

COPY picky-server.exe .

EXPOSE 1234

ENTRYPOINT ["c:\\wayk\\picky-server.exe"]