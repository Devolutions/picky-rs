# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Update saphir dependency to 2.7.6

### Removed

## [4.6.0] 2020-09-14

### Changed

- Update saphir dependency to `2.6`
- [Official mongo driver](https://github.com/mongodb/mongo-rust-driver) is now used instead of the prototype
- Dependencies clean up

### Removed

- API Key

## [4.5.0] 2020-04-22

### Added

- Cors support for `/sign` route

### Changed

- Now fully asynchronous using Saphir V2
- In HTTP requests and answers CSR and certificates format is now solely specified through MIME types
    - Pem: `application/x-pem-file`
    - Json: `application/json`
    - X509 certificate in binary: `application/pkix-cert`
    - X509 certificate in base64: `application/pkix-cert-base64`
    - PKCS10 (CSR) in binary: `application/pkcs10`
    - PKCS10 (CSR) in base64: `application/pkcs10-base64`
- Certificate validity duration has to be specified with the provider token's `x509_duration_secs` field

### Removed

- `Accept-Encoding` HTTP header is now ignored
- `Content-Transfer-Encoding` HTTP header is now ignored

## [4.4.0] 2020-03-13

### Changed

- Update mongodb driver to support connection string starting with `mongodb+srv`
