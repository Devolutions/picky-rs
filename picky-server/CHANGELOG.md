# Changelog

## [Unreleased]

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
 
### Removed

- `Accept-Encoding` HTTP header is now ignored
- `Content-Transfer-Encoding` HTTP header is now ignored

## [4.4.0] 2020-03-13

### Changed

- Update mongodb driver to support connection string starting with `mongodb+srv`.
