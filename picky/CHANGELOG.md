# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- Bump minimum supported Rust version to 1.51
- Update `rsa` dependency to `0.5`
- Update `picky-asn1` dependency to `0.4`

## [6.3.0] 2021-05-27

### Added

- PKCS7 implementation behind `pkcs7` feature
- `WinCertificate` for authenticode behind `wincert` feature

### Changed

- Update `aes-gcm` dependency to `0.9`

## [6.2.0] 2021-03-04

### Added

- `Csr::generate_with_attributes` to generate CSR with attributes.
- `CertificateBuilder::inherit_extensions_from_csr_attributes` to allow certificate to inherit extensions requested by CSR attribute.
- Various API additions to `GeneralNames` for improved ergonomics.

## [6.1.2] 2021-01-11

### Fixed

- Fix bad `use`s statements to `serde::export`

## [6.1.1] 2020-12-11

### Fixed

- Fix `HttpSignatureError`'s Display trait implementation (`certificate expired` → `signature expired`).
- Fix certificate validity period that MUST be encoded as `UTCTime` through the year 2049 as per RFC 5280.
  Previously, they were always encoded as `GeneralizedTime`.

## [6.1.0] 2020-10-21

### Added

- `CertificateBuilder::serial_number` can be used to provide a custom serial number instead of generating one.

### Fixed

- Bad generation for second exponent (`pq`) when generating PKCS#8 structure.
- Serial number was sometimes generated as negative.

## [6.0.0] 2020-10-13

### Added

- Implementation of `Jwe` (JSON Web Encryption) RFC.
- Email attribute can be added to `DirectoryName` using `add_email` method.
- `from_pem_str` method to `Cert`, `Csr`, `PrivateKey` and `PublicKey`.

### Changed

- Separate `SignatureHashType` into two separate enums `HashAlgorithm` and `SignatureAlgorithm`.
- `KeyIdGenError` is now wrapping a `HashAlgorithm`.
- Update `rsa` dependency.
- `HttpSignature` store custom `algorithm` names instead of just ignoring them.
- Major `jose` module changes
  - JOSE header fields are renamed to be identical to RFCs when possible.
  - `Jwt` is now divided into `Jws` (JSON Web Signature) and `Jwe` (JSON Web Encryption)
  - `Jws` provides an API to sign any kind of data (binary). JSON claims are part of `Jwt` only.
  - `Jwe` provides an API to encrypt any kind of data (binary). JSON claims are part of `Jwt` only.
- Typo in `CertificateBuilder` API: `valididy` has been renamed to `validity`.

### Fixed

- RSA private key generation ([#53](https://github.com/Devolutions/picky-rs/issues/53)).

## [5.1.1] 2020-07-13

### Changed

- Better `CaChainError::AuthorityKeyIdMismatch` display.

## [5.1.0] 2020-07-07

### Added

- Add `BufRead`-based API to read PEM streams: `pem::Pem::read_from` and `pem::read_pem`.

### Changed

- Some internal types are moved to a new `picky_asn1_x509` crate but API is unchanged.
- Dependencies clean up.

## [5.0.0] 2020-05-06

### Added

- Add `into_public_key` method to `x509::Cert`.
- Support for the ["algorithm" http signature parameter](https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.1.3).

### Changed

- `Jwt` has no generic lifetime parameter anymore.

### Removed

- `Cert::verify` and `Cert::verify_chain` methods (previously deprecated)
- `HttpRequest` trait impl for `http` crate v0.1

### Fixed

- Add missing parameters for AES and SHA object identifiers ([668c06e8d](https://github.com/Devolutions/picky-rs/commit/668c06e8d8e8a0caae8bd13cf81c189bbc2e4918))

## [4.7.0] 2020-04-16

### Added

- Implement `From<UTCDate>` trait on `DateTime<Utc>`.
- Support for leeway in HTTP signature verifier.
- Verifier API to X509 Cert.

### Deprecated

- `Cert::verify` and `Cert::verify_chain` methods in favor of the `Cert::verifier` method.
