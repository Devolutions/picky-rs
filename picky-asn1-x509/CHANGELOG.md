# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added 

- (Breaking) `ShaVariant` enum is extended for MD5 and SH1 algorithms
- Support for an Authenticode timestamp deserialization/serialization
- CTL implementation behind `ctl` feature
- New `SpcSipInfo` struct

### Changed

- (Breaking) Add `SpcStatementType` variant in `AttributeValues` enum
- `SpcAttributeAndOptionalValue` now supports both `SpcPeImageData` and `SpcSipInfo` values

### Fixed
- SignedData:
  - (Breaking) `RevocationInfoChoice` field is now optional as specified by the RFC
  - (Breaking) `CertificateSet` is now a `Vec<CertificateChoices>` which can accept both a normal `Certificate` and an `other` kind of certificate as specified by the RFC  

## [0.6.1] 2021-06-02

### Added

- More ECC OIDs ([#87](https://github.com/Devolutions/picky-rs/pull/87))

## [0.6.0] 2021-05-27

### Added

- Support for V1 and V2 X509 certificates ([#83](https://github.com/Devolutions/picky-rs/pull/83))
- Support for `CrlNumber` extension ([#83](https://github.com/Devolutions/picky-rs/pull/83))
- PKCS7 implementation behind `pkcs7` feature ([#83](https://github.com/Devolutions/picky-rs/pull/83))

### Changed

- More supported attribute values: `ContentType`, `MessageDigest` and `SpcSpOpusInfo` ([#83](https://github.com/Devolutions/picky-rs/pull/83))
- Fix clippy upper case acronyms warning in a few places ([#85](https://github.com/Devolutions/picky-rs/pull/85))

### Removed

- Remove `ImplicitCurve` from `EcParameters` enum ([#85](https://github.com/Devolutions/picky-rs/pull/85))

## [0.5.0] 2021-03-04

### Added

- Support for attributes in `CertificationRequestInfo` ([#78](https://github.com/Devolutions/picky-rs/pull/78))

## [0.4.0] 2020-11-20

### Added

- OIDs from RFC8410 ([#72](https://github.com/Devolutions/picky-rs/pull/72))
- Support for Ed25519 `AlgorithmIdentifier` and `PublicKey` ([#72](https://github.com/Devolutions/picky-rs/pull/72))

## [0.3.4] 2020-10-21

### Changed

- `AlgorithmIdentifier` parser has been made more lenient.
  For instance, `rsa-export-0.1.1` crate does not serialize the "NULL" parameter with rsa encryption OID.
  Such input is not rejected anymore.

## [0.3.3] 2020-10-13

### Added

- Documentation on `oids` module.

## [0.3.2] 2020-09-04

### Added

- `legacy` feature to support previously valid `RSAPrivateKey` with 6 components instead of 9 as specified by the RFC.
  Missing components are instead computed on the fly as required.

## [0.3.1] 2020-08-31

### Changed

- Update dependencies

## [0.3.0] 2020-08-21

### Added

- `DigestInfo` from RFC8017

### Changed

- `RSAPrivateKey` fields are now `pub`
- `PrivateKeyInfo::new_rsa_encryption` takes 6 arguments instead of 8

### Deprecated

- `RSAPrivateKey` getters are deprecated in favor of direct access of public fields

## [0.2.0] 2020-08-20

### Added

- NIST signature related OIDs
- `AlgorithmIdentifier::new_sha3_384_with_rsa_encryption` constructor
- `AlgorithmIdentifier::new_sha3_512_with_rsa_encryption` constructor
- Support for email attribute in certificate subject

### Changed

- Rename "organisation" to "organization"
- Change attribute structure in directory names to follow common practices

### Fixed

- `RSAPrivateKey` is now RFC8017 compliant

