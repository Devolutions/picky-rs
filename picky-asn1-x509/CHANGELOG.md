# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

