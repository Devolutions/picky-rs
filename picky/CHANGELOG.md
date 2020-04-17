# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNPUBLISHED] (5.0.0)

### Changed

- `Jwt` has no generic lifetime parameter anymore

### Removed

- `Cert::verify` and `Cert::verify_chain` methods (previously deprecated)

## [4.7.0] 2020-04-16

### Added

- Implement `From<UTCDate>` trait on `DateTime<Utc>`
- Support for leeway in HTTP signature verifier
- Verifier API to X509 Cert

### Deprecated

- `Cert::verify` and `Cert::verify_chain` methods in favor of the `Cert::verifier` method
