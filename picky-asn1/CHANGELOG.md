# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] 2020-07-07

### Changed

- Dependencies clean up

## [0.2.1] 2020-01-13

### Fixed

- Check for index out of bound in `IntegerAsn1::from_unsigned_bytes_be`

## [0.2.0] 2020-01-10

### Added

- Add `IntegerAsn1::from_unsigned_bytes_be`

### Changed

- Rename `IntegerAsn1::as_bytes_be` to `IntegerAsn1::as_unsigned_bytes_be`.
