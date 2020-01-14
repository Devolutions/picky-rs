# Changelog

## [0.2.2] 2020-01-14

### Fixed

- Fix `Asn1RawDer` behind Application/Context tags issue [#14](https://github.com/Devolutions/picky-rs/issues/14).

## [0.2.1] 2020-01-10

### Added

- `Asn1RawDer` wrapper for user-provided raw DER.

## [0.2.0] 2019-12-23

### Added

- Add `from_reader_with_max_len` deserialization function to limit how many bytes can be read at most.

### Changed

- `from_reader` function has a default limit of 10240 bytes before returning a truncated data error.
    Uses `from_reader_with_max_len` to change the limit.

### Fixed

- Fix various crash found by fuzzing.
