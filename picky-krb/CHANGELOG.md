# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.9.3](https://github.com/Devolutions/picky-rs/compare/picky-krb-v0.9.2...picky-krb-v0.9.3)] - 2025-02-04

### <!-- 0 -->Security

- Implement Kerberos encryption without a checksum (#342) ([90eab0150a](https://github.com/Devolutions/picky-rs/commit/90eab0150a6645b667ad2eb49085f0de5556ebd2)) 

  Added the possibility of Kerberos encryption but without a checksum.
  This functionality is needed to support `SECBUFFER_READONLY` and
  `SECBUFFER_READONLY_WITH_CHECKSUM` flags for security buffers in `sspi-rs`.

### <!-- 4 -->Bug Fixes

- Symlinks to license files in packages (#339) ([1834c04f39](https://github.com/Devolutions/picky-rs/commit/1834c04f3930fb1bbf040deb6525b166e378b8aa)) 

  Use symlinks instead of copying files to avoid a “dirty” state during
  cargo publish and preserve VCS info. With #337 merged, CI handles
  publishing consistently, so developer environments no longer matter.


## [0.9.2] 2024-11-26

### Changed

- Update dependencies

## [0.9.1] 2024-11-19

### Changed

- Update dependencies

## [0.9.0] 2024-07-12

### Changed

- Bump minimal rustc version to 1.61
- Update dependencies

## [0.8.0] 2023-08-24

### Fixed

- License files are now correctly included in the published package
- Creds and key spec constants
- Credssp password and smartcard structs

### Changed

- Update dependencies

## [0.7.1]

### Changed

- Update dependencies

## [0.7.0]

### Improvement

- Pretty string representation and description for error codes

## [0.6.0] 2023-02-14

### Added

- Add Kerberos error codes([#199](https://github.com/Devolutions/picky-rs/pull/199))
- Fix ToString impl for KrbErrorInner ([#194](https://github.com/Devolutions/picky-rs/pull/194))

## [0.5.0] 2022-11-07

### Added

- Useful features for PKU2U support in sspi-rs ([#186](https://github.com/Devolutions/picky-rs/pull/186))

## [0.4.0] 2022-09-01

### Added

-  Kerberos crypto algorithms([#173](https://github.com/Devolutions/picky-rs/pull/173))

## [0.3.1] 2022-07-28

### Added

- Add constants related to SECBUFFER_CHANNEL_BINDINGS([#163](https://github.com/Devolutions/picky-rs/pull/163))

## [0.3.0] 2022-07-18

### Added

- Kerberos "Change password" protocol ([#155](https://github.com/Devolutions/picky-rs/pull/155))

## [0.2.0] 2022-05-27

### Added

- Missing Kerberos name type constants ([#150](https://github.com/Devolutions/picky-rs/pull/150))

## [0.1.0] 2022-05-19

Initial version

