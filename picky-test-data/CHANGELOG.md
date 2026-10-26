# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [[0.1.2](https://github.com/Devolutions/picky-rs/compare/picky-test-data-v0.1.1...picky-test-data-v0.1.2)] - 2026-10-26

### <!-- 4 -->Bug Fixes

- Expose the Authenticode signature fixture as `PSDIAG_SIGNATURE` ([#534](https://github.com/Devolutions/picky-rs/issues/534)) ([76881c4ee7](https://github.com/Devolutions/picky-rs/commit/76881c4ee70089accab4c84fb26c37cf3ff12b97))
- Add `SSH_PRIVATE_KEY_EC_P256_LEADING_ZERO` and `SSH_PRIVATE_KEY_ED25519_LEADING_ZERO` fixtures ([#557](https://github.com/Devolutions/picky-rs/issues/557)) ([122303e05e](https://github.com/Devolutions/picky-rs/commit/122303e05e692b083e01834805fe5fdab87cdac3))
- Add `PUTTY_KEY_EC_P256_LEADING_ZERO`, `PUTTY_KEY_ED25519_LEADING_ZERO` and `PUTTY_KEY_ED25519_V2_SHORT_SECRET` fixtures ([#557](https://github.com/Devolutions/picky-rs/issues/557)) ([122303e05e](https://github.com/Devolutions/picky-rs/commit/122303e05e692b083e01834805fe5fdab87cdac3))

### <!-- 6 -->Documentation

- Make test-data source URLs clickable in the API documentation ([a50971d365](https://github.com/Devolutions/picky-rs/commit/a50971d3651368bdefeed607708bad81bdad97a6))

### Changed

- Bump minimal rustc version to 1.85.

## [[0.1.1](https://github.com/Devolutions/picky-rs/compare/picky-test-data-v0.1.0...picky-test-data-v0.1.1)] - 2025-01-16

### <!-- 4 -->Bug Fixes

- Symlinks to license files in packages (#339) ([1834c04f39](https://github.com/Devolutions/picky-rs/commit/1834c04f3930fb1bbf040deb6525b166e378b8aa)) 

  Use symlinks instead of copying files to avoid a “dirty” state during
  cargo publish and preserve VCS info. With #337 merged, CI handles
  publishing consistently, so developer environments no longer matter.


