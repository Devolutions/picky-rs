# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [[0.1.2](https://github.com/Devolutions/picky-rs/compare/picky-test-data-v0.1.1...picky-test-data-v0.1.2)] - 2026-10-10

### <!-- 4 -->Bug Fixes

- Don't panic on RFC 3161 timestamp fallback ([#534](https://github.com/Devolutions/picky-rs/issues/534)) ([76881c4ee7](https://github.com/Devolutions/picky-rs/commit/76881c4ee70089accab4c84fb26c37cf3ff12b97)) 

  `h_verify_signing_certificate` holds a mutable borrow of the validator
  state for its whole body, and the `MsCounterSign` fallback (expired
  signing certificate, RFC 3161 timestamp) borrows it again to read the
  CTL. With the `ctl` feature, verifying such a signature panics with
  `already mutably borrowed: BorrowError`, whether or not a CTL is set.
  The borrow is only read, so it's now shared.
  
  The new test verifies the psdiag signature after its signing certificate
  expired; it panics without the fix. The signature moves from
  `full_validation_authenticode_signature_with_well_known_ca` to
  `picky-test-data` so both tests share it.

- Keep leading zero bytes in key components ([#557](https://github.com/Devolutions/picky-rs/issues/557)) ([122303e05e](https://github.com/Devolutions/picky-rs/commit/122303e05e692b083e01834805fe5fdab87cdac3)) 

  EC coordinates and secrets, and Ed25519 secrets, have a fixed length,
  but several decoding paths trimmed their leading zero bytes and then
  required the full length.
  Keys with such a byte were rejected, or decoded to a short secret that
  failed later when signing.
  This affected keys built from components or decoded from JWK, OpenSSH or
  PuTTY: about 1 in 128 P-256 and P-384 public keys and 1 in 256 of their
  decoded private keys, most P-521 keys, and 1 in 256 Ed25519 keys.
  
  - `PublicKey::from_ec_components` and `PrivateKey::from_ec_components`
  left-pad coordinates and secrets to the field length and reject longer
  values.
  - JWK EC decoding accepts full-length coordinates that start with zero
  bytes, so P-521 keys such as the RFC 7520 example now convert to
  `PublicKey`, and rejects any other length, as RFC 7518 section 6.2.1.2
  requires.
  - `Jwk::from_public_key` and `JwkKeyType::new_ec_key` emit full-length
  coordinates: `new_ec_key` removes or adds leading zero bytes to reach
  the field length, so signed coordinates with a sign byte still work, and
  passes longer coordinates through unchanged for `to_public_key` to
  reject.
  - OpenSSH and PuTTY ECDSA decoding left-pad the `mpint` secret to the
  field length.
  - OpenSSH Ed25519 decoding reads the private key as the fixed 64-byte
  string it is.
  - PuTTY Ed25519 decoding restores the trailing zero bytes that PuTTY
  before 0.75 omits from its little-endian secret, still reads the
  big-endian `mpint` that earlier picky versions wrote, and rejects a
  secret that does not match the public key.
  - PuTTY Ed25519 encoding writes the full 32-byte secret, as PuTTY 0.75
  and later do, instead of a minimal `mpint`.
  
  JWK EC output changes for keys whose coordinates start with a zero byte:
  they are now encoded at full length.
  Short coordinates were already rejected on decoding; coordinates with
  extra leading zero bytes beyond the field length are now rejected as
  well.
  
  The OpenSSH and PuTTY test keys are generated with `ssh-keygen` and
  `puttygen`; `picky-test-data/test_assets/ssh/README.md` records the
  commands.
  
  ---------



### Changed

- Bump minimal rustc version to 1.85.

## [[0.1.1](https://github.com/Devolutions/picky-rs/compare/picky-test-data-v0.1.0...picky-test-data-v0.1.1)] - 2025-01-16

### <!-- 4 -->Bug Fixes

- Symlinks to license files in packages (#339) ([1834c04f39](https://github.com/Devolutions/picky-rs/commit/1834c04f3930fb1bbf040deb6525b166e378b8aa)) 

  Use symlinks instead of copying files to avoid a “dirty” state during
  cargo publish and preserve VCS info. With #337 merged, CI handles
  publishing consistently, so developer environments no longer matter.


