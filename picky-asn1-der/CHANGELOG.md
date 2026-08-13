# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.5.7](https://github.com/Devolutions/picky-rs/compare/picky-asn1-der-v0.5.6...picky-asn1-der-v0.5.7)] - 2026-08-13

### <!-- 0 -->Security

- Bump base64 from 0.22.1 to 0.23.0 ([#520](https://github.com/Devolutions/picky-rs/issues/520)) ([0e921e41d0](https://github.com/Devolutions/picky-rs/commit/0e921e41d0d08523748254c4a9a234c4cc28424f)) 

  Bumps [base64](https://github.com/marshallpierce/rust-base64) from
  0.22.1 to 0.23.0.
  <details>
  <summary>Changelog</summary>
  <p><em>Sourced from <a
  href="https://github.com/marshallpierce/rust-base64/blob/master/RELEASE-NOTES.md">base64's
  changelog</a>.</em></p>
  <blockquote>
  <h1>0.23.0</h1>
  <ul>
  <li>Added more consts for preconfigured configs and engines</li>
  <li>Make DecodeError::InvalidLastSymbol more clear by including the
  decoded value</li>
  <li>Added SIMD-accelerated engines behind the default-on
  <code>simd-unsafe</code> feature: <code>Simd</code> picks the best
  instruction set at runtime (AVX2 on <code>x86_64</code>, NEON on
  <code>aarch64</code>) and falls back to the scalar
  <code>GeneralPurpose</code> engine, while <code>Avx2</code> and
  <code>Neon</code> target one instruction set with no runtime
  detection and work in <code>no_std</code>. The engines support the
  standard and URL-safe alphabets.</li>
  <li>Update MSRV to 1.71.0</li>
  <li>Add support for custom padding symbols</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[9e9220a4166f628de7c8803289e120ae1e944f78](https://github.com/Devolutions/picky-rs/commit/9e9220a4166f628de7c8803289e120ae1e944f78)](https://github.com/Devolutions/picky-rs/commit/[9e9220a4166f628de7c8803289e120ae1e944f78](https://github.com/Devolutions/picky-rs/commit/9e9220a4166f628de7c8803289e120ae1e944f78))"><code>9e9220a</code></a>
  v0.23.0</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[870326ec592eebde9d6bfe4c5d8130c591273e9c](https://github.com/Devolutions/picky-rs/commit/870326ec592eebde9d6bfe4c5d8130c591273e9c)](https://github.com/Devolutions/picky-rs/commit/[870326ec592eebde9d6bfe4c5d8130c591273e9c](https://github.com/Devolutions/picky-rs/commit/870326ec592eebde9d6bfe4c5d8130c591273e9c))"><code>870326e</code></a>
  Merge pull request <a
  href="https://redirect.github.com/marshallpierce/rust-base64/issues/306">#306</a>
  from marshallpierce/mp/trailing-bits-docs</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[fbec5f1050f9fc16e6a826ebabaa2b7b0644bd67](https://github.com/Devolutions/picky-rs/commit/fbec5f1050f9fc16e6a826ebabaa2b7b0644bd67)](https://github.com/Devolutions/picky-rs/commit/[fbec5f1050f9fc16e6a826ebabaa2b7b0644bd67](https://github.com/Devolutions/picky-rs/commit/fbec5f1050f9fc16e6a826ebabaa2b7b0644bd67))"><code>fbec5f1</code></a>
  Document no trailing trailing bits</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[0a23549968f059b53cf39e96eba8f46779f322a7](https://github.com/Devolutions/picky-rs/commit/0a23549968f059b53cf39e96eba8f46779f322a7)](https://github.com/Devolutions/picky-rs/commit/[0a23549968f059b53cf39e96eba8f46779f322a7](https://github.com/Devolutions/picky-rs/commit/0a23549968f059b53cf39e96eba8f46779f322a7))"><code>0a23549</code></a>
  Merge pull request <a
  href="https://redirect.github.com/marshallpierce/rust-base64/issues/305">#305</a>
  from marshallpierce/mp/edition-2021</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[f10b7e20614135aa61289140683fc93e5a45d338](https://github.com/Devolutions/picky-rs/commit/f10b7e20614135aa61289140683fc93e5a45d338)](https://github.com/Devolutions/picky-rs/commit/[f10b7e20614135aa61289140683fc93e5a45d338](https://github.com/Devolutions/picky-rs/commit/f10b7e20614135aa61289140683fc93e5a45d338))"><code>f10b7e2</code></a>
  Update deps &amp; edition</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[9d21a598860645cb6290940e7a43033bc43ebd74](https://github.com/Devolutions/picky-rs/commit/9d21a598860645cb6290940e7a43033bc43ebd74)](https://github.com/Devolutions/picky-rs/commit/[9d21a598860645cb6290940e7a43033bc43ebd74](https://github.com/Devolutions/picky-rs/commit/9d21a598860645cb6290940e7a43033bc43ebd74))"><code>9d21a59</code></a>
  Merge pull request <a
  href="https://redirect.github.com/marshallpierce/rust-base64/issues/304">#304</a>
  from marshallpierce/mp/custom-padding-rebase</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[f70bad2caaa85350b95d988bfb9a0997e824bfd8](https://github.com/Devolutions/picky-rs/commit/f70bad2caaa85350b95d988bfb9a0997e824bfd8)](https://github.com/Devolutions/picky-rs/commit/[f70bad2caaa85350b95d988bfb9a0997e824bfd8](https://github.com/Devolutions/picky-rs/commit/f70bad2caaa85350b95d988bfb9a0997e824bfd8))"><code>f70bad2</code></a>
  Support custom padding symbols</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[684d79cd3deb8dfd5323619634c75bc0ff6edfd9](https://github.com/Devolutions/picky-rs/commit/684d79cd3deb8dfd5323619634c75bc0ff6edfd9)](https://github.com/Devolutions/picky-rs/commit/[684d79cd3deb8dfd5323619634c75bc0ff6edfd9](https://github.com/Devolutions/picky-rs/commit/684d79cd3deb8dfd5323619634c75bc0ff6edfd9))"><code>684d79c</code></a>
  Merge pull request <a
  href="https://redirect.github.com/marshallpierce/rust-base64/issues/301">#301</a>
  from marshallpierce/mp/simd-gardening</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[5bf66f2646c6fd99e1b18bf4e2bb0a47d34e1eaa](https://github.com/Devolutions/picky-rs/commit/5bf66f2646c6fd99e1b18bf4e2bb0a47d34e1eaa)](https://github.com/Devolutions/picky-rs/commit/[5bf66f2646c6fd99e1b18bf4e2bb0a47d34e1eaa](https://github.com/Devolutions/picky-rs/commit/5bf66f2646c6fd99e1b18bf4e2bb0a47d34e1eaa))"><code>5bf66f2</code></a>
  Merge pull request <a
  href="https://redirect.github.com/marshallpierce/rust-base64/issues/284">#284</a>
  from AbeZbm/add-tests</li>
  <li><a
  href="https://github.com/marshallpierce/rust-base64/commit/[[d3831cfbf7dafe226a8383450c3410e2f67c826a](https://github.com/Devolutions/picky-rs/commit/d3831cfbf7dafe226a8383450c3410e2f67c826a)](https://github.com/Devolutions/picky-rs/commit/[d3831cfbf7dafe226a8383450c3410e2f67c826a](https://github.com/Devolutions/picky-rs/commit/d3831cfbf7dafe226a8383450c3410e2f67c826a))"><code>d3831cf</code></a>
  Followups to SIMD work</li>
  <li>Additional commits viewable in <a
  href="https://github.com/marshallpierce/rust-base64/compare/v0.22.1...v0.23.0">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  
  [![Dependabot compatibility
  score](https://dependabot-badges.githubapp.com/badges/compatibility_score?dependency-name=base64&package-manager=cargo&previous-version=0.22.1&new-version=0.23.0)](https://docs.github.com/en/github/managing-security-vulnerabilities/about-dependabot-security-updates#about-compatibility-scores)
  
  Dependabot will resolve any conflicts with this PR as long as you don't
  alter it yourself. You can also trigger a rebase manually by commenting
  `@dependabot rebase`.



## [[0.5.6](https://github.com/Devolutions/picky-rs/compare/picky-asn1-der-v0.5.5...picky-asn1-der-v0.5.6)] - 2026-04-21

### <!-- 7 -->Build

- Upgrade RustCrypto dependencies ([#476](https://github.com/Devolutions/picky-rs/issues/476)) ([8ce838e347](https://github.com/Devolutions/picky-rs/commit/8ce838e3470ac605c912f61dc67c1c6d388b140d)) 

## [[0.5.5](https://github.com/Devolutions/picky-rs/compare/picky-asn1-der-v0.5.4...picky-asn1-der-v0.5.5)] - 2026-02-02

### <!-- 7 -->Build

- Update crypto dependencies ([#448](https://github.com/Devolutions/picky-rs/issues/448)) ([0bf42c1c4b](https://github.com/Devolutions/picky-rs/commit/0bf42c1c4bd727eaf5b4b0a877e8698986e0bd37)) 


## [[0.5.4](https://github.com/Devolutions/picky-rs/compare/picky-asn1-der-v0.5.3...picky-asn1-der-v0.5.4)] - 2025-10-21

### <!-- 7 -->Build

- Remove lazy_static ([#424](https://github.com/Devolutions/picky-rs/issues/424)) ([d96e761fba](https://github.com/Devolutions/picky-rs/commit/d96e761fbaf7e4061a9488240e3f6426a53cc6b1)) 

### Changed

- Bump minimal rustc version to 1.85.

## [[0.5.3](https://github.com/Devolutions/picky-rs/compare/picky-asn1-der-v0.5.2...picky-asn1-der-v0.5.3)] - 2025-09-26

### <!-- 7 -->Build

- Bump the crypto group across 1 directory with 3 updates (#388) ([58d179a0c3](https://github.com/Devolutions/picky-rs/commit/58d179a0c39d701025a363c3f294912c2881a8f5)) 

## [[0.5.2](https://github.com/Devolutions/picky-rs/compare/picky-asn1-der-v0.5.1...picky-asn1-der-v0.5.2)] - 2025-01-16

### <!-- 4 -->Bug Fixes

- Symlinks to license files in packages (#339) ([1834c04f39](https://github.com/Devolutions/picky-rs/commit/1834c04f3930fb1bbf040deb6525b166e378b8aa)) 

  Use symlinks instead of copying files to avoid a “dirty” state during
  cargo publish and preserve VCS info. With #337 merged, CI handles
  publishing consistently, so developer environments no longer matter.

## [0.5.1] 2024-11-26

### Changed

- Update dependencies

## [0.5.0] 2024-07-12

### Changed

- Bump minimal rustc version to 1.61
- Update dependencies

## [0.4.1] 2023-08-23

### Fixed

- License files are now correctly included in the published package

### Changed

- Update dependencies

## [0.4.0] 2022-11-07

### Added

- Derive additional traits for some types ([#171](https://github.com/Devolutions/picky-rs/pull/171))

## [0.3.1] 2022-05-19

### Changed

- Make `ApplicationTag`’s inner value public
- Update dependencies

## [0.3.0] 2022-02-02

### Added

- Support for `GeneralString`
- `ApplicationTag` to encode ASN.1 application tags

### Changed

- Bump minimal rustc version to 1.56

## [0.2.5] 2021-05-27

### Added

- Support for `BMP_STRING` type

## [0.2.4] 2020-08-31

### Changed

- Update dependencies

## [0.2.3] 2020-07-07

### Changed

- Dependencies clean up

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
