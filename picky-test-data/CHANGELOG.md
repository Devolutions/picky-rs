# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.1.1](https://github.com/Devolutions/picky-rs/compare/picky-test-data-v0.1.0...picky-test-data-v0.1.1)] - 2025-01-16

### <!-- 4 -->Bug Fixes

- Symlinks to license files in packages (#339) ([1834c04f39](https://github.com/Devolutions/picky-rs/commit/1834c04f3930fb1bbf040deb6525b166e378b8aa)) 

  Use symlinks instead of copying files to avoid a “dirty” state during
  cargo publish and preserve VCS info. With #337 merged, CI handles
  publishing consistently, so developer environments no longer matter.


