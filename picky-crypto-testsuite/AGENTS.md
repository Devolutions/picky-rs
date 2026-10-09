# picky-crypto-testsuite

`INTENT.md` states the principles for vectors, derived inputs and failing tests.
Sources, versions and checksums are in `vectors/manifest.toml`; `cargo xtask check-vectors` checks it.

## Changing the vector set

- Add vectors only for algorithms and parameters the contract defines.
- Wycheproof is the `vectors/wycheproof` submodule.
  To add or update its vectors, move the pinned commit (submodule and manifest together), list the files the suite reads, and rerun the suite against every backend.
- Other sources are vendored.
  Vendor a whole upstream file when all of it applies; otherwise keep whole groups, cut only at group headers, and record the rule as the entry's `extract`.
  Record the source URL and version; the checksum is `git hash-object --no-filters <file>`.
- To update a vendored source, replace its files wholesale and rerun the suite against every backend.
- Never edit a vector file or trim inside a group.
- Report newly failing vectors, and the size of any vendored data added.
