# picky-rs

Collection of crates related to cryptographic primitives, ASN.1 and PKI.
See each folder for individual description.

## Release workflow

- Create a new branch
- Make sure dependencies are up to date (`cargo upgrade` from [cargo-edit](https://crates.io/crates/cargo-edit#cargo-upgrade) companion will help)
- Make sure CHANGELOG.md files are up to date
- Open Pull Request for review
- Once CI is green and PR is approved, use [cargo-release](https://github.com/crate-ci/cargo-release) for each crate to release
	- `cargo release <NEXT VERSION>-rc.<RC NUMBER>` to release a new candidate version (do not finalize changelog)
	- `cargo release`, `cargo release patch`, `cargo release minor`, or `cargo release major` as appropriate otherwise. Refer to cargo-release's [reference](https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md)
- Merge PR _using merge_ commit to _preserve commits hash_

(TODO: move the last two steps to GitHub Actions)
