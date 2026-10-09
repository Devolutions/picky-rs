# picky-crypto

`picky-crypto` defines the minimal cryptographic provider contract for picky and its consumers, with capability entries, explicit provider composition and zeroizing outputs.
It contains no cryptographic backend or format parser.

[CONTRACT.md] is the normative contract; [INTENT.md] states its purpose and invariants.
Read the contract with resolved item links in the crate documentation: run `cargo doc -p picky-crypto --open` and open the `contract` module, or use [docs.rs] when the crate is published.

[CONTRACT.md]: CONTRACT.md
[INTENT.md]: INTENT.md
[docs.rs]: https://docs.rs/picky-crypto/latest/picky_crypto/contract/
