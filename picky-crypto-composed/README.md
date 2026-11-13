# picky-crypto-composed

Key-based KDF entries for the [picky-crypto contract], built from another provider's hash and HMAC entries.
This is a fill-in provider for backends whose library lacks these KDFs; it builds them only from those entries and contains no other cryptographic code.
Call `picky_crypto_composed::provider(&base)` with the provider whose entries the KDFs should use, then add the result as a fallback to that provider.
Contract sections 6.4 and 11 define the entries and explain why they live outside a backend.

## Entries

| Entry | Built from | Definition |
|---|---|---|
| One-step KDF with SHA-1, SHA-256, SHA-384 or SHA-512 | `base`'s hash entry for that hash | NIST SP 800-56C rev. 2 section 4.1, option 1 |
| Counter-mode KDF with HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-384 or HMAC-SHA-512 | `base`'s HMAC entry, if it supports tag generation | NIST SP 800-108 rev. 1 section 4.1, counter before the fixed input |

It builds an entry for every key-based KDF the contract defines whose hash or HMAC entry `base` supplies, so the provider is empty when `base` has none of them.
`provider` takes the entries when called and never consults `base` or the process-wide default afterwards.
Counter-mode blocks are generated tags, taken through `MacGeneration`, so a MAC entry that only verifies cannot serve.
Every entry reports `fips() == false`, so the FIPS policy rejects any composition with this provider.

Errors from the underlying entries propagate unchanged, except `Unsupported`, which names the KDF instead.
An underlying entry that returns a block of the wrong length makes the derivation fail with `ProviderFailure`.
Output from 2^31 bytes up to (2^32 − 1) × the hash length is `Unsupported`, a capacity limit far above the contract's 64-byte must-support maximum.

## Conformance tests

The `picky-crypto-conformance` runner tests this provider as part of [picky-crypto-bundle], over the RustCrypto backend, through its `bundle` feature.
Initialize the published-vector submodule before running it:

```console
git submodule update --init
cargo test -p picky-crypto-conformance --features bundle
```

This crate's own tests cover only which entries it builds and their FIPS reports, tag generation for counter-mode blocks, the one-step counter after the first block, the block-count bound, error mapping and the block-length check.

[picky-crypto contract]: ../picky-crypto/CONTRACT.md
[picky-crypto-bundle]: ../picky-crypto-bundle/README.md
