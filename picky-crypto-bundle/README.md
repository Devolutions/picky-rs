# picky-crypto-bundle

One named provider for the [picky-crypto contract], composed from the workspace's backends and fill-in providers and returned by `picky_crypto_bundle::provider()`.
The convenience features of consuming libraries enable this crate's features and install its provider, so every library in a build installs the same provider, whichever installs first.
A binary may also install it explicitly before its first cryptographic operation:

```rust
picky_crypto::install_default(picky_crypto_bundle::provider()).expect("no provider installed yet");
```

The crate contains no cryptographic code and installs nothing itself.

## Composition

`provider()` composes the enabled providers in this fixed order, each a fallback for the ones before it:

1. the enabled backends, in the order aws-lc, ring, RustCrypto (only RustCrypto is available);
2. with `composed`, [picky-crypto-composed] built over those backends, which adds the key-based KDFs;
3. with `ffdh`, [picky-crypto-ffdh], which adds the FFDH static key loader and ephemeral agreement using the first secure random entry among those backends.

Each fill-in entry is added only when the entries it is built from exist.
Without a backend, the provider therefore holds only the FFDH static key loader with `ffdh`, and is empty otherwise.
Features are additive: enabling one only adds members, so dependents enabling different features still get one deterministic provider.

Composition picks one member per algorithm, and per protection for MAC, cipher, AEAD and key-wrap entries, never per input (contract section 8.1).
An earlier member's entry therefore serves every input of the operations it advertises, including inputs it refuses as `Unsupported`.
A binary that needs inputs an earlier backend refuses, such as RSA key sizes that aws-lc does not load, composes its own provider with RustCrypto first.

## FIPS

The bundle is a non-FIPS convenience and applies no policy.
Its `fips()` follows the composition rules of contract section 8.1; with RustCrypto or a fill-in provider enabled, it is `false`.
FIPS binaries install a FIPS-capable backend behind the FIPS policy explicitly instead.

## Features

Nothing is enabled by default.

| Feature | Adds |
|---|---|
| `rustcrypto` | [picky-crypto-rustcrypto] with its `all` feature |
| `composed` | One-step KDFs with SHA-1/256/384/512 and counter-mode KDFs with HMAC-SHA-1/256/384/512, over the enabled backends |
| `ffdh` | FFDH static key loading, and ephemeral agreement when an enabled backend has a secure random entry |
| `all` | Every feature above |

Each backend feature enables the whole backend.
Consuming libraries expose backend choices such as `rustcrypto` as their convenience features, and enable the fill-in providers their own features need through weak dependency features (for example `picky-crypto-bundle?/composed`).

## Conformance tests

The `picky-crypto-conformance` runner tests this provider with `all` through its `bundle` feature.
Initialize the published-vector submodule before running it:

```console
git submodule update --init
cargo test -p picky-crypto-conformance --features bundle
```

This crate's own tests cover only the entries each feature combination assembles.

[picky-crypto contract]: ../picky-crypto/CONTRACT.md
[picky-crypto-composed]: ../picky-crypto-composed/README.md
[picky-crypto-ffdh]: ../picky-crypto-ffdh/README.md
[picky-crypto-rustcrypto]: ../picky-crypto-rustcrypto/README.md
