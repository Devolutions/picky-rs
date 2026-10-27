# picky-crypto-bundle

## Purpose

A single, named provider composed from the workspace's backends and fill-in providers, exposed through one `provider()` function.

It is what the convenience features of consuming libraries install: each forwards to this crate's features, so every library installs the same provider and the result does not depend on which library installs first.
Binaries may install it explicitly or build their own composition.

## Invariants

- Its composition is fixed and documented: every enabled backend in a fixed order (aws-lc, then ring, then RustCrypto), each a fallback for the previous, then the key-based KDFs that `picky-crypto-composed` builds over that composition, then `picky-crypto-ffdh` using the first random entry available.
- It has no default features.
  Each backend and each fill-in provider is behind its own feature, and `all` enables everything available.
- Features are additive: enabling a feature only adds entries, so dependents that enable different features still get one deterministic provider, though an earlier backend's entry can refuse inputs a later one accepted (`CONTRACT.md` §11).
- It contains no cryptographic code.
  It only assembles providers from the crates above.
- It installs nothing itself.
  Only the convenience features of consuming libraries install it.
- It is a non-FIPS convenience and applies no policy.
  FIPS binaries install a FIPS-capable backend with the FIPS policy explicitly.
