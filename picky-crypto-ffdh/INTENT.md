# picky-crypto-ffdh

## Purpose

`picky-crypto` fill-in provider offering finite-field Diffie-Hellman, implemented over `crypto-bigint`.

No reference library offers FFDH in a usable shape.
This crate fills that gap for non-FIPS binaries (PKINIT, PKU2U and DPAPI) while keeping the operation inside a provider, where policy and the availability check can see it.
It is generic over any base: it takes a random entry from another provider at construction, so it can be composed with any backend.

## Invariants

- It depends only on the contract crate, `crypto-bigint` and `zeroize`.
- It is a fill-in provider, not an adapter: it implements FFDH itself, with `crypto-bigint` performing the arithmetic, and performs every domain-parameter and peer-value check that `CONTRACT.md` requires.
- No variable-time operation on secret values (private exponent, shared secret), including in range checks, conversions and serialization.
- Secret values are zeroized when dropped.
- Randomness comes only from the contract random entry it is given.
- It only provides FFDH.
  Any other algorithm returns `Unsupported`.
- `fips()` always returns `false`, so the FIPS policy excludes it.
