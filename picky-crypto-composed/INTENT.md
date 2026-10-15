# picky-crypto-composed

## Purpose

Provider entries built from other providers' contract entries, for algorithms that at least one shipped backend's library lacks (Concat KDF, KBKDF).

This crate is where logic that a library lacks is allowed to live.
It keeps that logic out of backend adapters, visible to policy, and excluded from FIPS binaries.

## Invariants

- It depends only on the contract crate.
- It contains only provider entries; it offers no helper functions.
- Every entry is built only from contract operations of another provider.
  It contains no other cryptographic code.
- Every provider it builds reports `fips()` as `false`.
- An entry exists only if a consumer needs it and at least one shipped backend's library lacks it natively.
  When every shipped backend gains native support, the entry is removed.
- It is subject to the same minimality review as the contract.
