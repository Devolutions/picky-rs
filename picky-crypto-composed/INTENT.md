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
- It builds an entry for every key-based KDF the contract defines whose underlying hash or MAC entry the base provider supplies; which KDFs exist is decided by the contract's minimality rules, not by this crate.
  When every shipped backend provides these KDFs natively, this crate is removed.
- It is subject to the same minimality review as the contract.
