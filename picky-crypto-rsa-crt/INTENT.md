# picky-crypto-rsa-crt

## Purpose

Completes RSA private keys given as components into a full key, so that format code (SSH, PuTTY, JWK) can produce a PKCS#8 private key, the contract's single private-key encoding.

Input: `n`, `e`, `d`, `p`, `q`.
Output: `dP`, `dQ`, `qInv`.

This is key-format completion, not a standardized algorithm, so it is not a `picky-crypto` operation.
It lives in its own crate so that the arithmetic stays out of format crates, and so that FIPS binaries can exclude it from their dependency graph.

## Invariants

- It depends only on `crypto-bigint` and `zeroize`.
  It does not depend on the contract crate.
- It is a thin layer: `crypto-bigint` performs the arithmetic in constant time.
- No variable-time operation on secret values (`d`, `p`, `q` and the computed CRT values); in particular no `*_vartime` conversions on them.
- Intermediate secret values are zeroized.
- It checks that the inputs are consistent (`p × q = n`, and any other check `CONTRACT.md` or this crate's documentation lists), and returns an error on mismatch, never a panic.
- It only completes CRT parameters.
  It never factors `n`, generates keys or performs RSA operations.
- It is not FIPS-capable.
  FIPS binaries never depend on it, and the FIPS dependency-ban fixture bans `crypto-bigint`.
