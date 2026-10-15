# picky-crypto-rustcrypto

## Purpose

`picky-crypto` backend implemented on top of the RustCrypto crates.

It implements every algorithm of the contract that RustCrypto provides when the `all` feature is enabled, including legacy algorithms (MD4, MD5, RC4, 3DES, RC2) needed by NTLM, Kerberos and legacy PKCS#12.
No family is enabled by default; each feature adds a family of entries.

## Invariants

- `fips()` always returns `false`, because RustCrypto has no FIPS 140 validated module, so the FIPS policy rejects any provider containing its entries.
