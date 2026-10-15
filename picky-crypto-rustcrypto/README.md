# picky-crypto-rustcrypto

A thin RustCrypto backend for the [picky-crypto contract].
Call `picky_crypto_rustcrypto::provider()` to build a provider with the enabled capability families.
Nothing is enabled by default; `all` enables every family below.
Every entry, loader and private key reports `fips() == false`.

Parsing and encoding formats need no provider; only code that performs cryptographic operations through `picky-crypto` does.

## Features and the library

The library consists of the crates below; `Cargo.lock` records their versions.
Dependencies needed internally do not enable additional provider entries; families that draw randomness enable `random`, because they use its generator.
MAC, CBC, AES-GCM and AES-KW entries support both applying and processing protection.

| Feature | Provider entries | Library crates |
|---|---|---|
| `random` | Secure random from the operating-system generator | getrandom |
| `digest` | SHA-1/224/256/384/512, SHA3-384/512; HMAC-SHA-1/224/256/384/512; PBKDF2 with those HMACs | sha1, sha2, sha3, digest, hmac, pbkdf2 |
| `aes` | AES-128/192/256-CBC without padding | aes, cbc, cipher |
| `aead` | AES-128/192/256-GCM; enables `random` | aes-gcm, aes |
| `key-wrap` | AES-128/192/256-KW | aes-kw, aes |
| `rsa` | PKCS#1 v1.5 verification with MD5, SHA-1/224/256/384/512 and SHA3-384/512; PKCS#1 v1.5 and OAEP-SHA-1/256 encryption; RSA private-key loading and 2048/3072/4096-bit generation; enables `random` | rsa, md-5, sha1, sha2, sha3, chacha20 |
| `nist-ec` | P-256/SHA-256, P-384/SHA-384 and P-521/SHA-512 ECDSA verification; ECDH, private-key loading and generation for those curves; enables `random` | p256, p384, p521, sha2, hmac |
| `curve25519` | Ed25519 verification, private-key loading and generation; X25519 ephemeral agreement and private-key loading; enables `random` | ed25519-dalek, ed25519, x25519-dalek, sha2 |
| `legacy` | MD4, MD5, RC4, 3DES-EDE3-CBC and RC2-CBC | md4, md-5, digest, rc4, des, rc2, cbc, cipher |
| `all` | Every family above | Every dependency above |

The library also includes these support crates, some reached through re-exports: aead, crypto-common, hybrid-array, typenum, crypto-bigint, elliptic-curve, ecdsa, signature, curve25519-dalek, pkcs8, spki, sec1, der, const-oid, rand_core and zeroize.
PKCS#1 encoding is reached through rsa's pkcs1 re-export.
Secret cleanup features are enabled wherever the library offers them, and adapter-owned secret copies and returned buffers use zeroizing storage.

Loaded RSA keys sign with every listed RSA signature algorithm, decrypt with every listed RSA encryption algorithm and export their public key.
Loaded EC keys sign and agree on their own curve and export their public key.
Loaded Ed25519 keys sign and export their public key; loaded X25519 keys agree and export their public key.
Enabling ed25519-dalek's `legacy_compatibility` feature anywhere in a build weakens the library's Ed25519 signature `S` range check, because Cargo unifies features.
The adapter therefore checks `S < L` itself (RFC 8032 §5.1.7), and this workspace bans the feature with cargo-deny.

Key-based KDFs and finite-field Diffie-Hellman are not provided; they come from other providers.
RSA key generation draws a 256-bit seed from the operating-system generator and expands it with ChaCha20, so a generator failure is reported instead of panicking.
RSA signing and decryption blind the private-key operation with the operating-system generator.
PKCS#1 v1.5 decryption is subject to RUSTSEC-2023-0071 (the Marvin timing attack), for which the rsa crate has no fixed release.
In the locked rsa version the padding checks use constant-time comparisons, except the minimum padding-length check, which the crate flags as possibly not constant time (`src/algorithms/pkcs1v15.rs`, `decrypt_inner`).

Every invalid padding is reported as the same `VerificationFailed` error, as the contract requires.
This removes distinguishable errors, not timing differences inside the RSA operation; a protocol exposed to padding oracles applies its own countermeasure.

ECDSA signing mixes operating-system randomness into the RFC 6979 nonce as additional data.
RSA public keys beyond the rsa crate's limits (a modulus above 8192 bits or a public exponent above 2^33 − 1) are unsupported.
Private-key loading applies the same limits, although the rsa crate loads private keys of any modulus size.
Encoded RSA public keys longer than the largest encoding within those limits are unsupported before they are decoded, whether or not they are also malformed.
Private keys get no such cap, because the decoder skips PKCS#8 attributes of any length; their modulus and exponent are checked after parsing, before key construction.

## Conformance tests

The `picky-crypto-conformance` runner tests this backend with `all` through its `rustcrypto` feature.
Initialize the published-vector submodule before running it:

```console
git submodule update --init
cargo test -p picky-crypto-conformance --features rustcrypto
```

This crate's own tests cover adapter logic only.

[picky-crypto contract]: ../picky-crypto/CONTRACT.md
