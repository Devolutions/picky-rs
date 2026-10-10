# picky-crypto-rustcrypto

A thin RustCrypto backend for the [picky-crypto contract].
Call `picky_crypto_rustcrypto::provider()` to build a provider with the enabled capability families.
Nothing is enabled by default; `all` enables every family below.
Every entry, loader and private key reports `fips() == false`.

Parsing and encoding formats need no provider; only code that performs cryptographic operations through `picky-crypto` does.

## Features and the library

The library consists of the crates below, at the versions locked by the workspace.
Dependencies needed internally do not enable additional provider entries.
MAC, CBC, AES-GCM and AES-KW entries support both applying and processing protection.

| Feature | Provider entries | Library crates |
|---|---|---|
| `digest` | SHA-1/224/256/384/512, SHA3-384/512; HMAC-SHA-1/224/256/384/512; PBKDF2 with those HMACs | sha1 0.11.0, sha2 0.11.0, sha3 0.12.0, digest 0.11.3, hmac 0.13.0, pbkdf2 0.13.0 |
| `aes` | AES-128/192/256-CBC without padding | aes 0.9.2, cbc 0.2.1, cipher 0.5.2 |
| `aead` | AES-128/192/256-GCM; secure random | aes-gcm 0.11.1, aes 0.9.2, getrandom 0.4.3 |
| `key-wrap` | AES-128/192/256-KW | aes-kw 0.3.1, aes 0.9.2 |
| `rsa` | PKCS#1 v1.5 verification with MD5, SHA-1/224/256/384/512 and SHA3-384/512; PKCS#1 v1.5 and OAEP-SHA-1/256 encryption; RSA private-key loading and 2048/3072/4096-bit generation; secure random | rsa 0.10.0-rc.18, md-5 0.11.0, sha1 0.11.0, sha2 0.11.0, sha3 0.12.0, getrandom 0.4.3, chacha20 0.10.2 |
| `nist-ec` | P-256/SHA-256, P-384/SHA-384 and P-521/SHA-512 ECDSA verification; ECDH, private-key loading and generation for those curves; secure random | p256/p384/p521 0.14.0, sha2 0.11.0, hmac 0.13.0, getrandom 0.4.3 |
| `curve25519` | Ed25519 verification, private-key loading and generation; X25519 ephemeral agreement and private-key loading; secure random | ed25519-dalek/ed25519/x25519-dalek 3.0.0, sha2 0.11.0, getrandom 0.4.3 |
| `legacy` | MD4, MD5, RC4, 3DES-EDE3-CBC and RC2-CBC | md4/md-5 0.11.0, digest 0.11.3, rc4 0.2.0, des/rc2 0.9.0, cbc 0.2.1, cipher 0.5.2 |
| `all` | Every family above | Every dependency above |

The library also includes these support crates, some reached through re-exports: aead 0.6.1, crypto-common 0.2.2, hybrid-array 0.4.15, typenum 1.20.1, crypto-bigint 0.7.5, elliptic-curve 0.14.1, ecdsa 0.17.0, signature 3.0.0, curve25519-dalek 5.0.0, pkcs8 0.11.0, spki 0.8.0, sec1 0.8.1, der 0.8.2, const-oid 0.10.2, rand_core 0.10.1 and zeroize 1.9.0.
PKCS#1 encoding is reached through rsa's pkcs1 0.8.0-rc.4 re-export.
Secret cleanup features are enabled wherever the library offers them, and adapter-owned secret copies and returned buffers use zeroizing storage.

Loaded RSA keys sign with every listed RSA signature algorithm, decrypt with every listed RSA encryption algorithm and export their public key.
Loaded EC keys sign and agree on their own curve and export their public key.
Loaded Ed25519 keys sign and export their public key; loaded X25519 keys agree and export their public key.
Enabling ed25519-dalek's `legacy_compatibility` feature anywhere in a build weakens this backend's Ed25519 signature `S` range check, because Cargo unifies features; this workspace bans it with cargo-deny.

Key-based KDFs and finite-field Diffie-Hellman are not provided; they come from other providers.
RSA key generation draws a 256-bit seed from the operating-system generator and expands it with ChaCha20, so a generator failure is reported instead of panicking.
RSA signing and decryption blind the private-key operation with the operating-system generator.
ECDSA signing mixes operating-system randomness into the RFC 6979 nonce as additional data.
RSA public keys beyond the rsa crate's limits (a modulus above 8192 bits or a public exponent above 2^33 − 1) are unsupported.
Private-key loading applies the same limits, although the rsa crate loads private keys of any modulus size.

## Conformance tests

The `picky-crypto-conformance` runner tests this backend with `all` through its `rustcrypto` feature.
Initialize the published-vector submodule before running it:

```console
git submodule update --init
cargo test -p picky-crypto-conformance --features rustcrypto
```

This crate's own tests cover adapter logic only.

[picky-crypto contract]: ../picky-crypto/CONTRACT.md
