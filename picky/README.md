[![Crates.io](https://img.shields.io/crates/v/picky.svg)](https://crates.io/crates/picky)
[![docs.rs](https://docs.rs/picky/badge.svg)](https://docs.rs/picky)
![Crates.io](https://img.shields.io/crates/l/picky)

Compatible with rustc 1.85.
Minimal rustc version bumps happen [only with minor number bumps in this project](https://github.com/Devolutions/picky-rs/issues/89#issuecomment-868303478).

# picky

Portable X.509, PKI, JOSE and HTTP signature implementation.

## X.509 / PKI

[See doc](https://docs.rs/picky/latest/picky/x509/index.html) for tested examples.

## HTTP signature

[See doc](https://docs.rs/picky/latest/picky/http/index.html) for tested examples.

## JOSE

Doc doesn't have example yet, but [tests](https://github.com/Devolutions/picky-rs/blob/master/picky/src/jose/jwt.rs#L438) are good reference.

## FIPS build profile

FIPS builds use the AWS-LC FIPS provider and must opt out of the default
RustCrypto backend:

```toml
picky = { version = "7", default-features = false, features = ["fips-aws-lc", "x509", "jose"] }
```

The FIPS profile currently supports SHA-256/384/512, RSA PKCS#1 v1.5
signatures with SHA-2 and keys of at least 2048 bits, and ECDSA P-256/SHA-256
and P-384/SHA-384. It rejects legacy signature algorithms, key generation, JWE
encryption/decryption, PKCS#12, SSH, and PuTTY operations rather than falling
back to the RustCrypto backend.

`fips-aws-lc` selects a cryptographic module, but deployment compliance also
depends on using a platform, build configuration, and module version covered by
the applicable validation certificate.
