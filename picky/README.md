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

## FIPS build profiles

FIPS builds must opt out of the default RustCrypto backend and select the
AWS-LC provider.

AWS-LC:

```toml
picky = { version = "7", default-features = false, features = ["fips-aws-lc", "x509", "jose"] }
```

The AWS-LC profile supports SHA-256/384/512, RSA PKCS#1 v1.5 signatures
with SHA-2 and keys of at least 2048 bits, and ECDSA P-256/SHA-256 and
P-384/SHA-384. They reject legacy signature algorithms, key generation, SSH,
and PuTTY operations rather than falling back to the RustCrypto backend.

JWE encryption/decryption and PKCS#12 cryptographic operations are not
currently available in the AWS-LC FIPS profile and are rejected at compile
time when those features are selected.

The `jose` feature contains JOSE/JWT/JWE parsing and signature support without
enabling encryption crates. Select `jwe-crypto` for JWE encryption/decryption;
it is included by the default and `full` feature profiles. Select `pkcs12` for
PKCS#12 parsing and creation.

The provider feature enforces Picky's algorithm policy and backend routing. A
feature flag alone is not a compliance claim: deployment compliance also
depends on the linked module, platform, build configuration, module version,
and operating procedures covered by the applicable validation certificate.
