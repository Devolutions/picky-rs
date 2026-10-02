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

FIPS builds must opt out of the default RustCrypto backend and select exactly
one provider.

AWS-LC:

```toml
picky = { version = "7", default-features = false, features = ["fips-aws-lc", "x509", "jose"] }
```

wolfCrypt:

```toml
picky = { version = "7", default-features = false, features = ["fips-wolfcrypt", "x509", "jose"] }
```

`fips-wolfcrypt` uses the official `wolfssl-wolfcrypt` wrapper and links a
separately installed wolfSSL library. Set `WOLFSSL_PREFIX` to an installation
prefix containing `include/wolfssl` and `lib/libwolfssl`:

```sh
WOLFSSL_PREFIX=/opt/wolfssl-fips cargo build \
  --no-default-features --features fips-wolfcrypt,x509,jose
```

The wolfSSL installation is not supplied by Picky. A FIPS deployment requires
the exact validated wolfCrypt source, configuration, platform, and operational
environment covered by the applicable certificate, including successful
startup self-tests. Obtain the validated source and commercial license from
wolfSSL. The crates.io wrapper and wolfSSL library are GPL-licensed unless the
deployment has an appropriate commercial license. Public CI can validate the
wrapper integration against an ordinary wolfSSL build, but that does not make
the CI library or resulting artifact FIPS validated.

The pinned `wolfssl-wolfcrypt` 2.2.0 release currently requires Rust 1.88
because its build script uses a let-chain stabilized after Picky's base Rust
1.85 MSRV. It also has an upstream bindgen type mismatch on MSVC, so this
provider profile is integration-tested on Linux. The default RustCrypto and
AWS-LC profiles retain Picky's Rust 1.85 MSRV.

Both profiles currently support SHA-256/384/512, RSA PKCS#1 v1.5 signatures
with SHA-2 and keys of at least 2048 bits, and ECDSA P-256/SHA-256 and
P-384/SHA-384. They reject legacy signature algorithms, key generation, JWE
encryption/decryption, PKCS#12, SSH, and PuTTY operations rather than falling
back to the RustCrypto backend.

The `jose` feature contains JOSE/JWT/JWE parsing and signature support without
enabling RustCrypto encryption crates. Non-FIPS builds that need JWE
encryption/decryption select `jwe-crypto`; it is included by the default and
`full` feature profiles.

Selecting either provider feature enforces Picky's algorithm policy and backend
routing. A feature flag alone is not a compliance claim: deployment compliance
also depends on the linked module, platform, build configuration, module
version, and operating procedures covered by the applicable validation
certificate.
