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

The AWS-LC profile supports SHA-224/256/384/512 and SHA3-384/512; RSA PKCS#1
v1.5 signatures with SHA-2 and keys of at least 2048 bits; ECDSA
P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512; and Ed25519. RSA
2048/3072/4096/8192, P-256/P-384/P-521, and Ed25519 key generation and public
key derivation use AWS-LC.

JWE supports `dir`, RSA-OAEP-256, `ECDH-ES`, `ECDH-ES+A128KW`, and
`ECDH-ES+A256KW` key management with AES-128-GCM or AES-256-GCM content
encryption. ECDH uses P-256, P-384, or P-521. X25519, AES-192-GCM,
ECDH-ES+A192KW, and ChaCha20-Poly1305 remain unavailable.

PKCS#12 supports PBES2 using PBKDF2-HMAC-SHA-2 and AES-CBC. PBES1 and the
PKCS#12 Appendix B MAC KDF remain unavailable because they are outside the
approved AWS-LC policy. Consequently, FIPS builds can create MAC-less PBES2
archives and can parse archives with MAC validation explicitly skipped, but
cannot create or validate the conventional PKCS#12 MAC. PBKDF2 inputs must use
at least 1000 iterations, a 16-byte salt, and 14 bytes of password material to
satisfy the AWS-LC FIPS service indicator.

The `ssh` feature supports parsing, encoding, and SHA-256 fingerprinting of RSA,
P-256, P-384, P-521, and Ed25519 public keys in FIPS builds. OpenSSH private
keys, SSH certificates, security-key formats, and PuTTY PPK files remain
unavailable in this profile. Encrypted OpenSSH and PuTTY formats require
bcrypt-PBKDF, Argon2, or SHA-1 constructions that are not enabled. MD5 and
SHA-1 fingerprints are rejected by the FIPS policy.

The `jose` feature contains JOSE/JWT/JWE parsing and signature support without
enabling encryption crates. Select `jwe-crypto` for JWE encryption/decryption;
it is included by the default and `full` feature profiles. Select `pkcs12` for
PKCS#12 parsing and creation.

The provider feature enforces Picky's algorithm policy and backend routing. A
feature flag alone is not a compliance claim: deployment compliance also
depends on the linked module, platform, build configuration, module version,
and operating procedures covered by the applicable validation certificate.
