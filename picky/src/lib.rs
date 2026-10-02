//! [![Crates.io](https://img.shields.io/crates/v/picky.svg)](https://crates.io/crates/picky)
//! [![docs.rs](https://docs.rs/picky/badge.svg)](https://docs.rs/picky)
//! ![Crates.io](https://img.shields.io/crates/l/picky)
//! # picky
//!
//! Portable X.509, PKI, JOSE and HTTP signature implementation.

#[cfg(all(feature = "fips", feature = "rustcrypto"))]
compile_error!("`fips` and `rustcrypto` are mutually exclusive; use `default-features = false` for FIPS builds");

#[cfg(all(feature = "fips", not(feature = "fips-aws-lc")))]
compile_error!("`fips` requires the `fips-aws-lc` provider feature");

#[cfg(all(feature = "fips", any(feature = "ssh", feature = "putty")))]
compile_error!("SSH and PuTTY crypto are not available in FIPS builds");

#[cfg(all(feature = "fips-aws-lc", feature = "jwe-crypto"))]
compile_error!("JWE crypto is not yet available with `fips-aws-lc`");

#[cfg(all(feature = "fips-aws-lc", feature = "pkcs12"))]
compile_error!("PKCS#12 crypto is not yet available with `fips-aws-lc`");

#[cfg(not(any(feature = "rustcrypto", feature = "fips")))]
compile_error!("a crypto backend is required; enable `rustcrypto` or a FIPS provider");

pub mod crypto;

#[cfg(feature = "http_signature")]
pub mod http;

#[cfg(feature = "jose")]
pub mod jose;

#[cfg(feature = "x509")]
pub mod x509;

#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(feature = "pkcs12")]
pub mod pkcs12;

#[cfg(feature = "putty")]
pub mod putty;

pub mod hash;
pub mod key;
pub mod pem;
pub mod signature;

pub use picky_asn1_x509::{AlgorithmIdentifier, oid, oids};
