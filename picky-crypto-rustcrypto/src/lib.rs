//! RustCrypto capability entries for the picky cryptographic provider contract.
//! See the crate README for feature selection and supported algorithms.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "aead")]
mod aead;
#[cfg(any(feature = "aes", feature = "legacy"))]
mod cbc;
#[cfg(feature = "curve25519")]
mod curve25519;
#[cfg(feature = "nist-ec")]
mod ec;
#[cfg(any(feature = "digest", feature = "legacy"))]
mod hash;
#[cfg(feature = "key-wrap")]
mod key_wrap;
#[cfg(feature = "digest")]
mod mac;
#[cfg(feature = "digest")]
mod pbkdf2;
#[cfg(any(feature = "aead", feature = "rsa", feature = "nist-ec", feature = "curve25519"))]
mod random;
#[cfg(feature = "legacy")]
mod rc4;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(any(
    feature = "digest",
    feature = "aes",
    feature = "aead",
    feature = "key-wrap",
    feature = "rsa",
    feature = "nist-ec",
    feature = "curve25519",
    feature = "legacy"
))]
mod util;

/// Builds the provider with the capability families enabled by crate features.
pub fn provider() -> picky_crypto::CryptoProvider {
    let builder = picky_crypto::CryptoProvider::builder();
    #[cfg(any(feature = "digest", feature = "legacy"))]
    let builder = hash::entries(builder);
    #[cfg(feature = "digest")]
    let builder = pbkdf2::entries(mac::entries(builder));
    #[cfg(any(feature = "aes", feature = "legacy"))]
    let builder = cbc::entries(builder);
    #[cfg(feature = "aead")]
    let builder = aead::entries(builder);
    #[cfg(feature = "key-wrap")]
    let builder = key_wrap::entries(builder);
    #[cfg(feature = "rsa")]
    let builder = rsa::entries(builder);
    #[cfg(feature = "nist-ec")]
    let builder = ec::entries(builder);
    #[cfg(feature = "curve25519")]
    let builder = curve25519::entries(builder);
    #[cfg(feature = "legacy")]
    let builder = rc4::entries(builder);
    #[cfg(any(feature = "aead", feature = "rsa", feature = "nist-ec", feature = "curve25519"))]
    let builder = builder.with(picky_crypto::Entry::SecureRandom(std::sync::Arc::new(random::Random)));
    builder.build().expect("fixed, distinct RustCrypto entries")
}

#[cfg(test)]
mod tests {
    #[test]
    fn feature_assembly() {
        let provider = super::provider();
        let expected = 17 * usize::from(cfg!(feature = "digest"))
            + 3 * usize::from(cfg!(feature = "aes"))
            + 3 * usize::from(cfg!(feature = "aead"))
            + 3 * usize::from(cfg!(feature = "key-wrap"))
            + 15 * usize::from(cfg!(feature = "rsa"))
            + 12 * usize::from(cfg!(feature = "nist-ec"))
            + 5 * usize::from(cfg!(feature = "curve25519"))
            + 5 * usize::from(cfg!(feature = "legacy"))
            + usize::from(cfg!(any(
                feature = "aead",
                feature = "rsa",
                feature = "nist-ec",
                feature = "curve25519"
            )));
        assert_eq!(provider.entries().count(), expected);
        assert!(!provider.fips());
    }
}
