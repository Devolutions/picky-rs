//! A fixed composition of the picky-crypto backends and fill-in providers, behind one `provider()` function.
//! See the crate README for the composition order and the features.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use picky_crypto::CryptoProvider;

/// Builds the composition of the enabled features.
/// The enabled backends come first, in the fixed order aws-lc, ring, RustCrypto, each a fallback for the previous ones.
/// With `composed`, the key-based KDFs built over those backends follow.
/// With `ffdh`, FFDH drawing from the first secure random entry among the enabled backends comes last.
/// A fill-in provider whose base entries no enabled backend offers adds nothing.
/// It installs nothing and applies no policy.
pub fn provider() -> CryptoProvider {
    // UNTESTED: backends are composed in the fixed order aws-lc, ring, RustCrypto, then the composed KDFs, then FFDH.
    // The order decides which member serves an algorithm two members offer, so a fixed order gives every dependent the
    // same provider and lets a native entry win over a fill-in one.
    // No test can observe it while the members share no algorithm.
    // When adding a backend, insert its feature-gated line at its place in this list, before the fill-in providers.
    let backends: Vec<CryptoProvider> = vec![
        #[cfg(feature = "rustcrypto")]
        picky_crypto_rustcrypto::provider(),
    ];
    let provider = backends
        .into_iter()
        .reduce(|first, next| first.with_fallback(&next))
        .unwrap_or_else(|| CryptoProvider::builder().build().expect("an empty provider builds"));
    #[cfg(feature = "composed")]
    let provider = provider.with_fallback(&picky_crypto_composed::provider(&provider));
    #[cfg(feature = "ffdh")]
    let provider = provider.with_fallback(&picky_crypto_ffdh::provider(&provider));
    provider
}

#[cfg(test)]
mod tests {
    // Faults: an enabled feature adds no entries, or a fill-in provider is built over something other than the
    // enabled backends.
    #[test]
    fn feature_assembly() {
        #[cfg(feature = "rustcrypto")]
        let native = picky_crypto_rustcrypto::provider().entries().count();
        #[cfg(not(feature = "rustcrypto"))]
        let native = 0;
        let backend = cfg!(feature = "rustcrypto");
        let expected = native
            + 8 * usize::from(backend && cfg!(feature = "composed"))
            + 2 * usize::from(backend && cfg!(feature = "ffdh"));
        assert_eq!(super::provider().entries().count(), expected);
    }
}
