use crate::CryptoProvider;
use std::sync::OnceLock;

static DEFAULT: OnceLock<CryptoProvider> = OnceLock::new();

/// Installs the default, returning the rejected provider unchanged on conflict.
/// Waits for a running maker; if that maker succeeds, returns `Err(provider)`.
/// If the maker panics, a waiting installation can install its provider instead.
/// Must not be called from a maker: re-entrant initialization deadlocks or panics.
/// See CONTRACT.md section 9.
pub fn install_default(provider: CryptoProvider) -> Result<(), CryptoProvider> {
    DEFAULT.set(provider)
}

/// Returns the installed default, without installing or panicking.
/// See CONTRACT.md section 9.
pub fn get_default() -> Option<&'static CryptoProvider> {
    DEFAULT.get()
}

/// Returns the default, running a maker only when no provider is installed.
/// At most one maker runs at a time and at most one succeeds; concurrent callers wait.
/// A maker's panic propagates to its caller without installing a provider.
/// Waiting or later calls retry with their own makers while no provider is installed.
/// A maker must not call this function or `install_default`: re-entrant initialization deadlocks or panics.
/// See CONTRACT.md section 9.
///
/// A consuming library's single backend-specific convenience-feature site:
/// ```ignore
/// fn provider() -> &'static picky_crypto::CryptoProvider {
///     #[cfg(feature = "rustcrypto")]
///     {
///         picky_crypto::get_or_install_default(picky_crypto_rustcrypto_bundle::provider)
///     }
///     #[cfg(not(feature = "rustcrypto"))]
///     {
///         picky_crypto::helpers::default_provider()
///     }
/// }
/// ```
pub fn get_or_install_default(make: fn() -> CryptoProvider) -> &'static CryptoProvider {
    DEFAULT.get_or_init(make)
}
