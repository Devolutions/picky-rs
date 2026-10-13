//! Differential areas, each checking a pair of providers against each other in both directions.
//!
//! A check is differential only if one provider alone can't show the same thing; published answers already pin deterministic outputs.
//! Each module's `run` function takes two providers and panics with a report of every failed check.

pub mod asymmetric_encryption;
pub mod key_agreement;
pub mod signature;
pub mod symmetric;

/// Invokes the macro `$m` with the name of every module in [`differential`](crate::differential).
///
/// A runner defines one test per differential area and provider pair, calling `picky_crypto_testsuite::differential::$name::run`.
#[macro_export]
macro_rules! for_each_differential_area {
    ($m:ident) => {
        $m! { symmetric, key_agreement, signature, asymmetric_encryption }
    };
}
