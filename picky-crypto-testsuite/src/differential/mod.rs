//! Differential areas, each checking a pair of providers against each other in both directions.
//!
//! Each module's `run` function takes two providers and panics with a report of every failed check.

use picky_crypto::*;
use proptest::prelude::*;

use crate::harness::{CheckedResult, Checks, Expect};

pub mod asymmetric_encryption;
pub mod inconsistent_rsa;
pub mod key_agreement;
pub mod private_key;
pub mod symmetric;

/// Invokes the macro `$m` with the name of every module in [`differential`](crate::differential).
///
/// A runner defines one test per differential area and provider pair, calling `picky_crypto_testsuite::differential::$name::run`.
#[macro_export]
macro_rules! for_each_differential_area {
    ($m:ident) => {
        $m! { symmetric, key_agreement, private_key, asymmetric_encryption, inconsistent_rsa }
    };
}

fn outputs(
    c: &mut Checks,
    id: &str,
    a: impl FnOnce() -> Result<OutputBytes, Error>,
    b: impl FnOnce() -> Result<OutputBytes, Error>,
) {
    let left = c.call(&format!("{id}/A"), Expect::Success, a);
    let right = c.call(&format!("{id}/B"), Expect::Success, b);
    if let (Some(a), Some(b)) = (left, right) {
        c.bytes(id, &a, &b);
    }
}

fn selected<T>(
    c: &mut Checks,
    id: &str,
    inputs: &[T],
    operation: impl Fn(&T) -> Result<(OutputBytes, OutputBytes), Error>,
) {
    c.property(id, 0..inputs.len(), |index| {
        let (left, right) = operation(&inputs[index])
            .checked()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{id}/index={index}: {e}")))?;
        prop_assert_eq!(left.as_ref(), right.as_ref());
        Ok(())
    });
}
