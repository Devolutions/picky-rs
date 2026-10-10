//! Conformance suite for `picky-crypto` providers, derived from the contract and published vectors.
//!
//! A runner calls the `run` function of every module in [`areas`] on a provider, and of every module in [`differential`] on a pair of providers.
//! [`for_each_area!`] and [`for_each_differential_area!`] list these modules, so a runner can't miss one.
//! Each takes the name of a runner macro and invokes it with the module names, for example `hash, mac, ...`.
//! The runner macro defines one test per name, calling `picky_crypto_testsuite::areas::$name::run(&provider, Options::default())` or `picky_crypto_testsuite::differential::$name::run(&a, &b)`.
//! Each `run` function panics with a report of every failed check.
//!
//! The Wycheproof vectors are a git submodule: run `git submodule update --init` before running tests.
//! Set `PICKY_CRYPTO_TESTSUITE_EXTENDED=1` for expensive iteration tests, RSA generation, and larger property runs.
//! `PROPTEST_CASES` overrides the property case count.
//! [`harness::Options`] permits only the contract's opaque public-key verification failure tolerance.
#![forbid(unsafe_code)]

pub mod algorithms;
pub mod areas;
pub mod der;
pub mod differential;
pub mod harness;
pub mod keys;
pub mod published;
pub mod select;
pub mod vectors;
