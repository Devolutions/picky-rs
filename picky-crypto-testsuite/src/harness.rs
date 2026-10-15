//! Check collection, expected outcomes and property runner shared by every area.

use std::panic::{AssertUnwindSafe, catch_unwind};

use picky_crypto::*;
use proptest::strategy::Strategy;
use proptest::test_runner::{Config, FileFailurePersistence, RngSeed, TestCaseError, TestRunner};

use crate::algorithms::extended;

/// Per-run settings a runner passes to every area.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Accept `VerificationFailed` for an unusable public key (contract section 4).
    pub opaque_public_key_errors: bool,
    /// The other backends in the same build, combined into one provider, whose RSA encryptors produce reference ciphertexts.
    /// Decryption checks on RSA keys with inconsistent components use it when the base key has no published ciphertext for the algorithm.
    /// Signing checks on such keys from decryption files use its verifiers when the provider has none for the algorithm.
    pub reference_provider: Option<&'static CryptoProvider>,
}

#[derive(Default)]
pub struct Checks {
    pub failures: Vec<String>,
    /// How many checks used each kind of input, printed by [`Checks::finish`] so passing runs show their coverage.
    pub coverage: std::collections::BTreeMap<String, usize>,
}

#[derive(Clone, Copy, Debug)]
pub enum Expect {
    Success,
    Error(Error),
    Either(Error),
    AnyError(Error, Error),
    SmallOrderEd25519Key,
}

impl Checks {
    pub fn key_supports(&mut self, id: &str, key: &dyn PrivateKey, operation: KeyOperation) -> bool {
        self.metadata(id, || key.supports(operation)).unwrap_or(false)
    }

    pub fn protections(&mut self, id: &str, supports: impl Fn(Protection) -> bool) -> [bool; 2] {
        self.metadata(id, || [supports(Protection::Apply), supports(Protection::Process)])
            .unwrap_or_default()
    }

    pub fn metadata<T: 'static>(&mut self, id: &str, operation: impl FnOnce() -> T) -> Option<T> {
        self.call(id, Expect::Success, || Ok(operation()))
    }

    pub fn property<S: proptest::strategy::Strategy>(
        &mut self,
        id: &str,
        strategy: S,
        test: impl Fn(S::Value) -> Result<(), proptest::test_runner::TestCaseError>,
    ) {
        self.call(id, Expect::Success, || {
            property(id, strategy, test);
            Ok(())
        });
    }
    pub fn check(&mut self, id: &str, condition: bool, explanation: impl AsRef<str>) {
        if !condition {
            self.failures.push(format!("{id}: {}", explanation.as_ref()));
        }
    }

    pub fn call<T: 'static>(
        &mut self,
        id: &str,
        expected: Expect,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Option<T> {
        self.outcome(id, expected, None, operation)
    }

    pub fn outcome<T: 'static>(
        &mut self,
        id: &str,
        expected: Expect,
        outside_must_support: Option<(Algorithm, bool)>,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Option<T> {
        match catch_unwind(AssertUnwindSafe(operation)) {
            Err(payload) => {
                let text = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic");
                self.failures
                    .push(format!("{id}: expected {expected:?}; panic: {text}"));
                None
            }
            Ok(result) => {
                let valid = match (&result, expected) {
                    (Ok(_), Expect::Success | Expect::Either(_) | Expect::SmallOrderEd25519Key) => true,
                    (Err(actual), Expect::Error(error) | Expect::Either(error)) => *actual == error,
                    (Err(actual), Expect::AnyError(a, b)) => *actual == a || *actual == b,
                    (Err(Error::InvalidKey | Error::VerificationFailed), Expect::SmallOrderEd25519Key) => true,
                    (
                        Err(Error::Unsupported(Algorithm::Signature(SignatureAlgorithm::Ed25519))),
                        Expect::SmallOrderEd25519Key,
                    ) => true,
                    _ => false,
                } || outside_must_support.is_some_and(|(a, opaque)| {
                    matches!(&result, Err(Error::Unsupported(b)) if a == *b)
                        || opaque && matches!(&result, Err(Error::VerificationFailed))
                });
                if !valid {
                    let actual = result
                        .as_ref()
                        .err()
                        .map_or_else(|| "success".to_owned(), |e| format!("{e:?}"));
                    self.failures
                        .push(format!("{id}: expected {expected:?}; actual {actual}"));
                }
                result.ok()
            }
        }
    }

    pub fn bytes(&mut self, id: &str, output: &OutputBytes, expected: &[u8]) {
        self.check(
            id,
            output.as_ref() == expected,
            format!(
                "expected {} bytes {}, actual {} bytes {}",
                expected.len(),
                hex::encode(expected),
                output.len(),
                hex::encode(output.as_ref()),
            ),
        );
    }

    pub fn absent<T>(&mut self, provider: &CryptoProvider, algorithm: Algorithm, result: Result<T, Error>) {
        let id = format!("{algorithm:?}/availability");
        self.check(
            &id,
            result.err() == Some(Error::Unsupported(algorithm)),
            "typed accessor must return correctly named Unsupported",
        );
        self.check(&id, provider.get(algorithm).is_none(), "get must be None");
        let required = [Requirement::from(algorithm)];
        self.check(
            &id,
            helpers::missing(provider, &required) == required,
            "missing must report algorithm",
        );
    }

    /// Reads an entry's protections under `id` and checks the directional availability of each.
    pub fn directions(
        &mut self,
        provider: &CryptoProvider,
        id: &str,
        a: Algorithm,
        supports: impl Fn(Protection) -> bool,
    ) -> Option<[bool; 2]> {
        let protections = self.metadata(id, || [supports(Protection::Apply), supports(Protection::Process)])?;
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            self.direction(provider, a, protection, supported);
        }
        Some(protections)
    }

    pub fn direction(&mut self, provider: &CryptoProvider, a: Algorithm, p: Protection, supported: bool) {
        let requirement = match a {
            Algorithm::Mac(a) => Requirement::Mac(a, p),
            Algorithm::Cipher(a) => Requirement::Cipher(a, p),
            Algorithm::Aead(a) => Requirement::Aead(a, p),
            Algorithm::KeyWrap(a) => Requirement::KeyWrap(a, p),
            _ => unreachable!(),
        };
        let missing = self.metadata(&format!("{a:?}/{p:?}/missing"), || {
            helpers::missing(provider, &[requirement])
        });
        self.check(
            &format!("{a:?}/{p:?}"),
            missing.is_some_and(|v| v.is_empty() == supported),
            "directional availability disagrees with supports",
        );
        if !supported {
            let missing = self.metadata(&format!("{a:?}/missing"), || {
                helpers::missing(provider, &[Requirement::from(a)])
            });
            self.check(
                &format!("{a:?}"),
                missing == Some(vec![Requirement::from(a)]),
                "partial entry must not satisfy Requirement::Algorithm",
            );
        }
    }

    /// Counts one check under `label` in the coverage report.
    pub fn count(&mut self, label: impl Into<String>) {
        *self.coverage.entry(label.into()).or_default() += 1;
    }

    pub fn finish(self) {
        for (label, count) in &self.coverage {
            println!("coverage: {label}: {count}");
        }
        assert!(
            self.failures.is_empty(),
            "{} conformance failure(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

pub fn malformed_public(options: Options) -> Expect {
    if options.opaque_public_key_errors {
        Expect::AnyError(Error::InvalidKey, Error::VerificationFailed)
    } else {
        Expect::Error(Error::InvalidKey)
    }
}

thread_local! {
    static PERSIST_FAILURES: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Runs `f` without recording property failures in the regression files.
/// Used by self-tests whose mock providers fail properties on purpose.
pub fn without_failure_persistence<R>(f: impl FnOnce() -> R) -> R {
    let previous = PERSIST_FAILURES.replace(false);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    PERSIST_FAILURES.set(previous);
    result.unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

pub fn runner(file: &'static str) -> TestRunner {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .map(|s| s.parse().expect("PROPTEST_CASES must be an integer"))
        .unwrap_or(if extended() { 1024 } else { 16 });
    TestRunner::new(Config {
        cases,
        rng_seed: RngSeed::Fixed(0x7069636b79),
        failure_persistence: PERSIST_FAILURES
            .get()
            .then(|| Box::new(FileFailurePersistence::Direct(file)) as _),
        ..Config::default()
    })
}

/// Returns the regression file of the property `id`: `proptest-regressions/<name>.txt` in this crate.
/// The name keeps the ASCII letters and digits of `id`, joining the runs between them with `-`.
pub fn regression_file(id: &str) -> &'static str {
    static FILES: std::sync::Mutex<std::collections::BTreeSet<&'static str>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let name = id
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let path = format!("{}/proptest-regressions/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let mut files = FILES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(file) = files.get(path.as_str()) {
        return file;
    }
    // proptest takes a `'static` path, so each distinct path is leaked once and reused.
    let file: &'static str = Box::leak(path.into_boxed_str());
    files.insert(file);
    file
}

pub fn property<S: Strategy>(id: &str, strategy: S, test: impl Fn(S::Value) -> Result<(), TestCaseError>) {
    // A runner built by hand has no test source file for proptest's default location, so each property's failures go to its own file in this crate.
    let result = runner(regression_file(id)).run(&strategy, |value| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(value))) {
            Ok(result) => result,
            Err(_) => Err(TestCaseError::fail(format!("{id}: provider panic"))),
        }
    });
    assert!(result.is_ok(), "{id}: {result:?}");
}
