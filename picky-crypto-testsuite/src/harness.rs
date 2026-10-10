use std::panic::{AssertUnwindSafe, catch_unwind};
use std::{any::Any, fmt::Debug};

use picky_crypto::*;

use crate::{Options, algorithms};

#[derive(Default)]
pub struct Checks {
    failures: Vec<String>,
    #[cfg(test)]
    buffer_audits: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum Expect {
    Success,
    Error(Error),
    Either(Error),
    AnyError(Error, Error),
    SmallOrderEd25519Key,
}

pub trait CheckedResult<T> {
    fn checked(self) -> Result<T, Error>;
}
impl<T: 'static> CheckedResult<T> for Result<T, Error> {
    fn checked(self) -> Result<T, Error> {
        if let Ok(value) = &self {
            let mut checks = Checks::default();
            checks.buffers("returned buffer", value);
            checks.finish();
        }
        self
    }
}

impl Checks {
    pub fn buffers(&mut self, id: &str, value: &dyn Any) {
        #[cfg(test)]
        if value.is::<OutputBytes>()
            || value.is::<X25519Scalar>()
            || value.is::<MacTag>()
            || value.is::<MacVerifier>()
            || value.is::<MacOutput>()
        {
            self.buffer_audits += 1;
        }
        if let Some(output) = value.downcast_ref::<OutputBytes>() {
            self.debug(id, output, output);
        }
        if let Some(output) = value.downcast_ref::<X25519Scalar>() {
            self.debug(id, output, &output[..]);
        }
        if let Some(output) = value.downcast_ref::<Sealed>() {
            self.buffers(id, &output.nonce);
            self.buffers(id, &output.ciphertext_and_tag);
            self.debug(id, output, &output.nonce);
            self.debug(id, output, &output.ciphertext_and_tag);
        }
        if let Some(output) = value.downcast_ref::<MacTag>() {
            self.debug(id, output, &output.clone().into_inner());
        }
        if let Some(output) = value.downcast_ref::<MacVerifier>() {
            self.debug(id, output, &[]);
        }
        if let Some(output) = value.downcast_ref::<MacOutput>() {
            self.debug(id, output, &[]);
        }
        if let Some((a, b)) = value.downcast_ref::<(OutputBytes, OutputBytes)>() {
            self.buffers(id, a);
            self.buffers(id, b);
        }
        if let Some((a, b, c, d)) = value.downcast_ref::<(OutputBytes, OutputBytes, OutputBytes, OutputBytes)>() {
            self.buffers(id, a);
            self.buffers(id, b);
            self.buffers(id, c);
            self.buffers(id, d);
        }
        if let Some(Some(output)) = value.downcast_ref::<Option<OutputBytes>>() {
            self.buffers(id, output);
        }
        if let Some(Some(outputs)) = value.downcast_ref::<Option<(OutputBytes, OutputBytes)>>() {
            self.buffers(id, outputs);
        }
        if let Some(outputs) = value.downcast_ref::<Vec<OutputBytes>>() {
            for output in outputs {
                self.buffers(id, output);
            }
        }
    }
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
            crate::properties::property(id, strategy, test);
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
                if let Ok(value) = &result {
                    match catch_unwind(AssertUnwindSafe(|| self.buffers(id, value))) {
                        Ok(()) => (),
                        Err(_) => self.check(id, false, "returned-buffer Debug panicked"),
                    }
                }
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
        self.debug(id, output, output);
    }

    pub fn debug(&mut self, id: &str, value: &(impl Debug + Any), bytes: &[u8]) {
        let Ok(text) = catch_unwind(AssertUnwindSafe(|| format!("{value:?}"))) else {
            return self.check(id, false, "Debug panicked");
        };
        if let Some((twins, lengths)) = constant_twins(value) {
            self.check(
                id,
                twins.iter().all(|twin| *twin == text),
                "Debug depends on buffer contents",
            );
            let shown = |len: &usize| text.split(|c: char| !c.is_ascii_digit()).any(|n| n == len.to_string());
            self.check(id, lengths.iter().all(shown), "Debug doesn't show the buffer length");
        }
        let any = value as &dyn Any;
        let mac = [
            ("MacVerifier", any.is::<MacVerifier>()),
            ("MacOutput", any.is::<MacOutput>()),
        ];
        if let Some((name, _)) = mac.into_iter().find(|(_, is)| *is) {
            self.check(id, length_only(&text, name), "Debug must show only the length");
        }
        if bytes.is_empty() {
            return;
        }
        let (lower, upper) = (hex::encode(bytes), hex::encode_upper(bytes));
        // Short hex strings also occur inside words such as "nonce", so they are matched as whole tokens.
        let hex_shown = if bytes.len() >= 4 {
            text.contains(&lower) || text.contains(&upper)
        } else {
            text.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| token == lower || token == upper)
        };
        self.check(
            id,
            !hex_shown && !text.contains(&format!("{bytes:?}")),
            "Debug reveals buffer bytes",
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

    pub fn finish(self) {
        assert!(
            self.failures.is_empty(),
            "{} conformance failure(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

/// Formats outputs of the same type and lengths, filled with all-zero and all-one bytes, and returns those lengths.
/// A length-only `Debug` equals both formats and shows each length; one that depends on the bytes differs from at least one format.
fn constant_twins(value: &dyn Any) -> Option<([String; 2], Vec<usize>)> {
    let output = |len: usize, byte: u8| OutputBytes::new(Zeroizing::new(vec![byte; len]));
    let twins = |format: &dyn Fn(u8) -> String| [0, 0xff].map(format);
    if let Some(v) = value.downcast_ref::<OutputBytes>() {
        return Some((twins(&|byte| format!("{:?}", output(v.len(), byte))), vec![v.len()]));
    }
    if let Some(v) = value.downcast_ref::<Sealed>() {
        let lengths = vec![v.nonce.len(), v.ciphertext_and_tag.len()];
        let format = |byte| format!("{:?}", Sealed::new(output(lengths[0], byte), output(lengths[1], byte)));
        return Some((twins(&format), lengths.clone()));
    }
    if value.is::<X25519Scalar>() {
        let format = |byte| format!("{:?}", X25519Scalar::new(Zeroizing::new([byte; 32])));
        return Some((twins(&format), vec![32]));
    }
    let len = value.downcast_ref::<MacTag>()?.clone().into_inner().len();
    Some((twins(&|byte| format!("{:?}", echo_mac(vec![byte; len]))), vec![len]))
}

/// Checks the length-only diagnostics of a MAC type whose length isn't observable through its public API.
/// After the type name, the only words allowed are an optional `len` and one decimal number.
fn length_only(text: &str, name: &str) -> bool {
    let Some(rest) = text.strip_prefix(name) else {
        return false;
    };
    let words: Vec<_> = rest
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    let number = |word: &str| word.bytes().all(|b| b.is_ascii_digit());
    matches!(words.as_slice(), [n] | ["len", n] if number(n))
}

/// A non-cryptographic MAC entry whose tag is the given bytes, used only to build `MacTag` values.
struct EchoMac(Vec<u8>);
struct EchoContext(Vec<u8>);
impl Mac for EchoMac {
    fn algorithm(&self) -> MacAlgorithm {
        MacAlgorithm::HmacSha512
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, _: Protection) -> bool {
        true
    }
    fn start(&self, _: &[u8], _: Protection) -> Result<Box<dyn MacContext>, Error> {
        Ok(Box::new(EchoContext(self.0.clone())))
    }
}
impl MacContext for EchoContext {
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<MacOutput, Error> {
        Ok(MacOutput::new(Zeroizing::new(self.0)))
    }
}

fn echo_mac(tag: Vec<u8>) -> MacTag {
    let mac = EchoMac(tag);
    MacGeneration::start(&mac, &[])
        .and_then(MacGeneration::finish)
        .expect("echo MAC")
}

pub fn malformed_public(options: Options) -> Expect {
    if options.opaque_public_key_errors {
        Expect::AnyError(Error::InvalidKey, Error::VerificationFailed)
    } else {
        Expect::Error(Error::InvalidKey)
    }
}

#[doc(hidden)]
pub fn provider(provider: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    c.call(
        "helpers::key_agreement/Ffdh",
        Expect::Error(Error::InvalidInput),
        || helpers::key_agreement(provider, KeyAgreementAlgorithm::Ffdh).map(|_| ()),
    );
    if let Some((nonempty, entries_fips, reported)) = c.metadata("provider/FIPS", || {
        (
            provider.entries().next().is_some(),
            provider.entries().all(helpers::entry_fips),
            provider.fips(),
        )
    }) {
        c.check(
            "provider/FIPS",
            !reported || (nonempty && entries_fips),
            "FIPS report requires nonempty, FIPS entries",
        );
    }
    for entry in provider.entries() {
        let Some(id) = c.metadata("provider/entry identity", || helpers::entry_algorithm(entry)) else {
            continue;
        };
        c.check(
            &format!("{id:?}"),
            provider.get(id).is_some(),
            "entry not found under own algorithm",
        );
        c.call(&format!("{id:?}/Debug"), Expect::Success, || {
            let text = format!("{entry:?}");
            if !text.contains("fips") {
                return Err(Error::InvalidInput);
            }
            Ok(())
        });
        let protections = c
            .metadata(&format!("{id:?}/protections"), || match entry {
                Entry::Mac(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                Entry::Cipher(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                Entry::Aead(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                Entry::KeyWrap(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                _ => None,
            })
            .flatten();
        if let Some((a, b)) = protections {
            c.check(&format!("{id:?}"), a || b, "entry supports neither protection");
        }
        let bytes = &crate::select::ed25519_empty().seed;
        c.debug(&format!("{id:?}/Debug"), entry, bytes);
        c.debug("provider/Debug", provider, bytes);
    }
    for a in algorithms::all() {
        if provider.get(a).is_none() {
            c.check(
                &format!("{a:?}"),
                helpers::missing(provider, &[a.into()]) == [a.into()],
                "missing omitted absent entry",
            );
        }
    }
    c.finish();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Expect::Success, Ok(()))]
    #[case(Expect::Error(Error::InvalidInput), Err(Error::InvalidInput))]
    #[case(Expect::Either(Error::InvalidKey), Ok(()))]
    #[case(Expect::Either(Error::InvalidKey), Err(Error::InvalidKey))]
    fn allowed(#[case] expect: Expect, #[case] result: Result<(), Error>) {
        let mut checks = Checks::default();
        checks.call("control", expect, || result);
        checks.finish();
    }

    #[test]
    fn panic_and_wrong_error_are_collected() {
        let mut c = Checks::default();
        c.call::<()>("panicking provider", Expect::Success, || panic!("backend"));
        c.call::<()>("wrong error", Expect::Error(Error::InvalidKey), || {
            Err(Error::ProviderFailure)
        });
        assert_eq!(c.failures.len(), 2);
    }

    #[test]
    fn output_diagnostics_with_published_bytes() {
        let vectors = crate::vectors::wycheproof("hmac_sha256_test.json");
        let t = &crate::vectors::tests(&vectors.test_groups[0])[0];
        let bytes = crate::vectors::field(t, "tag");
        let entry = EchoMac(bytes.clone());
        let key = crate::vectors::field(t, "key");
        let message = crate::vectors::field(t, "msg");
        let mut generation = MacGeneration::start(&entry, &key).unwrap();
        generation.update(&message).unwrap();
        let tag = generation.finish().unwrap();
        let mut verification = MacVerification::start(&entry, &key).unwrap();
        verification.update(&message).unwrap();
        let verifier = verification.finish().unwrap();
        assert!(verifier.verify(&tag.clone().into_inner(), bytes.len()));
        let output = OutputBytes::new(Zeroizing::new(bytes.clone()));
        let scalar: [u8; 32] = crate::vectors::x25519_dh().0.try_into().unwrap();
        let scalar = X25519Scalar::new(Zeroizing::new(scalar));
        let sealed = Sealed::new(output.clone(), output.clone());
        let mut c = Checks::default();
        let id = "hmac_sha256_test.json/tcId=1/output diagnostics";
        c.debug(id, &tag, &bytes);
        c.debug(id, &verifier, &bytes);
        c.debug(id, &output, &bytes);
        c.debug(id, &MacOutput::new(Zeroizing::new(bytes.clone())), &bytes);
        c.debug(id, &sealed, &bytes);
        c.debug("rfc/rfc7748.txt/6.1/Alice/X25519Scalar", &scalar, scalar.as_ref());
        assert_eq!(output.clone().into_inner().as_slice(), bytes);
        assert_eq!(scalar.clone().into_inner().as_slice(), scalar.as_ref());
        c.finish();
    }

    #[rstest]
    #[case("MacVerifier { len: 32 }", true)]
    #[case("MacVerifier(32)", true)]
    #[case("MacVerifier", false)]
    #[case("MacVerifier { tag: 0a1b }", false)]
    #[case("MacVerifier { len: 32, tag: 5 }", false)]
    #[case("MacVerifier { len: 32, tag: deadbeef }", false)]
    #[case("MacVerifier { 32 }", true)]
    #[case("MacOutput { len: 32 }", false)]
    fn mac_length_only_diagnostics(#[case] text: &str, #[case] accepted: bool) {
        assert_eq!(length_only(text, "MacVerifier"), accepted);
    }

    struct Leaky(Vec<u8>);
    impl Debug for Leaky {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Leaky {{ bytes: {} }}", hex::encode(&self.0))
        }
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn short_output_diagnostics(#[case] len: usize) {
        let vectors = crate::vectors::wycheproof("hmac_sha256_test.json");
        let tag = crate::vectors::field(&crate::vectors::tests(&vectors.test_groups[0])[0], "tag");
        let bytes = &tag[..len];
        let mut c = Checks::default();
        c.debug(
            "short OutputBytes",
            &OutputBytes::new(Zeroizing::new(bytes.to_vec())),
            bytes,
        );
        c.finish();
        let mut c = Checks::default();
        c.debug("leaky control", &Leaky(bytes.to_vec()), bytes);
        assert_eq!(c.failures.len(), usize::from(len > 0));
    }

    #[test]
    fn buffer_audit_visits_agreement_tuples_and_nested_outputs() {
        let source = crate::vectors::x25519_dh().4;
        let output = OutputBytes::new(Zeroizing::new(source));
        let mut checks = Checks::default();
        checks.buffers(
            "agreement outputs",
            &(output.clone(), output.clone(), output.clone(), output.clone()),
        );
        assert_eq!(checks.buffer_audits, 4);
        checks.buffers("optional nested pair", &Some((output.clone(), output.clone())));
        assert_eq!(checks.buffer_audits, 6);
        checks.buffers("output list", &vec![output.clone(), output.clone()]);
        assert_eq!(checks.buffer_audits, 8);
        checks.finish();
        crate::properties::property("property output audit", proptest::strategy::Just(()), |_| {
            let mut checks = Checks::default();
            checks.buffers("property output", &output);
            assert_eq!(checks.buffer_audits, 1);
            checks.finish();
            Ok(output.clone()).checked().unwrap();
            Ok(())
        });
    }
}
