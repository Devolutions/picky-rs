use picky_crypto::*;
use picky_crypto_testsuite::harness::*;
use rstest::rstest;
use std::fmt::Debug;

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
    let vectors = picky_crypto_testsuite::vectors::wycheproof("hmac_sha256_test.json");
    let t = &picky_crypto_testsuite::vectors::tests(&vectors.test_groups[0])[0];
    let bytes = picky_crypto_testsuite::vectors::field(t, "tag");
    let entry = EchoMac(bytes.clone());
    let key = picky_crypto_testsuite::vectors::field(t, "key");
    let message = picky_crypto_testsuite::vectors::field(t, "msg");
    let mut generation = MacGeneration::start(&entry, &key).unwrap();
    generation.update(&message).unwrap();
    let tag = generation.finish().unwrap();
    let mut verification = MacVerification::start(&entry, &key).unwrap();
    verification.update(&message).unwrap();
    let verifier = verification.finish().unwrap();
    assert!(verifier.verify(&tag.clone().into_inner(), bytes.len()));
    let output = OutputBytes::new(Zeroizing::new(bytes.clone()));
    let scalar: [u8; 32] = picky_crypto_testsuite::vectors::x25519_dh().0.try_into().unwrap();
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
fn short_output_diagnostics(#[values(0, 1, 2, 3)] len: usize) {
    let vectors = picky_crypto_testsuite::vectors::wycheproof("hmac_sha256_test.json");
    let tag = picky_crypto_testsuite::vectors::field(
        &picky_crypto_testsuite::vectors::tests(&vectors.test_groups[0])[0],
        "tag",
    );
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
    let source = picky_crypto_testsuite::vectors::x25519_dh().4;
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
    picky_crypto_testsuite::properties::property("property output audit", proptest::strategy::Just(()), |_| {
        let mut checks = Checks::default();
        checks.buffers("property output", &output);
        assert_eq!(checks.buffer_audits, 1);
        checks.finish();
        Ok(output.clone()).checked().unwrap();
        Ok(())
    });
}
