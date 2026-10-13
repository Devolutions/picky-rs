use picky_crypto::*;
use picky_crypto_testsuite::harness::*;
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

struct ApplyOnlyMac;
impl Mac for ApplyOnlyMac {
    fn algorithm(&self) -> MacAlgorithm {
        MacAlgorithm::HmacSha256
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        protection == Protection::Apply
    }
    fn start(&self, _: &[u8], _: Protection) -> Result<Box<dyn MacContext>, Error> {
        Err(Error::ProviderFailure)
    }
}

// Catches an inverted comparison between `supports` and `helpers::missing` for directional entries:
// the conformance runs here never expect a one-protection entry to pass.
#[test]
fn directional_availability_matches_supports() {
    let provider = CryptoProvider::builder()
        .with(Entry::Mac(std::sync::Arc::new(ApplyOnlyMac)))
        .build()
        .unwrap();
    let algorithm = Algorithm::Mac(MacAlgorithm::HmacSha256);
    let mut c = Checks::default();
    c.direction(&provider, algorithm, Protection::Apply, true);
    c.direction(&provider, algorithm, Protection::Process, false);
    c.finish();
}
