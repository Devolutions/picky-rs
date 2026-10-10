use std::sync::{Arc, Mutex};

use picky_crypto::*;
use proptest::prelude::*;
use rstest::rstest;

use picky_crypto_testsuite::harness::property;

#[derive(Clone)]
struct Mock {
    member: u8,
    protections: [bool; 2],
    fips: bool,
    calls: Arc<Mutex<Vec<(u8, Protection)>>>,
}

impl Mock {
    fn supports(&self, p: Protection) -> bool {
        self.protections[usize::from(p == Protection::Process)]
    }
    fn record(&self, p: Protection, algorithm: Algorithm) -> Result<(), Error> {
        if !self.supports(p) {
            return Err(Error::Unsupported(algorithm));
        }
        self.calls.lock().unwrap().push((self.member, p));
        Ok(())
    }
    fn fail<T>(&self, p: Protection, algorithm: Algorithm) -> Result<T, Error> {
        self.record(p, algorithm)?;
        Err(Error::ProviderFailure)
    }
}

struct Context(Mock);
impl MacContext for Context {
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        self.0.calls.lock().unwrap().push((self.0.member, Protection::Apply));
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<MacOutput, Error> {
        Err(Error::ProviderFailure)
    }
}
impl Mac for Mock {
    fn algorithm(&self) -> MacAlgorithm {
        MacAlgorithm::HmacSha256
    }
    fn supports(&self, p: Protection) -> bool {
        self.supports(p)
    }
    fn fips(&self) -> bool {
        self.fips
    }
    fn start(&self, key: &[u8], p: Protection) -> Result<Box<dyn MacContext>, Error> {
        let algorithm = Algorithm::Mac(MacAlgorithm::HmacSha256);
        self.record(p, algorithm)?;
        if key.is_empty() {
            return Err(Error::Unsupported(algorithm));
        }
        Ok(Box::new(Context(self.clone())))
    }
}
impl Cipher for Mock {
    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Aes128Cbc
    }
    fn supports(&self, p: Protection) -> bool {
        self.supports(p)
    }
    fn fips(&self) -> bool {
        self.fips
    }
    fn encrypt(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<OutputBytes, Error> {
        self.fail(Protection::Apply, Algorithm::Cipher(CipherAlgorithm::Aes128Cbc))
    }
    fn decrypt(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<OutputBytes, Error> {
        self.fail(Protection::Process, Algorithm::Cipher(CipherAlgorithm::Aes128Cbc))
    }
}
impl Aead for Mock {
    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes128Gcm
    }
    fn supports(&self, p: Protection) -> bool {
        self.supports(p)
    }
    fn fips(&self) -> bool {
        self.fips
    }
    fn seal(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<Sealed, Error> {
        self.fail(Protection::Apply, Algorithm::Aead(AeadAlgorithm::Aes128Gcm))
    }
    fn open(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<OutputBytes, Error> {
        self.fail(Protection::Process, Algorithm::Aead(AeadAlgorithm::Aes128Gcm))
    }
}
impl KeyWrap for Mock {
    fn algorithm(&self) -> KeyWrapAlgorithm {
        KeyWrapAlgorithm::Aes128Kw
    }
    fn supports(&self, p: Protection) -> bool {
        self.supports(p)
    }
    fn fips(&self) -> bool {
        self.fips
    }
    fn wrap(&self, _: &[u8], _: &[u8]) -> Result<OutputBytes, Error> {
        self.fail(Protection::Apply, Algorithm::KeyWrap(KeyWrapAlgorithm::Aes128Kw))
    }
    fn unwrap(&self, _: &[u8], _: &[u8]) -> Result<OutputBytes, Error> {
        self.fail(Protection::Process, Algorithm::KeyWrap(KeyWrapAlgorithm::Aes128Kw))
    }
}
impl Hash for Mock {
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
    fn fips(&self) -> bool {
        self.fips
    }
    fn start(&self) -> Result<Box<dyn HashContext>, Error> {
        self.calls.lock().unwrap().push((self.member, Protection::Apply));
        Err(Error::Unsupported(Algorithm::Hash(HashAlgorithm::Sha256)))
    }
}
impl KeyAgreement for Mock {
    fn algorithm(&self) -> KeyAgreementAlgorithm {
        KeyAgreementAlgorithm::Ffdh
    }
    fn fips(&self) -> bool {
        self.fips
    }
    fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error> {
        Err(Error::ProviderFailure)
    }
}
fn entry(area: usize, mock: Mock) -> Entry {
    let e = Arc::new(mock);
    match area {
        0 => Entry::Mac(e),
        1 => Entry::Cipher(e),
        2 => Entry::Aead(e),
        3 => Entry::KeyWrap(e),
        _ => Entry::Hash(e),
    }
}
fn mock(member: u8, protections: [bool; 2], fips: bool, calls: Arc<Mutex<Vec<(u8, Protection)>>>) -> Mock {
    Mock {
        member,
        protections,
        fips,
        calls,
    }
}
fn built(entry: Entry) -> CryptoProvider {
    CryptoProvider::builder().with(entry).build().unwrap()
}
fn protections(mask: u8) -> [bool; 2] {
    [mask & 1 != 0, mask & 2 != 0]
}

#[rstest]
fn builder_errors(#[values(0, 1, 2, 3)] area: usize) {
    let calls = Arc::default();
    let e = entry(area, mock(1, [false, false], false, calls));
    let algorithm = helpers::entry_algorithm(&e);
    assert_eq!(
        CryptoProvider::builder().with(e).build().unwrap_err(),
        BuildError::NoProtection(algorithm)
    );
    let e = entry(area, mock(1, [true, false], false, Arc::default()));
    assert_eq!(
        CryptoProvider::builder().with(e.clone()).with(e).build().unwrap_err(),
        BuildError::Duplicate(algorithm)
    );
}

#[test]
fn mismatched_agreement() {
    let e = Entry::KeyAgreement(Arc::new(mock(1, [true, true], false, Arc::default())));
    assert_eq!(
        CryptoProvider::builder().with(e).build().unwrap_err(),
        BuildError::Mismatched(Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh))
    );
}

#[rstest]
fn composition(#[values(0, 1, 2, 3)] area: usize) {
    property(
        "provider-value/protection composition",
        (1u8..4, 1u8..4, any::<bool>(), any::<bool>()),
        |(primary, fallback, primary_fips, fallback_fips)| {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let primary = built(entry(
                area,
                mock(1, protections(primary), primary_fips, Arc::clone(&calls)),
            ));
            let fallback = built(entry(
                area,
                mock(2, protections(fallback), fallback_fips, Arc::clone(&calls)),
            ));
            let composed = primary.with_fallback(&fallback);
            prop_assert_eq!(composed.fips(), primary_fips && fallback_fips);
            let pe = primary.entries().next().unwrap();
            let fe = fallback.entries().next().unwrap();
            let algorithm = helpers::entry_algorithm(pe);
            let ce = composed.get(algorithm).unwrap();
            let supports = |e: &Entry, p| match e {
                Entry::Mac(e) => e.supports(p),
                Entry::Cipher(e) => e.supports(p),
                Entry::Aead(e) => e.supports(p),
                Entry::KeyWrap(e) => e.supports(p),
                _ => unreachable!(),
            };
            let mut serving_fips = true;
            let mut both = true;
            for p in [Protection::Apply, Protection::Process] {
                let primary_serves = supports(pe, p);
                let fallback_serves = supports(fe, p);
                let union = primary_serves || fallback_serves;
                prop_assert_eq!(supports(ce, p), union);
                both &= union;
                let requirement = match algorithm {
                    Algorithm::Mac(a) => Requirement::Mac(a, p),
                    Algorithm::Cipher(a) => Requirement::Cipher(a, p),
                    Algorithm::Aead(a) => Requirement::Aead(a, p),
                    Algorithm::KeyWrap(a) => Requirement::KeyWrap(a, p),
                    _ => unreachable!(),
                };
                prop_assert_eq!(helpers::missing(&composed, &[requirement]).is_empty(), union);
                calls.lock().unwrap().clear();
                match ce {
                    Entry::Mac(e) => {
                        let result = e.start(&[1], p);
                        if union {
                            let mut context = result.unwrap();
                            context.update(&[]).unwrap();
                            assert_eq!(context.finish().err(), Some(Error::ProviderFailure));
                        } else {
                            prop_assert_eq!(result.err(), Some(Error::Unsupported(algorithm)));
                        }
                    }
                    Entry::Cipher(e) => {
                        let result = if p == Protection::Apply {
                            e.encrypt(&[], &[], &[])
                        } else {
                            e.decrypt(&[], &[], &[])
                        };
                        prop_assert_eq!(
                            result.err(),
                            Some(if union {
                                Error::ProviderFailure
                            } else {
                                Error::Unsupported(algorithm)
                            })
                        );
                    }
                    Entry::Aead(e) => {
                        let result = if p == Protection::Apply {
                            e.seal(&[], &[], &[]).map(|s| s.nonce)
                        } else {
                            e.open(&[], &[], &[], &[])
                        };
                        prop_assert_eq!(
                            result.err(),
                            Some(if union {
                                Error::ProviderFailure
                            } else {
                                Error::Unsupported(algorithm)
                            })
                        );
                    }
                    Entry::KeyWrap(e) => {
                        let result = if p == Protection::Apply {
                            e.wrap(&[], &[])
                        } else {
                            e.unwrap(&[], &[])
                        };
                        prop_assert_eq!(
                            result.err(),
                            Some(if union {
                                Error::ProviderFailure
                            } else {
                                Error::Unsupported(algorithm)
                            })
                        );
                    }
                    _ => unreachable!(),
                }
                let log = calls.lock().unwrap().clone();
                if union {
                    let member = if primary_serves { 1 } else { 2 };
                    prop_assert!(!log.is_empty());
                    prop_assert!(log.iter().all(|(id, _)| *id == member));
                    serving_fips &= if primary_serves { primary_fips } else { fallback_fips };
                } else {
                    prop_assert!(log.is_empty());
                }
            }
            prop_assert_eq!(helpers::entry_fips(ce), serving_fips);
            prop_assert_eq!(helpers::missing(&composed, &[algorithm.into()]).is_empty(), both);
            Ok(())
        },
    );
}

#[test]
fn algorithm_fallback_and_shadowing() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let empty = CryptoProvider::builder().build().unwrap();
    let primary = built(entry(4, mock(1, [true, true], true, Arc::clone(&calls))));
    let fallback = built(entry(4, mock(2, [true, true], true, Arc::clone(&calls))));
    let algorithm = Algorithm::Hash(HashAlgorithm::Sha256);
    assert!(!empty.fips());
    assert!(primary.fips());
    let composed = primary.with_fallback(&fallback);
    assert!(composed.fips());
    assert_eq!(
        helpers::hash(&composed, HashAlgorithm::Sha256).unwrap().start().err(),
        Some(Error::Unsupported(algorithm))
    );
    assert_eq!(*calls.lock().unwrap(), [(1, Protection::Apply)]);
    calls.lock().unwrap().clear();
    let filled = empty.with_fallback(&fallback);
    assert!(!filled.fips());
    helpers::hash(&filled, HashAlgorithm::Sha256).unwrap().start().ok();
    assert_eq!(*calls.lock().unwrap(), [(2, Protection::Apply)]);
    let non_fips = built(entry(4, mock(2, [true, true], false, Arc::clone(&calls))));
    assert!(!primary.with_fallback(&non_fips).fips());
    assert!(!primary.with_fallback(&non_fips).with_fallback(&fallback).fips());
    assert!(!primary.with_fallback(&non_fips.with_fallback(&fallback)).fips());
}

#[test]
fn mac_refused_input_does_not_fall_back() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let a = built(entry(0, mock(1, [true, true], true, Arc::clone(&calls))));
    let b = built(entry(0, mock(2, [true, true], true, Arc::clone(&calls))));
    let composite = a.with_fallback(&b);
    assert_eq!(
        helpers::mac(&composite, MacAlgorithm::HmacSha256)
            .unwrap()
            .start(&[], Protection::Apply)
            .err(),
        Some(Error::Unsupported(Algorithm::Mac(MacAlgorithm::HmacSha256)))
    );
    assert_eq!(*calls.lock().unwrap(), [(1, Protection::Apply)]);
}
