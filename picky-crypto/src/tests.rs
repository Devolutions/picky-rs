use crate::*;
use std::sync::{Arc, Mutex};

fn bytes(data: &[u8]) -> OutputBytes {
    OutputBytes::new(Zeroizing::new(data.to_vec()))
}
fn provider(entries: impl IntoIterator<Item = Entry>) -> CryptoProvider {
    entries
        .into_iter()
        .fold(CryptoProvider::builder(), ProviderBuilder::with)
        .build()
        .unwrap()
}

#[derive(Clone)]
struct Mock {
    marker: u8,
    protections: u8,
    approved: bool,
    hash: HashAlgorithm,
    agreement: KeyAgreementAlgorithm,
    calls: Arc<Mutex<Vec<Protection>>>,
    fail: Option<Error>,
    update_fail: Option<Error>,
    finish_fail: Option<Error>,
}
impl Mock {
    fn new(marker: u8, protections: u8, approved: bool) -> Self {
        Self {
            marker,
            protections,
            approved,
            hash: HashAlgorithm::Sha256,
            agreement: KeyAgreementAlgorithm::X25519,
            calls: Arc::default(),
            fail: None,
            update_fail: None,
            finish_fail: None,
        }
    }
    fn supports_protection(&self, protection: Protection) -> bool {
        self.protections
            & match protection {
                Protection::Apply => 1,
                Protection::Process => 2,
            }
            != 0
    }
    fn operation(&self, algorithm: Algorithm, protection: Protection) -> Result<OutputBytes, Error> {
        self.calls.lock().unwrap().push(protection);
        if !self.supports_protection(protection) {
            return Err(Error::Unsupported(algorithm));
        }
        if let Some(error) = self.fail {
            return Err(error);
        }
        Ok(bytes(&[self.marker]))
    }
}
impl std::fmt::Debug for Mock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SECRET BACKEND")
    }
}
struct Context {
    data: Vec<u8>,
    update_fail: Option<Error>,
    finish_fail: Option<Error>,
}
impl HashContext for Context {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(error) = self.update_fail {
            return Err(error);
        }
        self.data.extend_from_slice(data);
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<OutputBytes, Error> {
        if let Some(error) = self.finish_fail {
            return Err(error);
        }
        Ok(bytes(&self.data))
    }
}
impl MacContext for Context {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        HashContext::update(self, data)
    }
    fn finish(self: Box<Self>) -> Result<MacOutput, Error> {
        if let Some(error) = self.finish_fail {
            return Err(error);
        }
        Ok(MacOutput::new(Zeroizing::new(self.data)))
    }
}
impl Hash for Mock {
    fn algorithm(&self) -> HashAlgorithm {
        self.hash
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn start(&self) -> Result<Box<dyn HashContext>, Error> {
        if let Some(error) = self.fail {
            return Err(error);
        }
        Ok(Box::new(Context {
            data: vec![],
            update_fail: self.update_fail,
            finish_fail: self.finish_fail,
        }))
    }
}
impl Mac for Mock {
    fn algorithm(&self) -> MacAlgorithm {
        MacAlgorithm::HmacSha256
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn supports(&self, protection: Protection) -> bool {
        self.supports_protection(protection)
    }
    fn start(&self, _key: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error> {
        self.operation(Algorithm::Mac(MacAlgorithm::HmacSha256), protection)?;
        Ok(Box::new(Context {
            data: vec![self.marker; 16],
            update_fail: self.update_fail,
            finish_fail: self.finish_fail,
        }))
    }
}
impl Cipher for Mock {
    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Aes128Cbc
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn supports(&self, protection: Protection) -> bool {
        self.supports_protection(protection)
    }
    fn encrypt(&self, _key: &[u8], _iv: &[u8], _data: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(Algorithm::Cipher(CipherAlgorithm::Aes128Cbc), Protection::Apply)
    }
    fn decrypt(&self, _key: &[u8], _iv: &[u8], _data: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(Algorithm::Cipher(CipherAlgorithm::Aes128Cbc), Protection::Process)
    }
}
impl Aead for Mock {
    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes128Gcm
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn supports(&self, protection: Protection) -> bool {
        self.supports_protection(protection)
    }
    fn seal(&self, _key: &[u8], _aad: &[u8], _data: &[u8]) -> Result<Sealed, Error> {
        Ok(Sealed::new(
            bytes(&[0; 12]),
            self.operation(Algorithm::Aead(AeadAlgorithm::Aes128Gcm), Protection::Apply)?,
        ))
    }
    fn open(&self, _key: &[u8], _nonce: &[u8], _aad: &[u8], _data: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(Algorithm::Aead(AeadAlgorithm::Aes128Gcm), Protection::Process)
    }
}
impl KeyWrap for Mock {
    fn algorithm(&self) -> KeyWrapAlgorithm {
        KeyWrapAlgorithm::Aes128Kw
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn supports(&self, protection: Protection) -> bool {
        self.supports_protection(protection)
    }
    fn wrap(&self, _key: &[u8], _data: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(Algorithm::KeyWrap(KeyWrapAlgorithm::Aes128Kw), Protection::Apply)
    }
    fn unwrap(&self, _key: &[u8], _data: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(Algorithm::KeyWrap(KeyWrapAlgorithm::Aes128Kw), Protection::Process)
    }
}
impl PasswordKdf for Mock {
    fn algorithm(&self) -> PasswordKdfAlgorithm {
        PasswordKdfAlgorithm::Pbkdf2HmacSha256
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, _len: usize) -> Result<OutputBytes, Error> {
        Err(Error::ProviderFailure)
    }
}
impl Kdf for Mock {
    fn algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::OneStepSha256
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn derive(&self, _secret: &[u8], _info: &[u8], _len: usize) -> Result<OutputBytes, Error> {
        Err(Error::ProviderFailure)
    }
}
impl StreamCipher for Mock {
    fn algorithm(&self) -> StreamCipherAlgorithm {
        StreamCipherAlgorithm::Rc4
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn start(&self, _key: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error> {
        Err(Error::ProviderFailure)
    }
}
impl SignatureVerifier for Mock {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn verify(&self, _key: PublicKey<'_>, _message: &[u8], _signature: &[u8]) -> Result<(), Error> {
        Err(Error::VerificationFailed)
    }
}
impl AsymmetricEncryptor for Mock {
    fn algorithm(&self) -> AsymmetricEncryptionAlgorithm {
        AsymmetricEncryptionAlgorithm::RsaOaepSha256
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn encrypt(&self, _key: PublicKey<'_>, _message: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::InvalidKey)
    }
}
impl KeyAgreement for Mock {
    fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.agreement
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error> {
        Err(Error::ProviderFailure)
    }
}
impl FfdhKeyAgreement for Mock {
    fn fips(&self) -> bool {
        self.approved
    }
    fn generate_ephemeral(&self, _parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error> {
        Err(Error::InvalidInput)
    }
}
impl PrivateKeyLoader for Mock {
    fn key_type(&self) -> KeyType {
        KeyType::X25519
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn load(&self, _key: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        Err(Error::InvalidKey)
    }
}
impl KeyGenerator for Mock {
    fn algorithm(&self) -> KeyGenerationAlgorithm {
        KeyGenerationAlgorithm::Ed25519
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn generate(&self) -> Result<OutputBytes, Error> {
        Err(Error::ProviderFailure)
    }
}
impl SecureRandom for Mock {
    fn algorithm(&self) -> RandomAlgorithm {
        RandomAlgorithm::SecureRandom
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        dest.fill(self.marker);
        self.fail.map_or(Ok(()), Err)
    }
}
impl PrivateKey for Mock {
    fn key_type(&self) -> KeyType {
        KeyType::Ffdh
    }
    fn key_size_bits(&self) -> usize {
        2048
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        operation == KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)
    }
    fn fips(&self) -> bool {
        self.approved
    }
    fn agree(&self, algorithm: KeyAgreementAlgorithm, peer: &[u8]) -> Result<OutputBytes, Error> {
        assert_eq!(algorithm, KeyAgreementAlgorithm::Ffdh);
        self.fail.map_or_else(|| Ok(bytes(peer)), Err)
    }
}

fn all_entries(mock: &Arc<Mock>) -> Vec<Entry> {
    vec![
        Entry::Hash(mock.clone()),
        Entry::Mac(mock.clone()),
        Entry::PasswordKdf(mock.clone()),
        Entry::Kdf(mock.clone()),
        Entry::Cipher(mock.clone()),
        Entry::StreamCipher(mock.clone()),
        Entry::Aead(mock.clone()),
        Entry::KeyWrap(mock.clone()),
        Entry::SignatureVerifier(mock.clone()),
        Entry::AsymmetricEncryptor(mock.clone()),
        Entry::KeyAgreement(mock.clone()),
        Entry::FfdhKeyAgreement(mock.clone()),
        Entry::PrivateKeyLoader(mock.clone()),
        Entry::KeyGenerator(mock.clone()),
        Entry::SecureRandom(mock.clone()),
    ]
}

#[test]
fn builder_and_metadata() {
    assert!(!provider([]).fips());
    let mock = Arc::new(Mock::new(17, 3, true));
    let entries = all_entries(&mock);
    let p = provider(entries.clone());
    assert!(p.fips());
    assert_eq!(p.entries().count(), 15);
    for entry in entries {
        let algorithm = helpers::entry_algorithm(&entry);
        assert!(p.get(algorithm).is_some());
        assert!(helpers::entry_fips(&entry));
        let result = CryptoProvider::builder().with(entry.clone()).with(entry).build();
        assert_eq!(result.unwrap_err(), BuildError::Duplicate(algorithm));
    }
    assert!(p.get(Algorithm::PublicKeyExport(KeyType::X25519)).is_none());
    let mut wrong = (*mock).clone();
    wrong.agreement = KeyAgreementAlgorithm::Ffdh;
    wrong.protections = 0;
    let algorithm = Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh);
    for entries in [
        vec![Entry::KeyAgreement(Arc::new(wrong.clone()))],
        vec![
            Entry::FfdhKeyAgreement(mock.clone()),
            Entry::KeyAgreement(Arc::new(wrong)),
        ],
    ] {
        let result = entries
            .into_iter()
            .fold(CryptoProvider::builder(), ProviderBuilder::with)
            .build();
        assert_eq!(result.unwrap_err(), BuildError::Mismatched(algorithm));
    }
    assert!(!provider(all_entries(&Arc::new(Mock::new(1, 3, false)))).fips());
}

type Directional = fn(Arc<Mock>) -> Entry;
const DIRECTIONAL: [Directional; 4] = [
    |m| Entry::Mac(m),
    |m| Entry::Cipher(m),
    |m| Entry::Aead(m),
    |m| Entry::KeyWrap(m),
];

#[test]
fn builder_requires_protection_before_checking_duplicates() {
    for make in DIRECTIONAL {
        let empty = make(Arc::new(Mock::new(1, 0, true)));
        let algorithm = helpers::entry_algorithm(&empty);
        assert_eq!(
            CryptoProvider::builder().with(empty.clone()).build().unwrap_err(),
            BuildError::NoProtection(algorithm)
        );
        for protections in [1, 2] {
            let valid = make(Arc::new(Mock::new(1, protections, true)));
            assert!(CryptoProvider::builder().with(valid.clone()).build().is_ok());
            assert_eq!(
                CryptoProvider::builder()
                    .with(valid)
                    .with(empty.clone())
                    .build()
                    .unwrap_err(),
                BuildError::NoProtection(algorithm)
            );
        }
    }
}

fn supported(entry: &Entry, p: Protection) -> bool {
    match entry {
        Entry::Mac(e) => e.supports(p),
        Entry::Cipher(e) => e.supports(p),
        Entry::Aead(e) => e.supports(p),
        Entry::KeyWrap(e) => e.supports(p),
        _ => unreachable!(),
    }
}
fn invoke(entry: &Entry, p: Protection) -> Result<OutputBytes, Error> {
    match (entry, p) {
        (Entry::Mac(e), Protection::Apply) => MacGeneration::start(&**e, &[])?
            .finish()
            .map(|t| OutputBytes::new(t.into_inner())),
        (Entry::Mac(e), Protection::Process) => {
            let tag = MacVerification::start(&**e, &[])?.finish()?;
            for marker in [17, 29] {
                if tag.verify(&[marker; 16], 16) {
                    return Ok(bytes(&[marker]));
                }
            }
            panic!("unknown mock marker")
        }
        (Entry::Cipher(e), Protection::Apply) => e.encrypt(&[], &[], &[]),
        (Entry::Cipher(e), Protection::Process) => e.decrypt(&[], &[], &[]),
        (Entry::Aead(e), Protection::Apply) => e.seal(&[], &[], &[]).map(|s| s.ciphertext_and_tag),
        (Entry::Aead(e), Protection::Process) => e.open(&[], &[], &[], &[]),
        (Entry::KeyWrap(e), Protection::Apply) => e.wrap(&[], &[]),
        (Entry::KeyWrap(e), Protection::Process) => e.unwrap(&[], &[]),
        _ => unreachable!(),
    }
}
fn same_entry(a: &Entry, b: &Entry) -> bool {
    match (a, b) {
        (Entry::Mac(a), Entry::Mac(b)) => Arc::ptr_eq(a, b),
        (Entry::Cipher(a), Entry::Cipher(b)) => Arc::ptr_eq(a, b),
        (Entry::Aead(a), Entry::Aead(b)) => Arc::ptr_eq(a, b),
        (Entry::KeyWrap(a), Entry::KeyWrap(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

#[test]
fn directional_composition_dispatch_and_fips() {
    struct Model {
        composite: bool,
        supports: [bool; 2],
        primary_serves: [bool; 2],
        entry_fips: bool,
        provider_fips: bool,
    }
    fn model(primary: [bool; 2], fallback: [bool; 2], primary_fips: bool, fallback_fips: bool) -> Model {
        let composite = (0..2).any(|i| !primary[i] && fallback[i]);
        let supports = std::array::from_fn(|i| primary[i] || composite && fallback[i]);
        let primary_serves = std::array::from_fn(|i| primary[i] || !fallback[i]);
        let entry_fips = if composite {
            (0..2).all(|i| !supports[i] || if primary_serves[i] { primary_fips } else { fallback_fips })
        } else {
            primary_fips
        };
        Model {
            composite,
            supports,
            primary_serves,
            entry_fips,
            provider_fips: primary_fips && fallback_fips,
        }
    }
    for make in DIRECTIONAL {
        for bits in 0..64u8 {
            let primary_mask = bits & 3;
            let fallback_mask = (bits >> 2) & 3;
            if primary_mask == 0 || fallback_mask == 0 {
                continue;
            }
            let primary_fips = bits & 16 != 0;
            let fallback_fips = bits & 32 != 0;
            let expected = model(
                [bits & 1 != 0, bits & 2 != 0],
                [bits & 4 != 0, bits & 8 != 0],
                primary_fips,
                fallback_fips,
            );
            let primary = Arc::new(Mock::new(17, primary_mask, primary_fips));
            let fallback = Arc::new(Mock::new(29, fallback_mask, fallback_fips));
            let original = make(primary.clone());
            let secondary = make(fallback.clone());
            let algorithm = helpers::entry_algorithm(&original);
            let combined = provider([original.clone()]).with_fallback(&provider([secondary.clone()]));
            let entry = combined.get(algorithm).unwrap();
            assert_eq!(same_entry(&original, entry), !expected.composite);
            assert!(!same_entry(&secondary, entry));
            let mut primary_calls = Vec::new();
            let mut fallback_calls = Vec::new();
            for (i, protection) in [Protection::Apply, Protection::Process].into_iter().enumerate() {
                assert_eq!(supported(entry, protection), expected.supports[i]);
                let result = invoke(entry, protection);
                if expected.supports[i] {
                    assert_eq!(result.unwrap()[0], if expected.primary_serves[i] { 17 } else { 29 });
                } else {
                    assert_eq!(result.unwrap_err(), Error::Unsupported(algorithm));
                }
                if expected.primary_serves[i] {
                    primary_calls.push(protection);
                } else {
                    fallback_calls.push(protection);
                }
            }
            assert_eq!(*primary.calls.lock().unwrap(), primary_calls);
            assert_eq!(*fallback.calls.lock().unwrap(), fallback_calls);
            assert_eq!(helpers::entry_fips(entry), expected.entry_fips);
            assert_eq!(combined.fips(), expected.provider_fips);
        }
    }
}

#[test]
fn composition_never_retries_inputs_and_preserves_shadowed_status() {
    for make in DIRECTIONAL {
        let mut primary = Mock::new(17, 1, true);
        primary.fail = Some(Error::InvalidInput);
        let fallback = Arc::new(Mock::new(29, 3, false));
        let p = provider([make(Arc::new(primary))]).with_fallback(&provider([make(fallback.clone())]));
        let entry = p.entries().next().unwrap();
        assert_eq!(invoke(entry, Protection::Apply).unwrap_err(), Error::InvalidInput);
        assert!(fallback.calls.lock().unwrap().is_empty());
    }
    let primary = provider([Entry::Hash(Arc::new(Mock::new(17, 3, true)))]);
    let fallback = provider([Entry::Hash(Arc::new(Mock::new(29, 3, false)))]);
    let result = primary.with_fallback(&fallback);
    assert!(std::ptr::eq(
        helpers::hash(&result, HashAlgorithm::Sha256).unwrap(),
        helpers::hash(&primary, HashAlgorithm::Sha256).unwrap(),
    ));
    assert_eq!(&*helpers::digest(&result, HashAlgorithm::Sha256, &[71]).unwrap(), &[71]);
    assert!(helpers::entry_fips(result.entries().next().unwrap()));
    assert!(!result.fips());
    assert!(!result.with_fallback(&primary).fips());
    assert!(!primary.with_fallback(&result).fips());
    assert!(!primary.with_fallback(&provider([])).fips());
    let mut other = Mock::new(29, 3, true);
    other.hash = HashAlgorithm::Sha1;
    let extended = primary.with_fallback(&provider([Entry::Hash(Arc::new(other))]));
    assert_eq!(extended.entries().count(), 2);
    assert!(extended.fips());
    assert!(!provider([]).with_fallback(&primary).fips());
}

#[test]
fn missing_requirements_preserve_order_and_protections() {
    let mock = Arc::new(Mock::new(17, 2, true));
    let p = provider(DIRECTIONAL.into_iter().map(|make| make(mock.clone())));
    let requirements = [
        Requirement::from(Algorithm::Mac(MacAlgorithm::HmacSha256)),
        Requirement::Mac(MacAlgorithm::HmacSha256, Protection::Process),
        Requirement::Mac(MacAlgorithm::HmacSha256, Protection::Apply),
        Requirement::from(Algorithm::Cipher(CipherAlgorithm::Aes128Cbc)),
        Requirement::Cipher(CipherAlgorithm::Aes128Cbc, Protection::Process),
        Requirement::Cipher(CipherAlgorithm::Aes128Cbc, Protection::Apply),
        Requirement::from(Algorithm::Aead(AeadAlgorithm::Aes128Gcm)),
        Requirement::Aead(AeadAlgorithm::Aes128Gcm, Protection::Process),
        Requirement::Aead(AeadAlgorithm::Aes128Gcm, Protection::Apply),
        Requirement::from(Algorithm::KeyWrap(KeyWrapAlgorithm::Aes128Kw)),
        Requirement::KeyWrap(KeyWrapAlgorithm::Aes128Kw, Protection::Process),
        Requirement::KeyWrap(KeyWrapAlgorithm::Aes128Kw, Protection::Apply),
        Requirement::from(Algorithm::Hash(HashAlgorithm::Md4)),
        Requirement::Mac(MacAlgorithm::HmacSha1, Protection::Process),
        Requirement::from(Algorithm::Hash(HashAlgorithm::Md4)),
    ];
    assert_eq!(
        helpers::missing(&p, &requirements),
        [0, 2, 3, 5, 6, 8, 9, 11, 12, 13, 14].map(|i| requirements[i])
    );
    let full = provider(all_entries(&Arc::new(Mock::new(17, 3, true))));
    let required: Vec<_> = full.entries().map(|e| helpers::entry_algorithm(e).into()).collect();
    assert!(helpers::missing(&full, &required).is_empty());
}

#[test]
fn mac_wrappers_and_verifier_lengths() {
    let mock = Arc::new(Mock::new(173, 3, true));
    let p = provider([Entry::Mac(mock.clone())]);
    let tag = helpers::compute_mac(&p, MacAlgorithm::HmacSha256, &[], &[91, 92]).unwrap();
    let mut verification = MacVerification::start(&*mock, &[]).unwrap();
    verification.update(&[91]).unwrap();
    verification.update(&[92]).unwrap();
    let verifier = verification.finish().unwrap();
    let inner = tag.clone().into_inner();
    assert!(verifier.verify(&inner, 18));
    for len in [8, 12, 16, 18] {
        assert!(verifier.clone().verify(&inner[..len], len));
    }
    let mut wrong = inner.to_vec();
    for i in 0..wrong.len() {
        wrong[i] ^= 1;
        assert!(!verifier.verify(&wrong, 18));
        wrong[i] ^= 1;
    }
    assert!(!verifier.verify(&[], 0));
    assert!(!verifier.verify(&inner, 17));
    assert!(!verifier.verify(&[173; 19], 19));
    assert!(helpers::verify_mac(&p, MacAlgorithm::HmacSha256, &[], &[91, 92], &inner[..12], 12).unwrap());
    assert_eq!(
        *mock.calls.lock().unwrap(),
        [Protection::Apply, Protection::Process, Protection::Process]
    );
    let p = provider([Entry::Mac(Arc::new(Mock::new(173, 2, true)))]);
    assert_eq!(
        helpers::compute_mac(&p, MacAlgorithm::HmacSha256, &[], &[]).unwrap_err(),
        Error::Unsupported(Algorithm::Mac(MacAlgorithm::HmacSha256))
    );
}

#[test]
fn helpers_propagate_each_streaming_error() {
    for position in 0..3 {
        let mut mock = Mock::new(17, 3, true);
        let error = [Error::InvalidKey, Error::InvalidInput, Error::ProviderFailure][position];
        match position {
            0 => mock.fail = Some(error),
            1 => mock.update_fail = Some(error),
            _ => mock.finish_fail = Some(error),
        }
        let mock = Arc::new(mock);
        let p = provider([Entry::Hash(mock.clone()), Entry::Mac(mock)]);
        assert_eq!(helpers::digest(&p, HashAlgorithm::Sha256, &[]).unwrap_err(), error);
        assert_eq!(
            helpers::compute_mac(&p, MacAlgorithm::HmacSha256, &[], &[]).unwrap_err(),
            error
        );
        assert_eq!(
            helpers::verify_mac(&p, MacAlgorithm::HmacSha256, &[], &[], &[], 0).unwrap_err(),
            error
        );
    }
}

#[test]
fn accessors_present_and_absent() {
    let p = provider(all_entries(&Arc::new(Mock::new(17, 3, true))));
    let empty = provider([]);
    macro_rules! check {
        ($function:ident, $algorithm:expr, $wrapped:expr) => {
            assert!(helpers::$function(&p, $algorithm).is_ok());
            assert_eq!(
                helpers::$function(&empty, $algorithm).unwrap_err(),
                Error::Unsupported($wrapped)
            );
        };
    }
    check!(hash, HashAlgorithm::Sha256, Algorithm::Hash(HashAlgorithm::Sha256));
    check!(mac, MacAlgorithm::HmacSha256, Algorithm::Mac(MacAlgorithm::HmacSha256));
    check!(
        password_kdf,
        PasswordKdfAlgorithm::Pbkdf2HmacSha256,
        Algorithm::PasswordKdf(PasswordKdfAlgorithm::Pbkdf2HmacSha256)
    );
    check!(
        kdf,
        KdfAlgorithm::OneStepSha256,
        Algorithm::Kdf(KdfAlgorithm::OneStepSha256)
    );
    check!(
        cipher,
        CipherAlgorithm::Aes128Cbc,
        Algorithm::Cipher(CipherAlgorithm::Aes128Cbc)
    );
    check!(
        stream_cipher,
        StreamCipherAlgorithm::Rc4,
        Algorithm::StreamCipher(StreamCipherAlgorithm::Rc4)
    );
    check!(
        aead,
        AeadAlgorithm::Aes128Gcm,
        Algorithm::Aead(AeadAlgorithm::Aes128Gcm)
    );
    check!(
        key_wrap,
        KeyWrapAlgorithm::Aes128Kw,
        Algorithm::KeyWrap(KeyWrapAlgorithm::Aes128Kw)
    );
    check!(
        signature_verifier,
        SignatureAlgorithm::Ed25519,
        Algorithm::Signature(SignatureAlgorithm::Ed25519)
    );
    check!(
        asymmetric_encryptor,
        AsymmetricEncryptionAlgorithm::RsaOaepSha256,
        Algorithm::AsymmetricEncryption(AsymmetricEncryptionAlgorithm::RsaOaepSha256)
    );
    check!(
        key_agreement,
        KeyAgreementAlgorithm::X25519,
        Algorithm::KeyAgreement(KeyAgreementAlgorithm::X25519)
    );
    check!(
        private_key_loader,
        KeyType::X25519,
        Algorithm::PrivateKeyLoading(KeyType::X25519)
    );
    check!(
        key_generator,
        KeyGenerationAlgorithm::Ed25519,
        Algorithm::KeyGeneration(KeyGenerationAlgorithm::Ed25519)
    );
    check!(
        secure_random,
        RandomAlgorithm::SecureRandom,
        Algorithm::Random(RandomAlgorithm::SecureRandom)
    );
    assert!(helpers::ffdh_key_agreement(&p).is_ok());
    assert_eq!(
        helpers::ffdh_key_agreement(&empty).unwrap_err(),
        Error::Unsupported(Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh))
    );
    for provider in [&p, &empty] {
        assert_eq!(
            helpers::key_agreement(provider, KeyAgreementAlgorithm::Ffdh).unwrap_err(),
            Error::InvalidInput
        );
    }
}

#[test]
fn random_clamping_and_ffdh_public_value() {
    for marker in [0, 255, 173] {
        let p = provider([Entry::SecureRandom(Arc::new(Mock::new(marker, 3, false)))]);
        let scalar = helpers::random_x25519_private_key(&p).unwrap();
        assert_eq!(scalar[0], marker & 248);
        assert_eq!(scalar[31], (marker & 127) | 64);
        assert_eq!(&scalar[1..31], &[marker; 30]);
    }
    assert_eq!(
        helpers::random_x25519_private_key(&provider([])).unwrap_err(),
        Error::Unsupported(Algorithm::Random(RandomAlgorithm::SecureRandom))
    );
    let mut mock = Mock::new(17, 3, true);
    mock.fail = Some(Error::ProviderFailure);
    assert_eq!(
        helpers::random_x25519_private_key(&provider([Entry::SecureRandom(Arc::new(mock.clone()))])).unwrap_err(),
        Error::ProviderFailure
    );
    let parameters = FfdhParameters::new(&[71], &[81, 82], Some(&[91]));
    assert_eq!(
        helpers::ffdh_public_value(&mock, parameters).unwrap_err(),
        Error::ProviderFailure
    );
    mock.fail = None;
    assert_eq!(&*helpers::ffdh_public_value(&mock, parameters).unwrap(), &[81, 82]);
}

struct BareKey;
impl PrivateKey for BareKey {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn key_size_bits(&self) -> usize {
        2048
    }
    fn supports(&self, _operation: KeyOperation) -> bool {
        false
    }
    fn fips(&self) -> bool {
        false
    }
}
#[test]
fn private_key_defaults_and_error_messages() {
    let key = BareKey;
    assert_eq!(
        key.sign(SignatureAlgorithm::Ed25519, &[]).unwrap_err(),
        Error::Unsupported(Algorithm::Signature(SignatureAlgorithm::Ed25519))
    );
    assert_eq!(
        key.decrypt(AsymmetricEncryptionAlgorithm::RsaPkcs1v15, &[])
            .unwrap_err(),
        Error::Unsupported(Algorithm::AsymmetricEncryption(
            AsymmetricEncryptionAlgorithm::RsaPkcs1v15
        ))
    );
    assert_eq!(
        key.agree(KeyAgreementAlgorithm::X25519, &[]).unwrap_err(),
        Error::Unsupported(Algorithm::KeyAgreement(KeyAgreementAlgorithm::X25519))
    );
    assert_eq!(
        key.public_key().unwrap_err(),
        Error::Unsupported(Algorithm::PublicKeyExport(KeyType::Rsa))
    );
    for (error, message) in [
        (Error::InvalidKey, "invalid key"),
        (Error::InvalidInput, "invalid input"),
        (Error::VerificationFailed, "verification failed"),
        (Error::ProviderFailure, "provider failure"),
    ] {
        assert_eq!(error.to_string(), message);
        assert!(std::error::Error::source(&error).is_none());
    }
    let algorithm = Algorithm::Hash(HashAlgorithm::Sha256);
    assert_eq!(Error::Unsupported(algorithm).to_string(), "unsupported: Hash(Sha256)");
    assert_eq!(
        BuildError::Duplicate(algorithm).to_string(),
        "duplicate algorithm: Hash(Sha256)"
    );
    assert_eq!(
        BuildError::Mismatched(algorithm).to_string(),
        "mismatched algorithm: Hash(Sha256)"
    );
    let algorithm = Algorithm::Mac(MacAlgorithm::HmacSha256);
    assert_eq!(
        BuildError::NoProtection(algorithm).to_string(),
        "no protection: Mac(HmacSha256)"
    );
}

#[test]
fn zeroizing_wrappers_and_material_redact_bytes() {
    let output = bytes(&[173; 16]);
    let scalar = X25519Scalar::new(Zeroizing::new([173; 32]));
    let mock = Mock::new(173, 3, true);
    let tag = MacGeneration::start(&mock, &[]).unwrap().finish().unwrap();
    let verifier = MacVerification::start(&mock, &[]).unwrap().finish().unwrap();
    let sealed = Sealed::new(output.clone(), output.clone());
    for (actual, expected) in [
        (format!("{output:?}"), "OutputBytes { len: 16 }"),
        (format!("{scalar:?}"), "X25519Scalar { len: 32 }"),
        (
            format!("{:?}", MacOutput::new(Zeroizing::new(vec![173; 16]))),
            "MacOutput { len: 16 }",
        ),
        (format!("{tag:?}"), "MacTag { len: 16 }"),
        (format!("{verifier:?}"), "MacVerifier { len: 16 }"),
        (
            format!("{sealed:?}"),
            "Sealed { nonce: OutputBytes { len: 16 }, ciphertext_and_tag: OutputBytes { len: 16 } }",
        ),
        (format!("{:?}", PrivateKeyMaterial::Pkcs8(&output)), "Pkcs8 { .. }"),
        (format!("{:?}", PrivateKeyMaterial::X25519(&scalar)), "X25519 { .. }"),
        (
            format!(
                "{:?}",
                PrivateKeyMaterial::Ffdh {
                    parameters: FfdhParameters::new(&output, &output, Some(&output)),
                    private_value: &output
                }
            ),
            "Ffdh { .. }",
        ),
    ] {
        assert_eq!(actual, expected);
        assert!(!actual.contains("173"));
    }
    assert_eq!(output.clone().into_inner().as_slice(), &[173; 16]);
    assert_eq!(output.as_ref(), &[173; 16]);
    assert_eq!(*scalar.clone().into_inner(), [173; 32]);
    assert_eq!(scalar.as_ref(), &[173; 32]);
    assert_eq!(tag.into_inner().as_slice(), &[173; 16]);
}

#[test]
fn trait_object_debug_uses_contract_metadata() {
    let mock = Arc::new(Mock::new(173, 3, true));
    for (entry, expected) in all_entries(&mock).into_iter().zip([
        "Hash { algorithm: Sha256, fips: true }",
        "Mac { algorithm: HmacSha256, fips: true }",
        "PasswordKdf { algorithm: Pbkdf2HmacSha256, fips: true }",
        "Kdf { algorithm: OneStepSha256, fips: true }",
        "Cipher { algorithm: Aes128Cbc, fips: true }",
        "StreamCipher { algorithm: Rc4, fips: true }",
        "Aead { algorithm: Aes128Gcm, fips: true }",
        "KeyWrap { algorithm: Aes128Kw, fips: true }",
        "SignatureVerifier { algorithm: Ed25519, fips: true }",
        "AsymmetricEncryptor { algorithm: RsaOaepSha256, fips: true }",
        "KeyAgreement { algorithm: X25519, fips: true }",
        "FfdhKeyAgreement { algorithm: Ffdh, fips: true }",
        "PrivateKeyLoader { key_type: X25519, fips: true }",
        "KeyGenerator { algorithm: Ed25519, fips: true }",
        "SecureRandom { algorithm: SecureRandom, fips: true }",
    ]) {
        let actual = format!("{entry:?}");
        assert!(actual.contains(expected), "{actual}");
        assert!(!actual.contains("SECRET"));
    }
    let key: Box<dyn PrivateKey> = Box::new((*mock).clone());
    assert_eq!(format!("{key:?}"), "PrivateKey { key_type: Ffdh, fips: true }");
    assert_eq!(
        format!("{:?}", &BareKey as &dyn PrivateKey),
        "PrivateKey { key_type: Rsa, fips: false }"
    );
}

#[test]
fn hash_lengths() {
    for (algorithm, len) in [
        (HashAlgorithm::Md4, 16),
        (HashAlgorithm::Md5, 16),
        (HashAlgorithm::Sha1, 20),
        (HashAlgorithm::Sha224, 28),
        (HashAlgorithm::Sha256, 32),
        (HashAlgorithm::Sha384, 48),
        (HashAlgorithm::Sha512, 64),
        (HashAlgorithm::Sha3_384, 48),
        (HashAlgorithm::Sha3_512, 64),
    ] {
        assert_eq!(algorithm.output_len(), len);
    }
}
