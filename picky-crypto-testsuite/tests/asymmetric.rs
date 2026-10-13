use picky_crypto::*;
use picky_crypto_testsuite::algorithms::*;
use picky_crypto_testsuite::areas::ffdh::{
    FFC_FILE, below_modulus_minus_one, ffdh_exponent_boundaries, ffdh_parameter_boundaries,
};
use picky_crypto_testsuite::areas::private_key::{
    CiphertextSource, derived_export, inconsistent_decryption, inconsistent_rsa, inconsistent_signatures,
};
use picky_crypto_testsuite::areas::{key_generation, signature, signature::ed25519_undecodable_keys};
use picky_crypto_testsuite::harness::{Checks, Expect, Options, without_failure_persistence};
use picky_crypto_testsuite::keys::*;
use picky_crypto_testsuite::{der, vectors as v};
use rstest::rstest;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct BoundaryInputs {
    p: Vec<u8>,
    g: Vec<u8>,
    q: Option<Vec<u8>>,
    x: Option<Vec<u8>>,
}
struct BoundaryProvider(Arc<Mutex<Vec<BoundaryInputs>>>);
impl BoundaryProvider {
    fn record(&self, parameters: FfdhParameters<'_>, x: Option<&[u8]>) {
        self.0.lock().unwrap().push(BoundaryInputs {
            p: parameters.p.to_vec(),
            g: parameters.g.to_vec(),
            q: parameters.q.map(<[u8]>::to_vec),
            x: x.map(<[u8]>::to_vec),
        });
    }
}
impl FfdhKeyAgreement for BoundaryProvider {
    fn fips(&self) -> bool {
        false
    }
    fn generate_ephemeral(&self, parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error> {
        self.record(parameters, None);
        Err(Error::InvalidInput)
    }
}
impl PrivateKeyLoader for BoundaryProvider {
    fn key_type(&self) -> KeyType {
        KeyType::Ffdh
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        let PrivateKeyMaterial::Ffdh {
            parameters,
            private_value,
        } = material
        else {
            return Err(Error::InvalidKey);
        };
        self.record(parameters, Some(private_value));
        Err(Error::InvalidKey)
    }
}

#[test]
fn ffdh_parameter_boundaries_reach_both_capabilities() {
    let calls = Arc::default();
    let provider = CryptoProvider::builder()
        .with(Entry::FfdhKeyAgreement(Arc::new(BoundaryProvider(Arc::clone(&calls)))))
        .with(Entry::PrivateKeyLoader(Arc::new(BoundaryProvider(Arc::clone(&calls)))))
        .build()
        .unwrap();
    let groups = v::dh_groups();
    let mut checks = Checks::default();
    ffdh_parameter_boundaries(&mut checks, &provider, &groups);
    checks.finish();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    let group = &groups[0];
    let minus_one = modulus_minus_one(&group.p);
    for (pair, (p, g)) in calls
        .chunks_exact(2)
        .zip([(&minus_one, &group.g), (&group.p, &minus_one)])
    {
        for call in pair {
            assert_eq!(&call.p, p);
            assert_eq!(&call.g, g);
            assert!(call.q.is_none());
            assert_eq!(der::bit_length(&call.p), 1024);
        }
        assert!(pair[0].x.is_none());
        assert_eq!(pair[1].x.as_deref(), Some(&[1][..]));
    }
}

#[test]
fn ffdh_exponent_boundaries_use_published_safe_prime_orders() {
    let calls = Arc::default();
    let provider = CryptoProvider::builder()
        .with(Entry::PrivateKeyLoader(Arc::new(BoundaryProvider(Arc::clone(&calls)))))
        .build()
        .unwrap();
    let groups = v::dh_groups();
    let mut checks = Checks::default();
    ffdh_exponent_boundaries(&mut checks, &provider, &groups);
    checks.finish();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    for (pair, group) in calls
        .chunks_exact(2)
        .zip(groups.iter().filter(|group| group.id.starts_with("rfc/rfc7919.txt/")))
    {
        for call in pair {
            assert_eq!(call.p, group.p);
            assert_eq!(call.g, group.g);
            assert_eq!(call.x, group.q);
        }
        assert!(pair[0].q.is_none());
        assert_eq!(pair[1].q, group.q);
    }
}

type Calls = Arc<Mutex<Vec<(KeyOperation, Vec<u8>)>>>;

#[derive(Clone)]
struct BranchKey {
    kind: KeyType,
    bits: usize,
    enabled: Option<KeyOperation>,
    input: Vec<u8>,
    output: Vec<u8>,
    calls: Calls,
}
struct BranchLoader(BranchKey);
impl PrivateKeyLoader for BranchLoader {
    fn key_type(&self) -> KeyType {
        self.0.kind
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, _: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        Ok(Box::new(self.0.clone()))
    }
}
fn operation_algorithm(operation: KeyOperation, kind: KeyType) -> Algorithm {
    match operation {
        KeyOperation::Sign(a) => Algorithm::Signature(a),
        KeyOperation::Decrypt(a) => Algorithm::AsymmetricEncryption(a),
        KeyOperation::Agree(a) => Algorithm::KeyAgreement(a),
        KeyOperation::PublicKey => Algorithm::PublicKeyExport(kind),
        _ => unreachable!(),
    }
}
impl BranchKey {
    fn operation(&self, operation: KeyOperation, input: &[u8]) -> Result<OutputBytes, Error> {
        self.calls.lock().unwrap().push((operation, input.to_vec()));
        if !self.supports(operation) {
            return Err(Error::Unsupported(operation_algorithm(operation, self.kind)));
        }
        if matches!(operation, KeyOperation::Decrypt(_) | KeyOperation::Agree(_)) && input.is_empty() {
            return Err(Error::InvalidInput);
        }
        if operation != KeyOperation::PublicKey && input != self.input {
            return Err(Error::InvalidInput);
        }
        Ok(OutputBytes::new(Zeroizing::new(self.output.clone())))
    }
}
impl PrivateKey for BranchKey {
    fn key_type(&self) -> KeyType {
        self.kind
    }
    fn key_size_bits(&self) -> usize {
        self.bits
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        self.enabled == Some(operation)
    }
    fn sign(&self, a: SignatureAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(KeyOperation::Sign(a), input)
    }
    fn decrypt(&self, a: AsymmetricEncryptionAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(KeyOperation::Decrypt(a), input)
    }
    fn agree(&self, a: KeyAgreementAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
        self.operation(KeyOperation::Agree(a), input)
    }
    fn public_key(&self) -> Result<OutputBytes, Error> {
        self.operation(KeyOperation::PublicKey, &[])
    }
}

#[rstest]
fn private_operation_branches_use_advertisement(
    #[values(0, 1, 2, 3)] area: usize,
    #[values(false, true)] advertised: bool,
) {
    let (kind, bits, operation, encoded, input, output, id) = match area {
        0 => {
            let corpus = v::wycheproof(RSA_SIGN_FILES[0]);
            let group = &corpus.test_groups[0];
            let t = &v::tests(group)[0];
            (
                KeyType::Rsa,
                2048,
                KeyOperation::Sign(rsa_signature(v::string(group, "sha"))),
                v::field(group, "privateKeyPkcs8"),
                v::field(t, "msg"),
                v::field(t, "sig"),
                v::id(SignatureAlgorithm::RsaPkcs1v15Sha1, RSA_SIGN_FILES[0], t),
            )
        }
        1 => {
            let file = RSA_DECRYPT_FILES[0].0;
            let corpus = v::wycheproof(file);
            let group = &corpus.test_groups[0];
            let t = v::tests(group)
                .iter()
                .find(|t| v::string(t, "result") == "valid" && !v::field(t, "msg").is_empty())
                .unwrap();
            (
                KeyType::Rsa,
                2048,
                KeyOperation::Decrypt(AsymmetricEncryptionAlgorithm::RsaPkcs1v15),
                v::field(group, "privateKeyPkcs8"),
                v::field(t, "ct"),
                v::field(t, "msg"),
                v::id(AsymmetricEncryptionAlgorithm::RsaPkcs1v15, file, t),
            )
        }
        2 => {
            let fields = v::rfc5114(6);
            let public = der::point(&fields["x_qA"], &fields["y_qA"], 32);
            (
                KeyType::EcP256,
                256,
                KeyOperation::Agree(KeyAgreementAlgorithm::EcdhP256),
                der::ec(KeyType::EcP256, &fields["dA"], Some(&public), None),
                der::point(&fields["x_qB"], &fields["y_qB"], 32),
                der::padded(&fields["x_Z"], 32),
                "rfc/rfc5114.txt/A.6".to_owned(),
            )
        }
        _ => {
            let corpus = v::wycheproof(RSA_SIGN_FILES[0]);
            let group = &corpus.test_groups[0];
            let encoded = v::field(group, "privateKeyPkcs8");
            let public = der::rsa_public(&encoded);
            (
                KeyType::Rsa,
                2048,
                KeyOperation::PublicKey,
                encoded,
                v::field(&v::tests(group)[0], "msg"),
                public,
                format!(
                    "{}/tcId={}/public key",
                    RSA_SIGN_FILES[0],
                    v::number(&v::tests(group)[0], "tcId")
                ),
            )
        }
    };
    let calls = Arc::default();
    let mock = BranchKey {
        kind,
        bits,
        enabled: advertised.then_some(operation),
        input: input.clone(),
        output: output.clone(),
        calls: Arc::clone(&calls),
    };
    let provider = CryptoProvider::builder()
        .with(Entry::PrivateKeyLoader(Arc::new(BranchLoader(mock))))
        .build()
        .unwrap();
    let mut checks = Checks::default();
    let key = loaded(
        &mut checks,
        &provider,
        kind,
        PrivateKeyMaterial::Pkcs8(&encoded),
        &id,
        bits,
        false,
        false,
    )
    .unwrap();
    let selection_calls: Vec<_> = calls.lock().unwrap().iter().map(|(call, _)| *call).collect();
    let selected_count = selection_calls.iter().filter(|&&call| call == operation).count();
    assert_eq!(selected_count, if advertised && area == 0 { 0 } else { 1 });
    if !advertised {
        for algorithm in SIGNATURES {
            assert!(selection_calls.contains(&KeyOperation::Sign(algorithm)));
        }
        for algorithm in ENCRYPTIONS {
            assert!(selection_calls.contains(&KeyOperation::Decrypt(algorithm)));
        }
        for algorithm in AGREEMENTS {
            assert!(selection_calls.contains(&KeyOperation::Agree(algorithm)));
        }
        assert!(selection_calls.contains(&KeyOperation::PublicKey));
    }
    let expected = if advertised {
        Expect::Success
    } else {
        Expect::Error(Error::Unsupported(operation_algorithm(operation, kind)))
    };
    match operation {
        KeyOperation::Agree(a) => agree_kat(&mut checks, &id, &*key, a, &input, &output, false),
        KeyOperation::PublicKey => exported(&mut checks, &id, &*key, &output),
        KeyOperation::Sign(a) => {
            if let Some(value) = checks.call(&id, expected, || key.sign(a, &input)) {
                checks.bytes(&id, &value, &output);
            }
        }
        KeyOperation::Decrypt(a) => {
            if let Some(value) = checks.call(&id, expected, || key.decrypt(a, &input)) {
                checks.bytes(&id, &value, &output);
            }
        }
        _ => unreachable!(),
    }
    checks.finish();
}

struct RepeatedGenerator {
    encodings: Vec<Vec<u8>>,
    calls: Arc<AtomicUsize>,
}
impl KeyGenerator for RepeatedGenerator {
    fn algorithm(&self) -> KeyGenerationAlgorithm {
        KeyGenerationAlgorithm::EcP256
    }
    fn fips(&self) -> bool {
        false
    }
    fn generate(&self) -> Result<OutputBytes, Error> {
        let index = self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(OutputBytes::new(Zeroizing::new(
            self.encodings[index % self.encodings.len()].clone(),
        )))
    }
}

#[test]
fn generated_key_freshness_compares_public_fields() {
    let (scalar, x, y, _) = v::ec9500().into_iter().next().unwrap();
    let public = der::point(&x, &y, 32);
    let encodings = vec![
        der::ec(KeyType::EcP256, &scalar, Some(&public), None),
        der::ec(KeyType::EcP256, &scalar, Some(&public), Some(KeyType::EcP256)),
    ];
    assert_ne!(encodings[0], encodings[1]);
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = CryptoProvider::builder()
        .with(Entry::KeyGenerator(Arc::new(RepeatedGenerator {
            encodings,
            calls: Arc::clone(&calls),
        })))
        .build()
        .unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        key_generation::run(&provider, Options::default())
    }))
    .unwrap_err();
    let message = failure.downcast_ref::<String>().unwrap();
    assert!(message.contains("generated public keys are identical"));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn ffdh_boundary_helpers_on_published_groups() {
    for (i, group) in v::dh_groups().iter().enumerate() {
        let y = modulus_minus_one(&group.p);
        assert_eq!(y.len(), group.p.len(), "{}", group.id);
        assert_eq!(y[..y.len() - 1], group.p[..group.p.len() - 1], "{}", group.id);
        assert_eq!(y[y.len() - 1] + 1, group.p[group.p.len() - 1], "{}", group.id);
        assert!(!below_modulus_minus_one(&group.p, &group.p), "{}", group.id);
        if i < 3 {
            let published = v::rfc5114(i + 1);
            assert!(below_modulus_minus_one(&published["yA"], &group.p));
            assert!(below_modulus_minus_one(&published["yB"], &group.p));
        }
    }
}

#[test]
fn static_ffdh_peer_errors_need_no_ephemeral_entry() {
    let group = &v::dh_groups()[0];
    let fields = v::rfc5114(1);
    let agree = KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh);
    for q in [group.q.as_deref(), None] {
        let calls = Arc::default();
        let key = BranchKey {
            kind: KeyType::Ffdh,
            bits: der::bit_length(&group.p),
            enabled: Some(agree),
            input: Vec::new(),
            output: Vec::new(),
            calls: Arc::clone(&calls),
        };
        let provider = CryptoProvider::builder()
            .with(Entry::PrivateKeyLoader(Arc::new(BranchLoader(key))))
            .build()
            .unwrap();
        assert!(helpers::ffdh_key_agreement(&provider).is_err());
        let mut c = Checks::default();
        loaded(
            &mut c,
            &provider,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters: FfdhParameters::new(&group.p, &group.g, q),
                private_value: &fields["xA"],
            },
            "rfc/rfc5114.txt/A.1/static peer controls",
            der::bit_length(&group.p),
            false,
            false,
        )
        .unwrap();
        c.finish();
        let peers: Vec<_> = calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(call, _)| *call == agree)
            .map(|(_, peer)| peer.clone())
            .collect();
        assert!(peers.iter().any(Vec::is_empty));
        assert!(peers.iter().any(|peer| peer == &[0]));
        assert!(peers.iter().any(|peer| peer == &[1]));
        assert!(peers.contains(&group.p));
        assert!(peers.contains(&modulus_minus_one(&group.p)));
        assert!(peers.iter().any(|peer| peer.len() > group.p.len() + 1));
    }
}

/// Ciphertexts with their plaintexts, shared by mock encryptors and keys as if they used one RSA key pair.
type Table = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;
type DecryptCalls = Arc<Mutex<Vec<(AsymmetricEncryptionAlgorithm, Vec<u8>)>>>;

/// Encrypts to a ciphertext of `tag` bytes and records the plaintext in the table.
struct TableEncryptor {
    algorithm: AsymmetricEncryptionAlgorithm,
    tag: u8,
    table: Table,
}
impl AsymmetricEncryptor for TableEncryptor {
    fn algorithm(&self) -> AsymmetricEncryptionAlgorithm {
        self.algorithm
    }
    fn fips(&self) -> bool {
        false
    }
    fn encrypt(&self, _: PublicKey<'_>, message: &[u8]) -> Result<OutputBytes, Error> {
        let ciphertext = vec![self.tag; 256];
        self.table.lock().unwrap().push((ciphertext.clone(), message.to_vec()));
        Ok(OutputBytes::new(Zeroizing::new(ciphertext)))
    }
}

/// An RSA key that decrypts through the table.
#[derive(Clone)]
struct TableKey {
    decrypts: Vec<AsymmetricEncryptionAlgorithm>,
    /// Returned by every advertised decryption instead of the table's plaintext.
    outcome: Option<Result<Vec<u8>, Error>>,
    /// Returned by unadvertised decryptions instead of `Unsupported`.
    unadvertised: Option<Error>,
    exports: bool,
    export: Result<Vec<u8>, Error>,
    table: Table,
    calls: DecryptCalls,
}
impl TableKey {
    fn new(decrypts: &[AsymmetricEncryptionAlgorithm], table: &Table) -> Self {
        TableKey {
            decrypts: decrypts.to_vec(),
            outcome: None,
            unadvertised: None,
            exports: false,
            export: Err(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::Rsa))),
            table: Arc::clone(table),
            calls: Arc::default(),
        }
    }
    fn inputs(&self, algorithm: AsymmetricEncryptionAlgorithm) -> Vec<Vec<u8>> {
        let calls = self.calls.lock().unwrap();
        calls
            .iter()
            .filter(|(a, _)| *a == algorithm)
            .map(|(_, input)| input.clone())
            .collect()
    }
}
impl PrivateKey for TableKey {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn key_size_bits(&self) -> usize {
        2048
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        match operation {
            KeyOperation::Decrypt(a) => self.decrypts.contains(&a),
            KeyOperation::PublicKey => self.exports,
            _ => false,
        }
    }
    fn sign(&self, a: SignatureAlgorithm, _: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::Signature(a)))
    }
    fn decrypt(&self, a: AsymmetricEncryptionAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
        self.calls.lock().unwrap().push((a, input.to_vec()));
        if !self.decrypts.contains(&a) {
            return Err(self
                .unadvertised
                .unwrap_or(Error::Unsupported(Algorithm::AsymmetricEncryption(a))));
        }
        let table = self.table.lock().unwrap();
        let plaintext = match &self.outcome {
            Some(outcome) => outcome.clone()?,
            None => table
                .iter()
                .find(|(c, _)| c == input)
                .ok_or(Error::InvalidInput)?
                .1
                .clone(),
        };
        Ok(OutputBytes::new(Zeroizing::new(plaintext)))
    }
    fn agree(&self, a: KeyAgreementAlgorithm, _: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::KeyAgreement(a)))
    }
    fn public_key(&self) -> Result<OutputBytes, Error> {
        self.export.clone().map(|key| OutputBytes::new(Zeroizing::new(key)))
    }
}

/// A must-support key of the first RSA decryption file, with the algorithm and a valid published ciphertext and plaintext.
fn published_decryption() -> (Vec<u8>, AsymmetricEncryptionAlgorithm, Vec<u8>, Vec<u8>) {
    let (file, algorithm) = RSA_DECRYPT_FILES[0];
    let corpus = v::wycheproof(file);
    let group = corpus
        .test_groups
        .iter()
        .find(|g| der::rsa_must(&v::field(g, "privateKeyPkcs8")))
        .unwrap();
    let t = v::tests(group)
        .iter()
        .find(|t| v::string(t, "result") == "valid" && !v::field(t, "msg").is_empty())
        .unwrap();
    (
        v::field(group, "privateKeyPkcs8"),
        algorithm,
        v::field(t, "ct"),
        v::field(t, "msg"),
    )
}

/// Runs the derived-key decryption checks with the published ciphertext, a reference encryptor and the provider's own encryptor as selected.
fn derived_decryption(base: &TableKey, derived: &TableKey, sources: [bool; 3]) -> Checks {
    let [published, reference, own] = sources;
    let (encoded, algorithm, ciphertext, plaintext) = published_decryption();
    derived
        .table
        .lock()
        .unwrap()
        .push((ciphertext.clone(), plaintext.clone()));
    let encryptor = |tag, available| {
        let mut builder = CryptoProvider::builder();
        if available {
            builder = builder.with(Entry::AsymmetricEncryptor(Arc::new(TableEncryptor {
                algorithm,
                tag,
                table: Arc::clone(&derived.table),
            })));
        }
        builder.build().unwrap()
    };
    let mut options = Options::default();
    options.reference_provider = Some(Box::leak(Box::new(encryptor(1, reference))));
    let mut c = Checks::default();
    inconsistent_decryption(
        &mut c,
        &encryptor(2, own),
        options,
        (base, derived),
        "derived",
        &der::rsa_public(&encoded),
        published.then_some((algorithm, ciphertext.as_slice(), plaintext.as_slice())),
    );
    c
}

#[rstest]
fn derived_decryption_uses_the_first_available_source(
    #[values(false, true)] published: bool,
    #[values(false, true)] reference: bool,
    #[values(false, true)] own: bool,
) {
    let (_, algorithm, ciphertext, _) = published_decryption();
    let table = Table::default();
    let derived = TableKey::new(&[algorithm], &table);
    let c = derived_decryption(
        &TableKey::new(&ENCRYPTIONS, &table),
        &derived,
        [published, reference, own],
    );
    let expected = [
        (published, CiphertextSource::Published, ciphertext),
        (reference, CiphertextSource::Reference, vec![1; 256]),
        (own, CiphertextSource::Own, vec![2; 256]),
    ]
    .into_iter()
    .find(|(available, _, _)| *available);
    let Some((_, source, input)) = expected else {
        assert!(c.failures.iter().any(|f| f.contains("no source produced a ciphertext")));
        assert!(derived.inputs(algorithm).is_empty());
        return;
    };
    assert!(c.failures.is_empty(), "{:?}", c.failures);
    assert_eq!(derived.inputs(algorithm), [input]);
    let label = format!("inconsistent RSA decryption ciphertext from {source:?}");
    assert_eq!(c.coverage.into_iter().collect::<Vec<_>>(), [(label, 1)]);
}

#[rstest]
#[case::plaintext(None, None, true)]
#[case::invalid_key(None, Some(Err(Error::InvalidKey)), true)]
#[case::verification_failed(None, Some(Err(Error::VerificationFailed)), false)]
#[case::invalid_input(None, Some(Err(Error::InvalidInput)), false)]
#[case::wrong_plaintext(None, Some(Ok(b"wrong".to_vec())), false)]
#[case::wrong_positive_control(Some(Ok(b"wrong".to_vec())), Some(Err(Error::InvalidKey)), false)]
fn derived_decryption_outcomes(
    #[case] base: Option<Result<Vec<u8>, Error>>,
    #[case] derived: Option<Result<Vec<u8>, Error>>,
    #[case] passes: bool,
) {
    let (_, algorithm, _, _) = published_decryption();
    let table = Table::default();
    let keys = [base, derived].map(|outcome| TableKey {
        outcome,
        ..TableKey::new(&[algorithm], &table)
    });
    let c = derived_decryption(&keys[0], &keys[1], [true, false, false]);
    assert_eq!(c.failures.is_empty(), passes, "{:?}", c.failures);
}

#[rstest]
#[case::unsupported(None, true)]
#[case::invalid_key(Some(Error::InvalidKey), false)]
fn unadvertised_derived_decryption_is_unsupported(#[case] unadvertised: Option<Error>, #[case] passes: bool) {
    let table = Table::default();
    let derived = TableKey {
        unadvertised,
        ..TableKey::new(&[], &table)
    };
    let c = derived_decryption(&TableKey::new(&ENCRYPTIONS, &table), &derived, [true, true, true]);
    assert_eq!(c.failures.is_empty(), passes, "{:?}", c.failures);
    for algorithm in ENCRYPTIONS {
        assert_eq!(derived.inputs(algorithm), [vec![0; 256]]);
    }
}

#[rstest]
#[case::base_key(true, |public: &[u8]| Ok(public.to_vec()), true)]
#[case::invalid_key(true, |_: &[u8]| Err(Error::InvalidKey), true)]
#[case::other_key(true, |public: &[u8]| Ok([public, &[0]].concat()), false)]
#[case::verification_failed(true, |_: &[u8]| Err(Error::VerificationFailed), false)]
#[case::unsupported(false, |_: &[u8]| Err(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::Rsa))), true)]
#[case::unadvertised_export(false, |public: &[u8]| Ok(public.to_vec()), false)]
fn derived_export_outcomes(
    #[case] exports: bool,
    #[case] export: fn(&[u8]) -> Result<Vec<u8>, Error>,
    #[case] passes: bool,
) {
    let (encoded, ..) = published_decryption();
    let public = der::rsa_public(&encoded);
    let mut derived = TableKey::new(&[], &Table::default());
    derived.exports = exports;
    derived.export = export(&public);
    let mut c = Checks::default();
    derived_export(&mut c, "derived", &derived, &public);
    assert_eq!(c.failures.is_empty(), passes, "{:?}", c.failures);
}

/// Loads every RSA key as a [`TableKey`].
struct TableLoader(TableKey);
impl PrivateKeyLoader for TableLoader {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, _: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        Ok(Box::new(self.0.clone()))
    }
}

#[test]
fn derived_keys_without_signing_get_export_and_decryption_checks() {
    let table = Table::default();
    // Every export and decryption returns an unaccepted error, so each check leaves a failure naming its file.
    let key = TableKey {
        outcome: Some(Err(Error::VerificationFailed)),
        exports: true,
        export: Err(Error::VerificationFailed),
        ..TableKey::new(&ENCRYPTIONS, &table)
    };
    let mut builder = CryptoProvider::builder().with(Entry::PrivateKeyLoader(Arc::new(TableLoader(key))));
    for (tag, algorithm) in (1..).zip(ENCRYPTIONS) {
        builder = builder.with(Entry::AsymmetricEncryptor(Arc::new(TableEncryptor {
            algorithm,
            tag,
            table: Arc::clone(&table),
        })));
    }
    let mut c = Checks::default();
    inconsistent_rsa(&mut c, &builder.build().unwrap(), Options::default());
    for file in RSA_SIGN_FILES
        .into_iter()
        .chain(RSA_DECRYPT_FILES.map(|(file, _)| file))
    {
        for check in ["/public_key: ", " ciphertext: "] {
            assert!(
                c.failures.iter().any(|f| f.starts_with(file) && f.contains(check)),
                "{file}{check}{:?}",
                c.failures
            );
        }
    }
}
#[test]
fn changed_ffc_exponents_are_in_range() {
    let cases = v::response(FFC_FILE)
        .into_iter()
        .filter(|r| r.text("Result").contains("private key changed"))
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 4);
    for r in cases {
        let x = r.bytes("XstatIUT");
        let q = r.bytes("Q");
        let x = der::unsigned(&x);
        let q = der::unsigned(&q);
        assert!(!x.is_empty());
        assert!(x.len() < q.len() || x.len() == q.len() && x < q, "{}", r.id(FFC_FILE));
    }
}

type VerifyCalls = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;
struct UndecodableKeys(VerifyCalls, Result<(), Error>);
impl SignatureVerifier for UndecodableKeys {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn verify(&self, public_key: PublicKey<'_>, _: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.0.lock().unwrap().push((public_key.0.to_vec(), signature.to_vec()));
        self.1
    }
}

#[test]
fn ed25519_undecodable_keys_follow_rfc8032_encoding() {
    let (identity, [(_, non_canonical), (_, negative_zero)]) = ed25519_undecodable_keys();
    // p = 2^255 - 19 is ed ff .. ff 7f little-endian, so p + 1 only changes the low byte.
    let mut p_plus_one = [0xff; 32];
    p_plus_one[0] = 0xee;
    p_plus_one[31] = 0x7f;
    assert_eq!(non_canonical, p_plus_one);
    let mut y_one = [0; 32];
    y_one[0] = 1;
    assert_eq!(identity, y_one);
    y_one[31] = 0x80;
    assert_eq!(negative_zero, y_one);
}

#[rstest]
#[case::invalid_key(Err(Error::InvalidKey), false, false)]
#[case::accepted(Ok(()), false, true)]
#[case::opaque_failure_without_option(Err(Error::VerificationFailed), false, true)]
#[case::opaque_failure_with_option(Err(Error::VerificationFailed), true, false)]
fn ed25519_undecodable_public_keys_reach_the_verifier(
    #[case] result: Result<(), Error>,
    #[case] opaque: bool,
    #[case] reported: bool,
) {
    let (identity, keys) = ed25519_undecodable_keys();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let provider = CryptoProvider::builder()
        .with(Entry::SignatureVerifier(Arc::new(UndecodableKeys(
            Arc::clone(&calls),
            result,
        ))))
        .build()
        .unwrap();
    let mut options = Options::default();
    options.opaque_public_key_errors = opaque;
    let report = without_failure_persistence(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| signature::run(&provider, options)))
    })
    .expect_err("a verifier with a fixed result fails the published vectors");
    let report = report.downcast_ref::<String>().unwrap();
    for (name, key) in keys {
        let id = format!("rfc/rfc8032.txt/5.1.3/A {name}:");
        assert_eq!(report.contains(&id), reported, "{id} in {report}");
        let calls = calls.lock().unwrap();
        let call = calls
            .iter()
            .find(|(public, _)| public[..] == key[..])
            .expect("undecodable key verified");
        assert_eq!(call.1, [identity, [0; 32]].concat());
    }
}

/// RSA signature algorithms without generation vectors for the published keys.
pub(crate) const PARTIAL: [SignatureAlgorithm; 3] = [
    SignatureAlgorithm::RsaPkcs1v15Md5,
    SignatureAlgorithm::RsaPkcs1v15Sha3_384,
    SignatureAlgorithm::RsaPkcs1v15Sha3_512,
];

struct SigningLoader {
    signature: Vec<u8>,
}
struct SigningKey {
    signature: Vec<u8>,
}
struct FixedVerifier {
    algorithm: SignatureAlgorithm,
    signature: Vec<u8>,
    calls: Arc<Mutex<Vec<SignatureAlgorithm>>>,
}
impl PrivateKeyLoader for SigningLoader {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, _: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        Ok(Box::new(SigningKey {
            signature: self.signature.clone(),
        }))
    }
}
impl PrivateKey for SigningKey {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn key_size_bits(&self) -> usize {
        2048
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        matches!(operation, KeyOperation::Sign(a) if PARTIAL.contains(&a))
    }
    fn sign(&self, algorithm: SignatureAlgorithm, _: &[u8]) -> Result<OutputBytes, Error> {
        if !self.supports(KeyOperation::Sign(algorithm)) {
            return Err(Error::Unsupported(Algorithm::Signature(algorithm)));
        }
        Ok(OutputBytes::new(Zeroizing::new(self.signature.clone())))
    }
}
impl SignatureVerifier for FixedVerifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    fn fips(&self) -> bool {
        false
    }
    fn verify(&self, _: PublicKey<'_>, _: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.calls.lock().unwrap().push(self.algorithm);
        if signature == self.signature {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// A provider whose RSA keys sign the `PARTIAL` algorithms with `signature`, with verifiers that accept only it when `verifiers` is set.
pub(crate) fn signing_provider(
    signature: &[u8],
    verifiers: bool,
    calls: &Arc<Mutex<Vec<SignatureAlgorithm>>>,
) -> CryptoProvider {
    let mut builder = CryptoProvider::builder().with(Entry::PrivateKeyLoader(Arc::new(SigningLoader {
        signature: signature.to_vec(),
    })));
    for algorithm in PARTIAL.into_iter().filter(|_| verifiers) {
        builder = builder.with(Entry::SignatureVerifier(Arc::new(FixedVerifier {
            algorithm,
            signature: signature.to_vec(),
            calls: Arc::clone(calls),
        })));
    }
    builder.build().unwrap()
}

#[test]
fn inconsistent_signatures_cover_algorithms_without_generation_vectors() {
    let source = v::wycheproof(RSA_SIGN_FILES[0]);
    let group = &source.test_groups[0];
    let signature = v::field(&v::tests(group)[0], "sig");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let base = SigningKey {
        signature: signature.clone(),
    };
    let derived = SigningKey {
        signature: signature.clone(),
    };
    for verifiers in [true, false] {
        calls.lock().unwrap().clear();
        let provider = signing_provider(&signature, verifiers, &calls);
        let mut c = Checks::default();
        inconsistent_signatures(
            &mut c,
            &provider,
            &base,
            &derived,
            "inconsistent RSA routing",
            (RSA_SIGN_FILES[0], group),
        );
        c.finish();
        let calls = calls.lock().unwrap();
        for algorithm in PARTIAL {
            let count = calls.iter().filter(|&&actual| actual == algorithm).count();
            assert_eq!(count, if verifiers { 2 } else { 0 }, "{algorithm:?}");
        }
    }
}
