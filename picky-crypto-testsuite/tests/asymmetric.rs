use picky_crypto::*;
use picky_crypto_testsuite::algorithms::*;
use picky_crypto_testsuite::asymmetric::*;
use picky_crypto_testsuite::harness::{Checks, Expect};
use picky_crypto_testsuite::{Options, der, vectors as v};
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
    let mut checks = Checks::default();
    ffdh_parameter_boundaries(&mut checks, &provider);
    checks.finish();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    let even = [[0x80].as_slice(), &[0; 127]].concat();
    let odd = [[0x80].as_slice(), &[0; 126], &[1]].concat();
    for (pair, (p, g)) in calls.chunks_exact(2).zip([(&even, &[2][..]), (&odd, even.as_slice())]) {
        for call in pair {
            assert_eq!(&call.p, p);
            assert_eq!(call.g, g);
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
        key_generation(&provider, Options::default())
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

struct DecryptOnlyLoader {
    base: Vec<u8>,
    derived: Vec<Vec<u8>>,
    key: BranchKey,
    derived_loads: Arc<AtomicUsize>,
}
impl PrivateKeyLoader for DecryptOnlyLoader {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        let PrivateKeyMaterial::Pkcs8(encoded) = material else {
            return Err(Error::InvalidKey);
        };
        if self.derived.iter().any(|key| key == encoded) {
            self.derived_loads.fetch_add(1, Ordering::Relaxed);
            return Err(Error::InvalidKey);
        }
        if encoded != self.base {
            return Err(Error::InvalidKey);
        }
        Ok(Box::new(self.key.clone()))
    }
}
fn decrypt_only(ciphertext: &[u8], plaintext: Vec<u8>, calls: &Calls) -> BranchKey {
    BranchKey {
        kind: KeyType::Rsa,
        bits: 2048,
        enabled: Some(KeyOperation::Decrypt(AsymmetricEncryptionAlgorithm::RsaPkcs1v15)),
        input: ciphertext.to_vec(),
        output: plaintext,
        calls: Arc::clone(calls),
    }
}
fn decrypts(calls: &Calls, ciphertext: &[u8]) -> usize {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(call, input)| {
            *call == KeyOperation::Decrypt(AsymmetricEncryptionAlgorithm::RsaPkcs1v15) && input == ciphertext
        })
        .count()
}
struct ReferenceEncryptor {
    ciphertext: Vec<u8>,
    calls: Arc<AtomicUsize>,
}
impl AsymmetricEncryptor for ReferenceEncryptor {
    fn algorithm(&self) -> AsymmetricEncryptionAlgorithm {
        AsymmetricEncryptionAlgorithm::RsaPkcs1v15
    }
    fn fips(&self) -> bool {
        false
    }
    fn encrypt(&self, _: PublicKey<'_>, _: &[u8]) -> Result<OutputBytes, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(OutputBytes::new(Zeroizing::new(self.ciphertext.clone())))
    }
}

#[test]
fn inconsistent_roundtrip_can_use_another_provider_encryptor() {
    let corpus = v::wycheproof(RSA_DECRYPT_FILES[0].0);
    let group = &corpus.test_groups[0];
    let encoded = v::field(group, "privateKeyPkcs8");
    let t = v::tests(group)
        .iter()
        .find(|t| v::string(t, "result") == "valid")
        .unwrap();
    let ciphertext = v::field(t, "ct");
    let messages = picky_crypto_testsuite::published::messages();
    let message = messages
        .iter()
        .find(|(_, m)| !m.is_empty() && m.len() <= 245)
        .unwrap()
        .1
        .clone();
    let calls = Arc::default();
    let encrypts = Arc::new(AtomicUsize::new(0));
    let base = decrypt_only(&ciphertext, message.clone(), &calls);
    let derived = decrypt_only(&ciphertext, message, &calls);
    let local = CryptoProvider::builder().build().unwrap();
    let other = CryptoProvider::builder()
        .with(Entry::AsymmetricEncryptor(Arc::new(ReferenceEncryptor {
            ciphertext: ciphertext.clone(),
            calls: Arc::clone(&encrypts),
        })))
        .build()
        .unwrap();
    let mut checks = Checks::default();
    inconsistent_roundtrip(
        &mut checks,
        (&local, Some(&other)),
        (&base, &derived),
        "published reference encryption",
        &encoded,
        AsymmetricEncryptionAlgorithm::RsaPkcs1v15,
    );
    checks.finish();
    assert_eq!(encrypts.load(Ordering::Relaxed), 1);
    assert_eq!(decrypts(&calls, &ciphertext), 2);
}

#[test]
fn inconsistent_decryption_does_not_require_signing() {
    let corpus = v::wycheproof(RSA_DECRYPT_FILES[0].0);
    let group = &corpus.test_groups[0];
    let base = v::field(group, "privateKeyPkcs8");
    let t = v::tests(group)
        .iter()
        .find(|t| v::string(t, "result") == "valid")
        .unwrap();
    let ciphertext = v::field(t, "ct");
    let calls = Arc::default();
    let derived_loads = Arc::new(AtomicUsize::new(0));
    let loader = DecryptOnlyLoader {
        derived: der::inconsistent_rsa(&base, None),
        base,
        key: decrypt_only(&ciphertext, v::field(t, "msg"), &calls),
        derived_loads: Arc::clone(&derived_loads),
    };
    let provider = CryptoProvider::builder()
        .with(Entry::PrivateKeyLoader(Arc::new(loader)))
        .build()
        .unwrap();
    let mut c = Checks::default();
    inconsistent_rsa(&mut c, &provider);
    assert!(decrypts(&calls, &ciphertext) > 0);
    assert!(derived_loads.load(Ordering::Relaxed) >= 2);
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
    let report = picky_crypto_testsuite::properties::without_failure_persistence(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| signature(&provider, options)))
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
