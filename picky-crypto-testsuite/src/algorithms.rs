use picky_crypto::*;

pub const HASHES: [HashAlgorithm; 9] = [
    HashAlgorithm::Md4,
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha224,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_384,
    HashAlgorithm::Sha3_512,
];
pub const MACS: [MacAlgorithm; 5] = [
    MacAlgorithm::HmacSha1,
    MacAlgorithm::HmacSha224,
    MacAlgorithm::HmacSha256,
    MacAlgorithm::HmacSha384,
    MacAlgorithm::HmacSha512,
];
pub const PASSWORD_KDFS: [PasswordKdfAlgorithm; 5] = [
    PasswordKdfAlgorithm::Pbkdf2HmacSha1,
    PasswordKdfAlgorithm::Pbkdf2HmacSha224,
    PasswordKdfAlgorithm::Pbkdf2HmacSha256,
    PasswordKdfAlgorithm::Pbkdf2HmacSha384,
    PasswordKdfAlgorithm::Pbkdf2HmacSha512,
];
pub const KDFS: [KdfAlgorithm; 8] = [
    KdfAlgorithm::OneStepSha1,
    KdfAlgorithm::OneStepSha256,
    KdfAlgorithm::OneStepSha384,
    KdfAlgorithm::OneStepSha512,
    KdfAlgorithm::CounterHmacSha1,
    KdfAlgorithm::CounterHmacSha256,
    KdfAlgorithm::CounterHmacSha384,
    KdfAlgorithm::CounterHmacSha512,
];
pub const CIPHERS: [CipherAlgorithm; 5] = [
    CipherAlgorithm::Aes128Cbc,
    CipherAlgorithm::Aes192Cbc,
    CipherAlgorithm::Aes256Cbc,
    CipherAlgorithm::TdesEde3Cbc,
    CipherAlgorithm::Rc2Cbc,
];
pub const AEADS: [AeadAlgorithm; 3] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes192Gcm,
    AeadAlgorithm::Aes256Gcm,
];
pub const WRAPS: [KeyWrapAlgorithm; 3] = [
    KeyWrapAlgorithm::Aes128Kw,
    KeyWrapAlgorithm::Aes192Kw,
    KeyWrapAlgorithm::Aes256Kw,
];
pub const SIGNATURES: [SignatureAlgorithm; 12] = [
    SignatureAlgorithm::RsaPkcs1v15Md5,
    SignatureAlgorithm::RsaPkcs1v15Sha1,
    SignatureAlgorithm::RsaPkcs1v15Sha224,
    SignatureAlgorithm::RsaPkcs1v15Sha256,
    SignatureAlgorithm::RsaPkcs1v15Sha384,
    SignatureAlgorithm::RsaPkcs1v15Sha512,
    SignatureAlgorithm::RsaPkcs1v15Sha3_384,
    SignatureAlgorithm::RsaPkcs1v15Sha3_512,
    SignatureAlgorithm::EcdsaP256Sha256,
    SignatureAlgorithm::EcdsaP384Sha384,
    SignatureAlgorithm::EcdsaP521Sha512,
    SignatureAlgorithm::Ed25519,
];
pub const ENCRYPTIONS: [AsymmetricEncryptionAlgorithm; 3] = [
    AsymmetricEncryptionAlgorithm::RsaPkcs1v15,
    AsymmetricEncryptionAlgorithm::RsaOaepSha1,
    AsymmetricEncryptionAlgorithm::RsaOaepSha256,
];
pub const AGREEMENTS: [KeyAgreementAlgorithm; 5] = [
    KeyAgreementAlgorithm::EcdhP256,
    KeyAgreementAlgorithm::EcdhP384,
    KeyAgreementAlgorithm::EcdhP521,
    KeyAgreementAlgorithm::X25519,
    KeyAgreementAlgorithm::Ffdh,
];
pub const KEY_TYPES: [KeyType; 7] = [
    KeyType::Rsa,
    KeyType::EcP256,
    KeyType::EcP384,
    KeyType::EcP521,
    KeyType::Ed25519,
    KeyType::X25519,
    KeyType::Ffdh,
];
pub const GENERATIONS: [KeyGenerationAlgorithm; 7] = [
    KeyGenerationAlgorithm::Rsa2048,
    KeyGenerationAlgorithm::Rsa3072,
    KeyGenerationAlgorithm::Rsa4096,
    KeyGenerationAlgorithm::EcP256,
    KeyGenerationAlgorithm::EcP384,
    KeyGenerationAlgorithm::EcP521,
    KeyGenerationAlgorithm::Ed25519,
];
pub const SHAS: [&str; 5] = ["sha1", "sha224", "sha256", "sha384", "sha512"];
pub const CURVES: [(KeyType, KeyAgreementAlgorithm, SignatureAlgorithm, usize, &str); 3] = [
    (
        KeyType::EcP256,
        KeyAgreementAlgorithm::EcdhP256,
        SignatureAlgorithm::EcdsaP256Sha256,
        32,
        "secp256r1",
    ),
    (
        KeyType::EcP384,
        KeyAgreementAlgorithm::EcdhP384,
        SignatureAlgorithm::EcdsaP384Sha384,
        48,
        "secp384r1",
    ),
    (
        KeyType::EcP521,
        KeyAgreementAlgorithm::EcdhP521,
        SignatureAlgorithm::EcdsaP521Sha512,
        66,
        "secp521r1",
    ),
];

pub fn all() -> Vec<Algorithm> {
    let mut a = Vec::new();
    a.extend(HASHES.map(Algorithm::Hash));
    a.extend(MACS.map(Algorithm::Mac));
    a.extend(PASSWORD_KDFS.map(Algorithm::PasswordKdf));
    a.extend(KDFS.map(Algorithm::Kdf));
    a.extend(CIPHERS.map(Algorithm::Cipher));
    a.push(Algorithm::StreamCipher(StreamCipherAlgorithm::Rc4));
    a.extend(AEADS.map(Algorithm::Aead));
    a.extend(WRAPS.map(Algorithm::KeyWrap));
    a.extend(SIGNATURES.map(Algorithm::Signature));
    a.extend(ENCRYPTIONS.map(Algorithm::AsymmetricEncryption));
    a.extend(AGREEMENTS.map(Algorithm::KeyAgreement));
    a.extend(KEY_TYPES.map(Algorithm::PrivateKeyLoading));
    a.extend(GENERATIONS.map(Algorithm::KeyGeneration));
    a.push(Algorithm::Random(RandomAlgorithm::SecureRandom));
    a
}

pub fn rsa_signature(sha: &str) -> SignatureAlgorithm {
    match sha {
        "SHA-1" => SignatureAlgorithm::RsaPkcs1v15Sha1,
        "SHA-224" => SignatureAlgorithm::RsaPkcs1v15Sha224,
        "SHA-256" => SignatureAlgorithm::RsaPkcs1v15Sha256,
        "SHA-384" => SignatureAlgorithm::RsaPkcs1v15Sha384,
        "SHA-512" => SignatureAlgorithm::RsaPkcs1v15Sha512,
        "SHA3-384" => SignatureAlgorithm::RsaPkcs1v15Sha3_384,
        "SHA3-512" => SignatureAlgorithm::RsaPkcs1v15Sha3_512,
        _ => panic!("unrecognized published hash: {sha}"),
    }
}

pub fn extended() -> bool {
    std::env::var("PICKY_CRYPTO_TESTSUITE_EXTENDED").as_deref() == Ok("1")
}
