use picky_crypto::{
    Algorithm, AsymmetricEncryptionAlgorithm, AsymmetricEncryptor, Entry, Error, KeyGenerationAlgorithm, KeyGenerator,
    KeyOperation, KeyType, OutputBytes, PrivateKey, PrivateKeyLoader, PrivateKeyMaterial, ProviderBuilder, PublicKey,
    SignatureAlgorithm, SignatureVerifier, Zeroizing,
};
use rsa::{
    BoxedUint, RsaPrivateKey, RsaPublicKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{EncodePrivateKey, PrivateKeyInfoRef, Version, der::Decode},
    signature::Verifier,
    traits::{PaddingScheme, PublicKeyParts, SignatureScheme},
};
use std::sync::Arc;

struct Verify(SignatureAlgorithm);
struct Encrypt(AsymmetricEncryptionAlgorithm);
struct Loader;
struct Generator(KeyGenerationAlgorithm);
struct Key(RsaPrivateKey);

fn precision(bytes: &[u8]) -> Result<u32, Error> {
    u32::try_from(bytes.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .ok_or(Error::InvalidKey)
}

fn uint(bytes: &[u8], bits: u32) -> Result<BoxedUint, Error> {
    BoxedUint::from_be_slice(bytes, bits).map_err(|_| Error::InvalidKey)
}

fn load_public_key(der: &[u8], algorithm: Algorithm) -> Result<RsaPublicKey, Error> {
    let parsed = rsa::pkcs1::RsaPublicKey::from_der(der).map_err(|_| Error::InvalidKey)?;
    let n = uint(parsed.modulus.as_bytes(), precision(parsed.modulus.as_bytes())?)?;
    let e = uint(
        parsed.public_exponent.as_bytes(),
        precision(parsed.public_exponent.as_bytes())?,
    )?;
    // Classification follows the library's check order: modulus size, structure, then exponent bounds
    // (rsa 0.10.0-rc.18, src\key.rs:228–234,714–745).
    RsaPublicKey::new(n, e).map_err(|error| match error {
        rsa::Error::ModulusTooLarge | rsa::Error::PublicExponentTooLarge => Error::Unsupported(algorithm),
        _ => Error::InvalidKey,
    })
}

macro_rules! with_digest {
    ($algorithm:expr, $call:ident $(, $argument:expr)*) => {
        match $algorithm {
            SignatureAlgorithm::RsaPkcs1v15Md5 => $call::<md5::Md5>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha1 => $call::<sha1::Sha1>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha224 => $call::<sha2::Sha224>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha256 => $call::<sha2::Sha256>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha384 => $call::<sha2::Sha384>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha512 => $call::<sha2::Sha512>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha3_384 => $call::<sha3::Sha3_384>($($argument),*),
            SignatureAlgorithm::RsaPkcs1v15Sha3_512 => $call::<sha3::Sha3_512>($($argument),*),
            _ => Err(Error::Unsupported(Algorithm::Signature($algorithm))),
        }
    };
}
fn verify<D: sha2::Digest + rsa::pkcs8::AssociatedOid>(
    key: RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if signature.len() != key.size() {
        return Err(Error::VerificationFailed);
    }
    let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| Error::VerificationFailed)?;
    rsa::pkcs1v15::VerifyingKey::<D>::new(key)
        .verify(message, &signature)
        .map_err(|_| Error::VerificationFailed)
}
impl SignatureVerifier for Verify {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn verify(&self, public_key: PublicKey<'_>, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key = load_public_key(public_key.0, Algorithm::Signature(self.0))?;
        with_digest!(self.0, verify, key, message, signature)
    }
}

fn encryption_supported(algorithm: AsymmetricEncryptionAlgorithm) -> bool {
    matches!(
        algorithm,
        AsymmetricEncryptionAlgorithm::RsaPkcs1v15
            | AsymmetricEncryptionAlgorithm::RsaOaepSha1
            | AsymmetricEncryptionAlgorithm::RsaOaepSha256
    )
}
fn error(error: rsa::Error) -> Error {
    // Decryption re-encrypts its result and reports a mismatch as Internal, mapped to InvalidKey
    // (rsa 0.10.0-rc.18, src\algorithms\rsa.rs:156–172; src\pkcs1v15.rs:180; src\oaep.rs:279).
    match error {
        rsa::Error::Rng => Error::ProviderFailure,
        rsa::Error::MessageTooLong => Error::InvalidInput,
        rsa::Error::Decryption | rsa::Error::Verification => Error::VerificationFailed,
        _ => Error::InvalidKey,
    }
}
fn encrypt<P: PaddingScheme>(key: &RsaPublicKey, plaintext: &[u8], padding: P) -> Result<OutputBytes, Error> {
    // Native ciphertext output is modulus-sized (rsa 0.10.0-rc.18, src\pkcs1v15.rs:159; src\oaep.rs:218).
    padding
        .encrypt(&mut getrandom::SysRng, key, plaintext)
        .map(|output| OutputBytes::new(Zeroizing::new(output)))
        .map_err(error)
}
impl AsymmetricEncryptor for Encrypt {
    fn algorithm(&self) -> AsymmetricEncryptionAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn encrypt(&self, public_key: PublicKey<'_>, plaintext: &[u8]) -> Result<OutputBytes, Error> {
        let key = load_public_key(public_key.0, Algorithm::AsymmetricEncryption(self.0))?;
        match self.0 {
            AsymmetricEncryptionAlgorithm::RsaPkcs1v15 => encrypt(&key, plaintext, rsa::Pkcs1v15Encrypt),
            AsymmetricEncryptionAlgorithm::RsaOaepSha1 => encrypt(&key, plaintext, rsa::Oaep::<sha1::Sha1>::new()),
            AsymmetricEncryptionAlgorithm::RsaOaepSha256 => encrypt(&key, plaintext, rsa::Oaep::<sha2::Sha256>::new()),
            _ => Err(Error::Unsupported(Algorithm::AsymmetricEncryption(self.0))),
        }
    }
}
impl PrivateKeyLoader for Loader {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        let PrivateKeyMaterial::Pkcs8(der) = material else {
            return Err(Error::InvalidKey);
        };
        // The library's PKCS#1 decoder multiplies the public-exponent length by eight in u32
        // (rsa 0.10.0-rc.18, src\encoding.rs:55–57).
        if der.len() as u128 > u128::from(u32::MAX / 8) {
            return Err(Error::InvalidKey);
        }
        let info = PrivateKeyInfoRef::from_der(der).map_err(|_| Error::InvalidKey)?;
        if info.version() != Version::V1 {
            return Err(Error::InvalidKey);
        }
        info.algorithm
            .assert_algorithm_oid(rsa::pkcs1::ALGORITHM_OID)
            .map_err(|_| Error::InvalidKey)?;
        if info.algorithm.parameters_any().map_err(|_| Error::InvalidKey)? != rsa::pkcs8::der::asn1::Null.into() {
            return Err(Error::InvalidKey);
        }
        let parsed = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key.as_bytes()).map_err(|_| Error::InvalidKey)?;
        // The library's public-key limits apply before decoding: it loads private keys of any modulus size
        // (rsa 0.10.0-rc.18, src\key.rs:706–710) and reports an oversized exponent only as a malformed key
        // (src\encoding.rs:66; src\key.rs:723–729). `as_bytes` strips the sign octet, so 8192 bits is 1024 bytes
        // (der 0.8.2, src\asn1\integer\uint.rs:351–365,406–416).
        let exponent = parsed.public_exponent.as_bytes();
        if parsed.modulus.as_bytes().len() > RsaPublicKey::MAX_SIZE / 8
            || uint(exponent, precision(exponent)?)? > BoxedUint::from(RsaPublicKey::MAX_PUB_EXPONENT)
        {
            return Err(Error::Unsupported(Algorithm::PrivateKeyLoading(KeyType::Rsa)));
        }
        let key = RsaPrivateKey::try_from(info).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(Key(key)))
    }
}
impl KeyGenerator for Generator {
    fn algorithm(&self) -> KeyGenerationAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn generate(&self) -> Result<OutputBytes, Error> {
        use rsa::rand_core::SeedableRng;
        let bits = match self.0 {
            KeyGenerationAlgorithm::Rsa2048 => 2048,
            KeyGenerationAlgorithm::Rsa3072 => 3072,
            KeyGenerationAlgorithm::Rsa4096 => 4096,
            _ => return Err(Error::Unsupported(Algorithm::KeyGeneration(self.0))),
        };
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).map_err(|_| Error::ProviderFailure)?;
        // Infallible seeded RNG that wipes its buffer and state on drop (chacha20 0.10.2, src\rng.rs:94–98;
        // src\lib.rs:306–310).
        let mut rng = chacha20::ChaCha20Rng::from_seed(*seed);
        let key = RsaPrivateKey::new_with_exp(&mut rng, bits, BoxedUint::from(65537u64))
            .map_err(|_| Error::ProviderFailure)?;
        let document = key.to_pkcs8_der().map_err(|_| Error::ProviderFailure)?;
        crate::util::output(document.as_bytes())
    }
}
fn signing_error(error: rsa::Error, algorithm: SignatureAlgorithm) -> Error {
    // An undersized modulus is MessageTooLong (rsa 0.10.0-rc.18, src\algorithms\pkcs1v15.rs:120–125).
    // Signing checks its result like decryption and reports a mismatch as Internal, mapped to InvalidKey
    // (src\algorithms\rsa.rs:156–172; src\pkcs1v15.rs:209).
    match error {
        rsa::Error::MessageTooLong => Error::Unsupported(Algorithm::Signature(algorithm)),
        rsa::Error::Rng => Error::ProviderFailure,
        _ => Error::InvalidKey,
    }
}

fn sign<D: sha2::Digest + rsa::pkcs8::AssociatedOid>(
    key: &RsaPrivateKey,
    message: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<OutputBytes, Error> {
    let digest = Zeroizing::new(D::digest(message));
    // The scheme blinds with a fallible generator, unlike `sign_with_rng`, and pads to size(), not whole limbs
    // (rsa 0.10.0-rc.18, src\key.rs:662; src\traits\padding.rs:35–40; src\pkcs1v15.rs:200–209).
    rsa::Pkcs1v15Sign::new::<D>()
        .sign(Some(&mut getrandom::SysRng), key, &digest)
        .map(|signature| OutputBytes::new(Zeroizing::new(signature)))
        .map_err(|error| signing_error(error, algorithm))
}
fn decrypt<P: PaddingScheme>(key: &RsaPrivateKey, ciphertext: &[u8], padding: P) -> Result<OutputBytes, Error> {
    padding
        .decrypt(Some(&mut getrandom::SysRng), key, ciphertext)
        .map(|output| OutputBytes::new(Zeroizing::new(output)))
        .map_err(error)
}
impl PrivateKey for Key {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn key_size_bits(&self) -> usize {
        self.0.n().bits_vartime() as usize
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        match operation {
            KeyOperation::Sign(algorithm) => matches!(
                algorithm,
                SignatureAlgorithm::RsaPkcs1v15Md5
                    | SignatureAlgorithm::RsaPkcs1v15Sha1
                    | SignatureAlgorithm::RsaPkcs1v15Sha224
                    | SignatureAlgorithm::RsaPkcs1v15Sha256
                    | SignatureAlgorithm::RsaPkcs1v15Sha384
                    | SignatureAlgorithm::RsaPkcs1v15Sha512
                    | SignatureAlgorithm::RsaPkcs1v15Sha3_384
                    | SignatureAlgorithm::RsaPkcs1v15Sha3_512
            ),
            KeyOperation::Decrypt(algorithm) => encryption_supported(algorithm),
            KeyOperation::PublicKey => true,
            _ => false,
        }
    }
    fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<OutputBytes, Error> {
        with_digest!(algorithm, sign, &self.0, message, algorithm)
    }
    fn decrypt(&self, algorithm: AsymmetricEncryptionAlgorithm, ciphertext: &[u8]) -> Result<OutputBytes, Error> {
        if !encryption_supported(algorithm) {
            return Err(Error::Unsupported(Algorithm::AsymmetricEncryption(algorithm)));
        }
        if ciphertext.len() != self.0.size() {
            return Err(Error::InvalidInput);
        }
        match algorithm {
            AsymmetricEncryptionAlgorithm::RsaPkcs1v15 => decrypt(&self.0, ciphertext, rsa::Pkcs1v15Encrypt),
            AsymmetricEncryptionAlgorithm::RsaOaepSha1 => decrypt(&self.0, ciphertext, rsa::Oaep::<sha1::Sha1>::new()),
            AsymmetricEncryptionAlgorithm::RsaOaepSha256 => {
                decrypt(&self.0, ciphertext, rsa::Oaep::<sha2::Sha256>::new())
            }
            _ => Err(Error::Unsupported(Algorithm::AsymmetricEncryption(algorithm))),
        }
    }
    fn public_key(&self) -> Result<OutputBytes, Error> {
        let public = self.0.as_public_key().to_pkcs1_der().map_err(|_| Error::InvalidKey)?;
        crate::util::output(public.as_bytes())
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    let builder = [
        SignatureAlgorithm::RsaPkcs1v15Md5,
        SignatureAlgorithm::RsaPkcs1v15Sha1,
        SignatureAlgorithm::RsaPkcs1v15Sha224,
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        SignatureAlgorithm::RsaPkcs1v15Sha384,
        SignatureAlgorithm::RsaPkcs1v15Sha512,
        SignatureAlgorithm::RsaPkcs1v15Sha3_384,
        SignatureAlgorithm::RsaPkcs1v15Sha3_512,
    ]
    .into_iter()
    .fold(builder, |builder, algorithm| {
        builder.with(Entry::SignatureVerifier(Arc::new(Verify(algorithm))))
    });
    let builder = [
        AsymmetricEncryptionAlgorithm::RsaPkcs1v15,
        AsymmetricEncryptionAlgorithm::RsaOaepSha1,
        AsymmetricEncryptionAlgorithm::RsaOaepSha256,
    ]
    .into_iter()
    .fold(builder, |builder, algorithm| {
        builder.with(Entry::AsymmetricEncryptor(Arc::new(Encrypt(algorithm))))
    });
    let builder = builder.with(Entry::PrivateKeyLoader(Arc::new(Loader)));
    [
        KeyGenerationAlgorithm::Rsa2048,
        KeyGenerationAlgorithm::Rsa3072,
        KeyGenerationAlgorithm::Rsa4096,
    ]
    .into_iter()
    .fold(builder, |builder, algorithm| {
        builder.with(Entry::KeyGenerator(Arc::new(Generator(algorithm))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::der::{Encode, asn1::UintRef};

    #[test]
    fn rsa_limits_preserve_operation_identity() {
        let modulus = [1u8; 1025];
        let too_large_exponent = [2u8, 0, 0, 0, 1];
        let mut even_modulus = [1u8; 256];
        even_modulus[255] = 2;
        let signature = SignatureAlgorithm::RsaPkcs1v15Sha256;
        let encryption = AsymmetricEncryptionAlgorithm::RsaOaepSha256;
        for (n, e, unsupported) in [
            (&modulus[..], &[1, 0, 1][..], true),
            (&modulus[..256], &too_large_exponent[..], true),
            (&even_modulus[..], &[1, 0, 1][..], false),
        ] {
            let der = rsa::pkcs1::RsaPublicKey {
                modulus: UintRef::new(n).unwrap(),
                public_exponent: UintRef::new(e).unwrap(),
            }
            .to_der()
            .unwrap();
            let expected = |algorithm| {
                if unsupported {
                    Error::Unsupported(algorithm)
                } else {
                    Error::InvalidKey
                }
            };
            assert_eq!(
                Verify(signature).verify(PublicKey(&der), b"", b""),
                Err(expected(Algorithm::Signature(signature)))
            );
            assert_eq!(
                Encrypt(encryption).encrypt(PublicKey(&der), b"").err(),
                Some(expected(Algorithm::AsymmetricEncryption(encryption)))
            );
        }
    }

    #[test]
    fn private_modulus_above_public_limit_is_unsupported() {
        use rsa::pkcs8::der::asn1::OctetStringRef;
        let one = UintRef::new(&[1]).unwrap();
        let modulus = [0xffu8; 1025];
        for (len, expected) in [
            (1025, Error::Unsupported(Algorithm::PrivateKeyLoading(KeyType::Rsa))),
            (1024, Error::InvalidKey),
        ] {
            let pkcs1 = rsa::pkcs1::RsaPrivateKey {
                modulus: UintRef::new(&modulus[..len]).unwrap(),
                public_exponent: one,
                private_exponent: one,
                prime1: one,
                prime2: one,
                exponent1: one,
                exponent2: one,
                coefficient: one,
                other_prime_infos: None,
            }
            .to_der()
            .unwrap();
            let info = PrivateKeyInfoRef::new(rsa::pkcs1::ALGORITHM_ID, OctetStringRef::new(&pkcs1).unwrap());
            let der = info.to_der().unwrap();
            assert_eq!(Loader.load(PrivateKeyMaterial::Pkcs8(&der)).err(), Some(expected));
        }
    }

    // Signatures must be padded to the modulus width, not to whole limbs (Signature::to_bytes()).
    #[test]
    fn rsa_outputs_use_modulus_width() {
        use rsa::rand_core::SeedableRng;
        let mut rng = chacha20::ChaCha20Rng::from_seed([7u8; 32]);
        let document = RsaPrivateKey::new(&mut rng, 1040).unwrap().to_pkcs8_der().unwrap();
        let key = Loader.load(PrivateKeyMaterial::Pkcs8(document.as_bytes())).unwrap();
        let algorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
        let signature = key.sign(algorithm, b"message").unwrap();
        assert_eq!(signature.len(), 130);
        let public = key.public_key().unwrap();
        Verify(algorithm)
            .verify(PublicKey(&public), b"message", &signature)
            .unwrap();
    }

    #[test]
    fn small_modulus_and_large_exponent_are_unsupported() {
        use rsa::{rand_core::SeedableRng, traits::PrivateKeyParts};
        let seed = Zeroizing::new([42u8; 32]);
        let mut rng = chacha20::ChaCha20Rng::from_seed(*seed);
        let key = RsaPrivateKey::new_unchecked(&mut rng, 128).unwrap();
        let swapped = RsaPrivateKey::from_components_with_large_exponent(
            key.n().as_ref().clone(),
            key.d().clone(),
            key.e().clone(),
            key.primes().to_vec(),
        )
        .unwrap();
        let document = swapped.to_pkcs8_der().unwrap();
        assert!(matches!(
            Loader.load(PrivateKeyMaterial::Pkcs8(document.as_bytes())),
            Err(Error::Unsupported(Algorithm::PrivateKeyLoading(KeyType::Rsa)))
        ));
        let algorithm = SignatureAlgorithm::RsaPkcs1v15Sha512;
        assert!(matches!(
            Key(key).sign(algorithm, b""),
            Err(Error::Unsupported(Algorithm::Signature(a))) if a == algorithm
        ));
    }
}
