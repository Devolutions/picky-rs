use picky_crypto::{
    Algorithm, AsymmetricEncryptionAlgorithm, AsymmetricEncryptor, Entry, Error, KeyGenerationAlgorithm, KeyGenerator,
    KeyOperation, KeyType, OutputBytes, PrivateKey, PrivateKeyLoader, PrivateKeyMaterial, ProviderBuilder, PublicKey,
    SignatureAlgorithm, SignatureVerifier, Zeroizing,
};
use rsa::{
    BoxedUint, PrivateKey as RsaPrivateKey, PublicKey as RsaPublicKey,
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

/// Bit length of an unsigned big-endian integer without leading zero octets.
fn bit_length(bytes: &[u8]) -> usize {
    bytes
        .first()
        .map_or(0, |first| bytes.len() * 8 - first.leading_zeros() as usize)
}

fn uint(bytes: &[u8], bits: u32) -> Result<BoxedUint, Error> {
    BoxedUint::from_be_slice(bytes, bits).map_err(|_| Error::InvalidKey)
}

/// DER length of a TLV with `content` bytes of content, in long-form length when needed.
const fn der_len(content: usize) -> usize {
    let mut length_octets = 1;
    if content >= 0x80 {
        let mut rest = content;
        while rest > 0 {
            length_octets += 1;
            rest >>= 8;
        }
    }
    1 + length_octets + content
}

/// DER length of a positive INTEGER of at most `bits` bits, including a possible sign octet.
const fn der_integer_len(bits: usize) -> usize {
    der_len(bits / 8 + 1)
}

const MODULUS_LEN: usize = der_integer_len(RsaPublicKey::MAX_SIZE);
const EXPONENT_LEN: usize = der_integer_len((u64::BITS - RsaPublicKey::MAX_PUB_EXPONENT.leading_zeros()) as usize);

/// INVARIANT: the encoded length of the longest PKCS#1 `RSAPublicKey` within the library's limits (rsa 0.10.0,
/// src/public_key.rs:39,60).
const PUBLIC_KEY_MAX_LEN: usize = der_len(MODULUS_LEN + EXPONENT_LEN);

fn load_public_key(der: &[u8], algorithm: Algorithm) -> Result<RsaPublicKey, Error> {
    // Defense in depth: capacity limits take precedence over structure, so the cap bounds work before decoding.
    if der.len() > PUBLIC_KEY_MAX_LEN {
        return Err(Error::Unsupported(algorithm));
    }
    let parsed = rsa::pkcs1::RsaPublicKeyRef::from_der(der).map_err(|_| Error::InvalidKey)?;
    let n = uint(parsed.modulus.as_bytes(), precision(parsed.modulus.as_bytes())?)?;
    let e = uint(
        parsed.public_exponent.as_bytes(),
        precision(parsed.public_exponent.as_bytes())?,
    )?;
    // Classification follows the library's check order: modulus size, structure, then exponent bounds (rsa
    // 0.10.0, src/public_key.rs:105–127,233–268).
    // The zero lower bound leaves out the library's default 1024-bit minimum (src/public_key.rs:36,89–91), which
    // private-key loading does not apply (src/private_key.rs:372–382,533–537), so both paths accept the same moduli.
    RsaPublicKey::new_with_size_limits(n, e, 0..=RsaPublicKey::MAX_SIZE).map_err(|error| match error {
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

fn error(error: rsa::Error) -> Error {
    match error {
        rsa::Error::Rng => Error::ProviderFailure,
        rsa::Error::MessageTooLong => Error::InvalidInput,
        rsa::Error::Decryption | rsa::Error::Verification => Error::VerificationFailed,
        _ => Error::InvalidKey,
    }
}
fn encrypt<P: PaddingScheme>(key: &RsaPublicKey, plaintext: &[u8], padding: P) -> Result<OutputBytes, Error> {
    // Native ciphertext output is modulus-sized (rsa 0.10.0, src/pkcs1v15.rs:333; src/oaep.rs:298).
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
        let parsed =
            rsa::pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes()).map_err(|_| Error::InvalidKey)?;
        // The library's public-key limits apply after parsing and before key construction.
        // The library loads private keys of any modulus size (rsa 0.10.0, src/private_key.rs:533–537;
        // src/public_key.rs:227–229) and reports an oversized exponent only as a malformed key (src/encoding.rs:68;
        // src/public_key.rs:246–248).
        // Key construction converts d, p and q at the modulus precision, and its stack use grows with the modulus
        // (src/encoding.rs:41–69).
        // DER parsing does not grow with the input, so no length cap precedes it; PKCS#8 attributes, which the decoder
        // skips (pkcs8 0.11.0, src/private_key_info.rs:223–224), would make a whole-document cap refuse valid keys.
        // `as_bytes` strips the sign octet, so 8192 bits is 1024 bytes (der 0.8.2,
        // src/asn1/integer/uint.rs:351–365,406–416).
        let exponent = parsed.public_exponent.as_bytes();
        if parsed.modulus.as_bytes().len() > RsaPublicKey::MAX_SIZE / 8
            || uint(exponent, precision(exponent)?)? > BoxedUint::from(RsaPublicKey::MAX_PUB_EXPONENT)
        {
            return Err(Error::Unsupported(Algorithm::PrivateKeyLoading(KeyType::Rsa)));
        }
        // Two-prime key construction stores each prime in half the modulus width and refuses a wider prime, which
        // decoding reports only as a malformed key (rsa 0.10.0, src/private_key.rs:281–299; src/encoding.rs:68).
        // Keys with unequal primes are outside the must-support set, so that width is a capacity limit.
        let half = bit_length(parsed.modulus.as_bytes()).div_ceil(2);
        if bit_length(parsed.prime1.as_bytes()) > half || bit_length(parsed.prime2.as_bytes()) > half {
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
        let bits = match self.0 {
            KeyGenerationAlgorithm::Rsa2048 => 2048,
            KeyGenerationAlgorithm::Rsa3072 => 3072,
            KeyGenerationAlgorithm::Rsa4096 => 4096,
            _ => return Err(Error::Unsupported(Algorithm::KeyGeneration(self.0))),
        };
        generate_pkcs8(bits)
    }
}
fn generate_pkcs8(bits: usize) -> Result<OutputBytes, Error> {
    use rsa::rand_core::SeedableRng;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| Error::ProviderFailure)?;
    // Infallible seeded RNG.
    // UNTESTED: the seed and the generator's buffer and state are wiped after use; wiping the seed's stack copies is
    // best effort.
    // Leftover seed bytes would reproduce the generated key.
    // When changing it, keep the seed in `Zeroizing` and a generator that wipes on drop (chacha20 0.10.2,
    // src/rng.rs:94–98; src/lib.rs:306–310).
    let mut rng = chacha20::ChaCha20Rng::from_seed(*seed);
    let key =
        RsaPrivateKey::new_with_exp(&mut rng, bits, BoxedUint::from(65537u64)).map_err(|_| Error::ProviderFailure)?;
    let document = key.to_pkcs8_der().map_err(|_| Error::ProviderFailure)?;
    crate::util::output(document.as_bytes())
}
fn signing_error(error: rsa::Error, algorithm: SignatureAlgorithm) -> Error {
    // An undersized modulus is MessageTooLong (rsa 0.10.0, src/algorithms/pkcs1v15.rs:68–73).
    // Signing checks its result like decryption and reports a mismatch as Internal, mapped to InvalidKey
    // (src/algorithms/rsa.rs:188–204; src/pkcs1v15.rs:421–424).
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
    // The scheme blinds with a fallible generator and pads to size(), not whole limbs (rsa 0.10.0,
    // src/traits/padding.rs:37–42; src/pkcs1v15.rs:411–425).
    // UNTESTED: the private-key operation is blinded with the operating-system generator.
    // Blinding counters timing attacks on the private key, and signatures are the same either way.
    // When changing the call, keep passing a generator.
    rsa::Pkcs1v15Sign::new::<D>()
        .sign(Some(&mut getrandom::SysRng), key, &digest)
        .map(|signature| OutputBytes::new(Zeroizing::new(signature)))
        .map_err(|error| signing_error(error, algorithm))
}
impl PrivateKey for Key {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn key_size_bits(&self) -> usize {
        self.0.n().bit_width_vartime() as usize
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
            // Not offered: rsa 0.10.0 decrypts PKCS#1 v1.5 with implicit rejection (src/pkcs1v15.rs:221–226) and skips
            // the OAEP leading octet (src/algorithms/oaep.rs:231), so it cannot report every padding failure as
            // `VerificationFailed`.
            KeyOperation::Decrypt(_) => false,
            KeyOperation::PublicKey => true,
            _ => false,
        }
    }
    fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<OutputBytes, Error> {
        with_digest!(algorithm, sign, &self.0, message, algorithm)
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
    use rsa::pkcs8::der::{
        Encode,
        asn1::{OctetStringRef, UintRef},
    };

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

    // The cap is the library's encoding of the largest public key within its limits; longer inputs are refused undecoded.
    #[test]
    fn encoded_length_cap() {
        let algorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
        let n = UintRef::new(&[0xff; RsaPublicKey::MAX_SIZE / 8]).unwrap();
        let exponent = RsaPublicKey::MAX_PUB_EXPONENT.to_be_bytes();
        let e = UintRef::new(&exponent).unwrap();
        let public = rsa::pkcs1::RsaPublicKey {
            modulus: n,
            public_exponent: e,
        };
        assert_eq!(public.to_der().unwrap().len(), PUBLIC_KEY_MAX_LEN);
        for (len, expected) in [
            (PUBLIC_KEY_MAX_LEN, Error::InvalidKey),
            (
                PUBLIC_KEY_MAX_LEN + 1,
                Error::Unsupported(Algorithm::Signature(algorithm)),
            ),
        ] {
            assert_eq!(
                Verify(algorithm).verify(PublicKey(&vec![0; len]), b"", b""),
                Err(expected)
            );
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

    // Conformance generates RSA keys only in extended runs, so this keeps seed expansion and PKCS#8 output covered.
    #[test]
    fn generated_key_loads() {
        let document = generate_pkcs8(1024).unwrap();
        let key = Loader.load(PrivateKeyMaterial::Pkcs8(&document)).unwrap();
        assert_eq!(key.key_size_bits(), 1024);
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
            key.primes().iter().map(|prime| prime.as_ref().clone()).collect(),
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
