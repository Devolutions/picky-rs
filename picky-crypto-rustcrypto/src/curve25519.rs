use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
    pkcs8::{EncodePrivateKey, PrivateKeyInfoRef, spki::der::Decode},
};
use picky_crypto::{
    Algorithm, Entry, EphemeralSecret, Error, KeyAgreement, KeyAgreementAlgorithm, KeyGenerationAlgorithm,
    KeyGenerator, KeyOperation, KeyType, OutputBytes, PrivateKey, PrivateKeyLoader, PrivateKeyMaterial,
    ProviderBuilder, PublicKey, SignatureAlgorithm, SignatureVerifier, Zeroizing,
};
use std::sync::Arc;

struct Verify;
struct EdLoader;
struct XLoader;
struct XAgreement;
struct Generator;
struct EdKey(SigningKey);
struct XKey(x25519_dalek::StaticSecret);

impl SignatureVerifier for Verify {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn verify(&self, public: PublicKey<'_>, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let public = public.0.try_into().map_err(|_| Error::InvalidKey)?;
        let key = VerifyingKey::from_bytes(public).map_err(|_| Error::InvalidKey)?;
        // The library accepts non-canonical A encodings (ZIP-215, ed25519-dalek 3.0.0, src\verifying.rs:172–182),
        // so the adapter compares the library's canonical recompression with the input.
        if key.to_edwards().compress().as_bytes() != public {
            return Err(Error::InvalidKey);
        }
        let signature = Signature::from_slice(signature).map_err(|_| Error::VerificationFailed)?;
        key.verify(message, &signature).map_err(|_| Error::VerificationFailed)
    }
}
impl PrivateKeyLoader for EdLoader {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        let PrivateKeyMaterial::Pkcs8(der) = material else {
            return Err(Error::InvalidKey);
        };
        let info = PrivateKeyInfoRef::from_der(der).map_err(|_| Error::InvalidKey)?;
        // Ed25519's decoder ignores non-aligned public keys and rejects other lengths
        // (ed25519 3.0.0, src\pkcs8.rs:180–185).
        // as_bytes rejects unused bits (der 0.8.2, src\asn1\bit_string.rs:121–127).
        if info.public_key.is_some_and(|public| public.as_bytes().is_none()) {
            return Err(Error::InvalidKey);
        }
        // The library checks that an embedded public key matches (ed25519-dalek 3.0.0, src\signing.rs:748–759).
        let key = SigningKey::try_from(info).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(EdKey(key)))
    }
}
impl PrivateKey for EdKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    fn key_size_bits(&self) -> usize {
        255
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        matches!(
            operation,
            KeyOperation::Sign(SignatureAlgorithm::Ed25519) | KeyOperation::PublicKey
        )
    }
    fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<OutputBytes, Error> {
        if algorithm != SignatureAlgorithm::Ed25519 {
            return Err(Error::Unsupported(Algorithm::Signature(algorithm)));
        }
        let bytes = Zeroizing::new(self.0.try_sign(message).map_err(|_| Error::InvalidKey)?.to_bytes());
        crate::util::output(&*bytes)
    }
    fn public_key(&self) -> Result<OutputBytes, Error> {
        crate::util::output(self.0.verifying_key().as_bytes())
    }
}
impl PrivateKeyLoader for XLoader {
    fn key_type(&self) -> KeyType {
        KeyType::X25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        let PrivateKeyMaterial::X25519(scalar) = material else {
            return Err(Error::InvalidKey);
        };
        Ok(Box::new(XKey(x25519_dalek::StaticSecret::from(*scalar))))
    }
}
impl PrivateKey for XKey {
    fn key_type(&self) -> KeyType {
        KeyType::X25519
    }
    fn key_size_bits(&self) -> usize {
        255
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        matches!(
            operation,
            KeyOperation::Agree(KeyAgreementAlgorithm::X25519) | KeyOperation::PublicKey
        )
    }
    fn agree(&self, algorithm: KeyAgreementAlgorithm, bytes: &[u8]) -> Result<OutputBytes, Error> {
        if algorithm != KeyAgreementAlgorithm::X25519 {
            return Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm)));
        }
        let public: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        let secret = self.0.diffie_hellman(&x25519_dalek::PublicKey::from(public));
        if !secret.was_contributory() {
            return Err(Error::InvalidInput);
        }
        crate::util::output(secret.as_bytes())
    }
    fn public_key(&self) -> Result<OutputBytes, Error> {
        crate::util::output(x25519_dalek::PublicKey::from(&self.0).as_bytes())
    }
}
impl KeyAgreement for XAgreement {
    fn algorithm(&self) -> KeyAgreementAlgorithm {
        KeyAgreementAlgorithm::X25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error> {
        // Mirrors x25519-dalek 3.0.0's EphemeralSecret::random(): 32 bytes from getrandom, clamping left to the library.
        // Returns random-generator failures instead of panicking (src\x25519.rs:96–101).
        let mut scalar = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *scalar).map_err(|_| Error::ProviderFailure)?;
        Ok(Box::new(XKey(x25519_dalek::StaticSecret::from(*scalar))))
    }
}
impl EphemeralSecret for XKey {
    fn public_key(&self) -> Result<OutputBytes, Error> {
        PrivateKey::public_key(self)
    }
    fn agree(self: Box<Self>, bytes: &[u8]) -> Result<OutputBytes, Error> {
        PrivateKey::agree(&*self, KeyAgreementAlgorithm::X25519, bytes)
    }
}
impl KeyGenerator for Generator {
    fn algorithm(&self) -> KeyGenerationAlgorithm {
        KeyGenerationAlgorithm::Ed25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn generate(&self) -> Result<OutputBytes, Error> {
        use crypto_common::Generate;
        let key = SigningKey::try_generate_from_rng(&mut getrandom::SysRng).map_err(|_| Error::ProviderFailure)?;
        let document = key.to_pkcs8_der().map_err(|_| Error::ProviderFailure)?;
        crate::util::output(document.as_bytes())
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    builder
        .with(Entry::SignatureVerifier(Arc::new(Verify)))
        .with(Entry::PrivateKeyLoader(Arc::new(EdLoader)))
        .with(Entry::PrivateKeyLoader(Arc::new(XLoader)))
        .with(Entry::KeyAgreement(Arc::new(XAgreement)))
        .with(Entry::KeyGenerator(Arc::new(Generator)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519::pkcs8::{BitStringRef, spki::der::Encode};

    #[test]
    fn unaligned_outer_public_key_is_rejected() {
        let seed = Zeroizing::new([1u8; 32]);
        let document = SigningKey::from_bytes(&seed).to_pkcs8_der().unwrap();
        let mut info = PrivateKeyInfoRef::from_der(document.as_bytes()).unwrap();
        info.public_key = Some(BitStringRef::new(1, &[0; 32]).unwrap());
        let encoded = Zeroizing::new(info.to_der().unwrap());
        assert!(matches!(
            EdLoader.load(PrivateKeyMaterial::Pkcs8(&encoded)),
            Err(Error::InvalidKey)
        ));
    }

    #[test]
    fn non_canonical_public_key_is_rejected() {
        // y = p + 1 with p = 2^255 − 19, little-endian.
        let mut public = [0xff; 32];
        public[0] = 0xee;
        public[31] = 0x7f;
        assert!(matches!(
            Verify.verify(PublicKey(&public), b"", &[0; 64]),
            Err(Error::InvalidKey)
        ));
    }
}
