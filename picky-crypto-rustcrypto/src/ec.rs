use picky_crypto::{
    Algorithm, Entry, EphemeralSecret, Error, KeyAgreement, KeyAgreementAlgorithm, KeyGenerationAlgorithm,
    KeyGenerator, KeyOperation, KeyType, OutputBytes, PrivateKey, PrivateKeyLoader, PrivateKeyMaterial,
    ProviderBuilder, PublicKey, SignatureAlgorithm, SignatureVerifier, Zeroizing,
};
use std::sync::Arc;

fn uncompressed(bytes: &[u8], len: usize, error: Error) -> Result<(), Error> {
    if bytes.len() != len || bytes.first() != Some(&4) {
        return Err(error);
    }
    Ok(())
}

macro_rules! curve {
    ($module:ident, $library:ident, $key_type:ident, $sign:ident, $agree:ident, $generate:ident, $bits:expr, $point_len:expr, $signature_len:expr) => {
        mod $module {
            use super::*;
            use $library::{
                SecretKey, ecdh,
                ecdsa::{
                    Signature, SigningKey, VerifyingKey,
                    signature::{Signer, Verifier},
                },
                elliptic_curve::{Generate, sec1::ToSec1Point},
                pkcs8::{EncodePrivateKey, PrivateKeyInfoRef, Version, der::Decode},
            };
            struct Verify;
            struct Agreement;
            struct Loader;
            struct Generator;
            struct Key(SecretKey);
            struct Ephemeral(ecdh::EphemeralSecret);

            impl SignatureVerifier for Verify {
                fn algorithm(&self) -> SignatureAlgorithm {
                    SignatureAlgorithm::$sign
                }
                fn fips(&self) -> bool {
                    false
                }
                fn verify(&self, public: PublicKey<'_>, message: &[u8], signature: &[u8]) -> Result<(), Error> {
                    uncompressed(public.0, $point_len, Error::InvalidKey)?;
                    let key = VerifyingKey::from_sec1_bytes(public.0).map_err(|_| Error::InvalidKey)?;
                    // Rejects lengths other than 2 × the field size (ecdsa 0.17.0, src\lib.rs:212–216).
                    let signature = Signature::from_slice(signature).map_err(|_| Error::VerificationFailed)?;
                    key.verify(message, &signature)
                        .map_err(|_| Error::VerificationFailed)
                }
            }
            fn peer(bytes: &[u8]) -> Result<$library::PublicKey, Error> {
                uncompressed(bytes, $point_len, Error::InvalidInput)?;
                $library::PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidInput)
            }
            impl PrivateKeyLoader for Loader {
                fn key_type(&self) -> KeyType {
                    KeyType::$key_type
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
                    let inner =
                        sec1::EcPrivateKey::from_der(info.private_key.as_bytes()).map_err(|_| Error::InvalidKey)?;
                    // SecretKey::from_slice zero-pads short scalars (elliptic-curve 0.14.1, src\secret_key.rs:163–173).
                    if inner.private_key.len() != $signature_len / 2 {
                        return Err(Error::InvalidKey);
                    }
                    // The library checks the curve OIDs and that an embedded public key matches
                    // (elliptic-curve 0.14.1, src\secret_key\pkcs8.rs:53–59; src\secret_key.rs:465–484).
                    let key = SecretKey::try_from(info).map_err(|_| Error::InvalidKey)?;
                    Ok(Box::new(Key(key)))
                }
            }
            impl PrivateKey for Key {
                fn key_type(&self) -> KeyType {
                    KeyType::$key_type
                }
                fn key_size_bits(&self) -> usize {
                    $bits
                }
                fn fips(&self) -> bool {
                    false
                }
                fn supports(&self, operation: KeyOperation) -> bool {
                    matches!(
                        operation,
                        KeyOperation::Sign(SignatureAlgorithm::$sign)
                            | KeyOperation::Agree(KeyAgreementAlgorithm::$agree)
                            | KeyOperation::PublicKey
                    )
                }
                fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<OutputBytes, Error> {
                    if algorithm != SignatureAlgorithm::$sign {
                        return Err(Error::Unsupported(Algorithm::Signature(algorithm)));
                    }
                    let signing = SigningKey::from(&self.0);
                    let signature: Signature = signing.try_sign(message).map_err(|_| Error::InvalidKey)?;
                    let bytes = Zeroizing::new(signature.to_bytes());
                    crate::util::output(&bytes)
                }
                fn agree(&self, algorithm: KeyAgreementAlgorithm, bytes: &[u8]) -> Result<OutputBytes, Error> {
                    if algorithm != KeyAgreementAlgorithm::$agree {
                        return Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm)));
                    }
                    let secret = self.0.diffie_hellman(&peer(bytes)?);
                    crate::util::output(secret.raw_secret_bytes())
                }
                fn public_key(&self) -> Result<OutputBytes, Error> {
                    crate::util::output(self.0.public_key().to_sec1_point(false).as_bytes())
                }
            }
            impl KeyAgreement for Agreement {
                fn algorithm(&self) -> KeyAgreementAlgorithm {
                    KeyAgreementAlgorithm::$agree
                }
                fn fips(&self) -> bool {
                    false
                }
                fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error> {
                    let secret = ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng)
                        .map_err(|_| Error::ProviderFailure)?;
                    Ok(Box::new(Ephemeral(secret)))
                }
            }
            impl EphemeralSecret for Ephemeral {
                fn public_key(&self) -> Result<OutputBytes, Error> {
                    crate::util::output(self.0.public_key().to_sec1_point(false).as_bytes())
                }
                fn agree(self: Box<Self>, bytes: &[u8]) -> Result<OutputBytes, Error> {
                    let secret = self.0.diffie_hellman(&peer(bytes)?);
                    crate::util::output(secret.raw_secret_bytes())
                }
            }
            impl KeyGenerator for Generator {
                fn algorithm(&self) -> KeyGenerationAlgorithm {
                    KeyGenerationAlgorithm::$generate
                }
                fn fips(&self) -> bool {
                    false
                }
                fn generate(&self) -> Result<OutputBytes, Error> {
                    let key =
                        SecretKey::try_generate_from_rng(&mut getrandom::SysRng).map_err(|_| Error::ProviderFailure)?;
                    let document = key.to_pkcs8_der().map_err(|_| Error::ProviderFailure)?;
                    crate::util::output(document.as_bytes())
                }
            }
            pub(super) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
                builder
                    .with(Entry::SignatureVerifier(Arc::new(Verify)))
                    .with(Entry::KeyAgreement(Arc::new(Agreement)))
                    .with(Entry::PrivateKeyLoader(Arc::new(Loader)))
                    .with(Entry::KeyGenerator(Arc::new(Generator)))
            }

            #[cfg(test)]
            #[test]
            fn short_private_scalar_is_rejected() {
                use $library::pkcs8::der::{Encode, asn1::OctetStringRef};
                let scalar = Zeroizing::new([1u8; $signature_len / 2]);
                let document = SecretKey::from_slice(&*scalar).unwrap().to_pkcs8_der().unwrap();
                let mut info = PrivateKeyInfoRef::from_der(document.as_bytes()).unwrap();
                let mut inner = sec1::EcPrivateKey::from_der(info.private_key.as_bytes()).unwrap();
                inner.private_key = &scalar[1..];
                inner.public_key = None;
                let encoded_inner = Zeroizing::new(inner.to_der().unwrap());
                info.private_key = OctetStringRef::new(&encoded_inner).unwrap();
                let encoded = Zeroizing::new(info.to_der().unwrap());
                assert!(matches!(
                    Loader.load(PrivateKeyMaterial::Pkcs8(&encoded)),
                    Err(Error::InvalidKey)
                ));
            }
        }
    };
}
curve!(
    p256_adapter,
    p256,
    EcP256,
    EcdsaP256Sha256,
    EcdhP256,
    EcP256,
    256,
    65,
    64
);
curve!(
    p384_adapter,
    p384,
    EcP384,
    EcdsaP384Sha384,
    EcdhP384,
    EcP384,
    384,
    97,
    96
);
curve!(
    p521_adapter,
    p521,
    EcP521,
    EcdsaP521Sha512,
    EcdhP521,
    EcP521,
    521,
    133,
    132
);

pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    p521_adapter::entries(p384_adapter::entries(p256_adapter::entries(builder)))
}
