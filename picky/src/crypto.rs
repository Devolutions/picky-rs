//! Active cryptographic provider and build-time policy.

use thiserror::Error;

#[cfg(feature = "fips")]
use crate::hash::HashAlgorithm;
#[cfg(feature = "fips")]
use crate::key::EcCurve;
#[cfg(feature = "fips")]
use crate::signature::SignatureAlgorithm;

/// The cryptographic provider selected at build time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoProvider {
    RustCrypto,
    AwsLcFips,
}

/// Returns the cryptographic provider selected for this build.
pub const fn provider() -> CryptoProvider {
    #[cfg(feature = "fips-aws-lc")]
    {
        CryptoProvider::AwsLcFips
    }

    #[cfg(not(feature = "fips-aws-lc"))]
    {
        CryptoProvider::RustCrypto
    }
}

/// Returns whether the build enforces the FIPS algorithm policy.
pub const fn fips_mode() -> bool {
    cfg!(feature = "fips")
}

#[derive(Debug, Error)]
#[error("algorithm disabled by the active cryptographic policy: {algorithm}")]
pub struct CryptoPolicyError {
    pub algorithm: String,
}

#[cfg(feature = "fips")]
pub(crate) fn require_hash(algorithm: HashAlgorithm) -> Result<(), CryptoPolicyError> {
    if !fips_mode()
        || matches!(
            algorithm,
            HashAlgorithm::SHA2_256 | HashAlgorithm::SHA2_384 | HashAlgorithm::SHA2_512
        )
    {
        Ok(())
    } else {
        Err(CryptoPolicyError {
            algorithm: format!("{algorithm:?}"),
        })
    }
}

#[cfg(feature = "fips")]
pub(crate) fn require_signature(
    algorithm: SignatureAlgorithm,
    curve: Option<EcCurve>,
) -> Result<(), CryptoPolicyError> {
    if !fips_mode() {
        return Ok(());
    }

    let allowed = matches!(
        (algorithm, curve),
        (
            SignatureAlgorithm::RsaPkcs1v15(
                HashAlgorithm::SHA2_256 | HashAlgorithm::SHA2_384 | HashAlgorithm::SHA2_512,
            ),
            None,
        ) | (
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256),
            Some(EcCurve::NistP256)
        ) | (
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384),
            Some(EcCurve::NistP384)
        )
    );

    if allowed {
        Ok(())
    } else {
        Err(CryptoPolicyError {
            algorithm: match curve {
                Some(curve) => format!("{algorithm:?} with {curve}"),
                None => format!("{algorithm:?}"),
            },
        })
    }
}

#[cfg(feature = "fips-aws-lc")]
pub(crate) mod fips {
    use super::{CryptoPolicyError, require_signature};
    use crate::hash::HashAlgorithm;
    use crate::key::ec::{EcCurve, EcdsaKeypair, EcdsaPublicKey, NamedEcCurve};
    use crate::key::{PrivateKey, PublicKey};
    use crate::signature::{SignatureAlgorithm, SignatureError};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, RsaKeyPair, UnparsedPublicKey};

    fn policy_error(error: CryptoPolicyError) -> SignatureError {
        SignatureError::AlgorithmDisabledByPolicy {
            algorithm: error.algorithm,
        }
    }

    pub(crate) fn sign(
        algorithm: SignatureAlgorithm,
        msg: &[u8],
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>, SignatureError> {
        match algorithm {
            SignatureAlgorithm::RsaPkcs1v15(hash) => {
                require_signature(algorithm, None).map_err(policy_error)?;
                let key = RsaKeyPair::from_der(&private_key.to_pkcs1()?).map_err(|error| SignatureError::Rsa {
                    context: format!("AWS-LC rejected the RSA private key: {error}"),
                })?;
                if key.public_modulus_len() < 256 {
                    return Err(SignatureError::AlgorithmDisabledByPolicy {
                        algorithm: format!("RSA key smaller than 2048 bits ({} bits)", key.public_modulus_len() * 8),
                    });
                }
                let encoding = match hash {
                    HashAlgorithm::SHA2_256 => &signature::RSA_PKCS1_SHA256,
                    HashAlgorithm::SHA2_384 => &signature::RSA_PKCS1_SHA384,
                    HashAlgorithm::SHA2_512 => &signature::RSA_PKCS1_SHA512,
                    _ => unreachable!("policy checked above"),
                };
                let mut output = vec![0; key.public_modulus_len()];
                key.sign(encoding, &SystemRandom::new(), msg, &mut output)
                    .map_err(|_| SignatureError::Rsa {
                        context: "AWS-LC RSA signing failed".to_string(),
                    })?;
                Ok(output)
            }
            SignatureAlgorithm::Ecdsa(hash) => {
                let key = EcdsaKeypair::try_from(private_key)?;
                let curve = match key.curve() {
                    NamedEcCurve::Known(curve) => *curve,
                    NamedEcCurve::Unsupported(_) => {
                        return Err(SignatureError::AlgorithmDisabledByPolicy {
                            algorithm: "unsupported EC curve".to_string(),
                        });
                    }
                };
                require_signature(algorithm, Some(curve)).map_err(policy_error)?;
                let signing_algorithm = match (curve, hash) {
                    (EcCurve::NistP256, HashAlgorithm::SHA2_256) => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    (EcCurve::NistP384, HashAlgorithm::SHA2_384) => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    _ => unreachable!("policy checked above"),
                };
                let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
                    signing_algorithm,
                    key.secret(),
                    key.public_key().ok_or_else(|| SignatureError::Ec {
                        context: "EC public key is required for FIPS signing".to_string(),
                    })?,
                )
                .map_err(|error| SignatureError::Ec {
                    context: format!("AWS-LC rejected the EC keypair: {error}"),
                })?;
                key_pair
                    .sign(&SystemRandom::new(), msg)
                    .map(|signature| signature.as_ref().to_vec())
                    .map_err(|_| SignatureError::Ec {
                        context: "AWS-LC ECDSA signing failed".to_string(),
                    })
            }
            SignatureAlgorithm::Ed25519 => Err(SignatureError::AlgorithmDisabledByPolicy {
                algorithm: "Ed25519".to_string(),
            }),
        }
    }

    pub(crate) fn verify(
        algorithm: SignatureAlgorithm,
        public_key: &PublicKey,
        msg: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), SignatureError> {
        let (verification_algorithm, key_bytes): (&dyn signature::VerificationAlgorithm, Vec<u8>) = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15(hash) => {
                require_signature(algorithm, None).map_err(policy_error)?;
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match hash {
                    HashAlgorithm::SHA2_256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    HashAlgorithm::SHA2_384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    HashAlgorithm::SHA2_512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    _ => unreachable!("policy checked above"),
                };
                (verification_algorithm, public_key.to_pkcs1()?)
            }
            SignatureAlgorithm::Ecdsa(hash) => {
                let key = EcdsaPublicKey::try_from(public_key)?;
                let curve = match key.curve() {
                    NamedEcCurve::Known(curve) => *curve,
                    NamedEcCurve::Unsupported(_) => {
                        return Err(SignatureError::AlgorithmDisabledByPolicy {
                            algorithm: "unsupported EC curve".to_string(),
                        });
                    }
                };
                require_signature(algorithm, Some(curve)).map_err(policy_error)?;
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match (curve, hash) {
                    (EcCurve::NistP256, HashAlgorithm::SHA2_256) => &signature::ECDSA_P256_SHA256_ASN1,
                    (EcCurve::NistP384, HashAlgorithm::SHA2_384) => &signature::ECDSA_P384_SHA384_ASN1,
                    _ => unreachable!("policy checked above"),
                };
                (verification_algorithm, key.encoded_point().to_vec())
            }
            SignatureAlgorithm::Ed25519 => {
                return Err(SignatureError::AlgorithmDisabledByPolicy {
                    algorithm: "Ed25519".to_string(),
                });
            }
        };

        UnparsedPublicKey::new(verification_algorithm, key_bytes)
            .verify(msg, signature_bytes)
            .map_err(|_| SignatureError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_matches_build_features() {
        if cfg!(feature = "fips-aws-lc") {
            assert_eq!(provider(), CryptoProvider::AwsLcFips);
            assert!(fips_mode());
        } else {
            assert_eq!(provider(), CryptoProvider::RustCrypto);
        }
    }

    #[cfg(feature = "fips-aws-lc")]
    #[test]
    fn approved_rsa_signature_uses_fips_provider() {
        use crate::key::PrivateKey;

        let key = PrivateKey::from_pem_str(picky_test_data::RSA_2048_PK_1).unwrap();
        let public_key = key.to_public_key().unwrap();
        let algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256);
        let message = b"picky FIPS provider test";

        let signature = algorithm.sign(message, &key).unwrap();
        algorithm.verify(&public_key, message, &signature).unwrap();
    }

    #[cfg(feature = "fips-aws-lc")]
    #[test]
    fn approved_ecdsa_signature_uses_fips_provider() {
        use crate::key::PrivateKey;

        let key = PrivateKey::from_pem_str(picky_test_data::EC_NIST256_PK_1).unwrap();
        let public_key = key.to_public_key().unwrap();
        let algorithm = SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256);
        let message = b"picky FIPS provider test";

        let signature = algorithm.sign(message, &key).unwrap();
        algorithm.verify(&public_key, message, &signature).unwrap();
    }

    #[cfg(feature = "fips-aws-lc")]
    #[test]
    fn rejects_legacy_signature_algorithm() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;

        let key = PrivateKey::from_pem_str(picky_test_data::RSA_2048_PK_1).unwrap();
        let error = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
            .sign(b"legacy", &key)
            .unwrap_err();

        assert!(matches!(error, SignatureError::AlgorithmDisabledByPolicy { .. }));
    }
}
