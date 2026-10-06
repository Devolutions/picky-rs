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

    #[cfg(feature = "rustcrypto")]
    {
        CryptoProvider::RustCrypto
    }
}

/// Returns whether the build enforces the FIPS algorithm policy.
pub const fn fips_mode() -> bool {
    cfg!(feature = "fips")
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("algorithm disabled by the active cryptographic policy: {algorithm}")]
pub struct CryptoPolicyError {
    pub algorithm: String,
}

#[cfg(feature = "fips")]
pub(crate) fn require_hash(algorithm: HashAlgorithm) -> Result<(), CryptoPolicyError> {
    if !fips_mode()
        || matches!(
            algorithm,
            HashAlgorithm::SHA2_224
                | HashAlgorithm::SHA2_256
                | HashAlgorithm::SHA2_384
                | HashAlgorithm::SHA2_512
                | HashAlgorithm::SHA3_384
                | HashAlgorithm::SHA3_512
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
            ) | SignatureAlgorithm::RsaPss(HashAlgorithm::SHA2_256 | HashAlgorithm::SHA2_384 | HashAlgorithm::SHA2_512,),
            None,
        ) | (
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256),
            Some(EcCurve::NistP256)
        ) | (
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384),
            Some(EcCurve::NistP384)
        ) | (
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512),
            Some(EcCurve::NistP521)
        ) | (SignatureAlgorithm::Ed25519, None)
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
mod aws_lc_fips {
    use super::{CryptoPolicyError, require_signature};
    use crate::hash::HashAlgorithm;
    use crate::key::ec::{EcCurve, EcdsaKeypair, EcdsaPublicKey, NamedEcCurve};
    use crate::key::ed::{EdAlgorithm, EdKeypair, EdPublicKey, NamedEdAlgorithm};
    use crate::key::{PrivateKey, PublicKey};
    use crate::signature::{SignatureAlgorithm, SignatureError};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, RsaKeyPair, UnparsedPublicKey};

    fn policy_error(error: CryptoPolicyError) -> SignatureError {
        SignatureError::AlgorithmDisabledByPolicy {
            algorithm: error.algorithm,
        }
    }

    fn require_rsa_signature_key(public_key: &PublicKey) -> Result<(), SignatureError> {
        let picky_asn1_x509::PublicKey::Rsa(key) = &public_key.as_inner().subject_public_key else {
            return Err(SignatureError::Rsa {
                context: "RSA signature requires an RSA key".to_string(),
            });
        };
        let modulus = key.modulus.as_unsigned_bytes_be();
        let bits = modulus.iter().position(|byte| *byte != 0).map_or(0, |start| {
            (modulus.len() - start) * 8 - modulus[start].leading_zeros() as usize
        });
        // The pinned AWS-LC signature service requires an even modulus bit length.
        if !(2048..=8192).contains(&bits) || bits % 2 != 0 {
            return Err(SignatureError::AlgorithmDisabledByPolicy {
                algorithm: format!(
                    "RSA signature key must have an even bit length between 2048 and 8192 ({bits} bits)"
                ),
            });
        }
        Ok(())
    }

    pub(crate) fn sign(
        algorithm: SignatureAlgorithm,
        msg: &[u8],
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>, SignatureError> {
        match algorithm {
            algorithm @ (SignatureAlgorithm::RsaPkcs1v15(hash) | SignatureAlgorithm::RsaPss(hash)) => {
                require_signature(algorithm, None).map_err(policy_error)?;
                require_rsa_signature_key(&private_key.to_public_key()?)?;
                let key = RsaKeyPair::from_der(&private_key.to_pkcs1()?).map_err(|error| SignatureError::Rsa {
                    context: format!("AWS-LC rejected the RSA private key: {error}"),
                })?;
                let encoding = match (algorithm, hash) {
                    (SignatureAlgorithm::RsaPkcs1v15(_), HashAlgorithm::SHA2_256) => &signature::RSA_PKCS1_SHA256,
                    (SignatureAlgorithm::RsaPkcs1v15(_), HashAlgorithm::SHA2_384) => &signature::RSA_PKCS1_SHA384,
                    (SignatureAlgorithm::RsaPkcs1v15(_), HashAlgorithm::SHA2_512) => &signature::RSA_PKCS1_SHA512,
                    (SignatureAlgorithm::RsaPss(_), HashAlgorithm::SHA2_256) => &signature::RSA_PSS_SHA256,
                    (SignatureAlgorithm::RsaPss(_), HashAlgorithm::SHA2_384) => &signature::RSA_PSS_SHA384,
                    (SignatureAlgorithm::RsaPss(_), HashAlgorithm::SHA2_512) => &signature::RSA_PSS_SHA512,
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
                    (EcCurve::NistP521, HashAlgorithm::SHA2_512) => &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
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
            SignatureAlgorithm::Ed25519 => {
                require_signature(algorithm, None).map_err(policy_error)?;
                let key = EdKeypair::try_from(private_key)?;
                if key.algorithm() != &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) {
                    return Err(SignatureError::AlgorithmDisabledByPolicy {
                        algorithm: key.algorithm().to_string(),
                    });
                }
                let key_pair = match key.public_key() {
                    Some(public_key) => signature::Ed25519KeyPair::from_seed_and_public_key(key.secret(), public_key),
                    None => signature::Ed25519KeyPair::from_seed_unchecked(key.secret()),
                }
                .map_err(|error| SignatureError::Ed {
                    context: format!("AWS-LC rejected the Ed25519 keypair: {error}"),
                })?;
                key_pair
                    .try_sign(msg)
                    .map(|signature| signature.as_ref().to_vec())
                    .map_err(|_| SignatureError::Ed {
                        context: "AWS-LC Ed25519 signing failed".to_string(),
                    })
            }
        }
    }

    pub(crate) fn verify(
        algorithm: SignatureAlgorithm,
        public_key: &PublicKey,
        msg: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), SignatureError> {
        let (verification_algorithm, key_bytes): (&dyn signature::VerificationAlgorithm, Vec<u8>) = match algorithm {
            algorithm @ (SignatureAlgorithm::RsaPkcs1v15(hash) | SignatureAlgorithm::RsaPss(hash)) => {
                require_signature(algorithm, None).map_err(policy_error)?;
                require_rsa_signature_key(public_key)?;
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match hash {
                    HashAlgorithm::SHA2_256 if matches!(algorithm, SignatureAlgorithm::RsaPkcs1v15(_)) => {
                        &signature::RSA_PKCS1_2048_8192_SHA256
                    }
                    HashAlgorithm::SHA2_384 if matches!(algorithm, SignatureAlgorithm::RsaPkcs1v15(_)) => {
                        &signature::RSA_PKCS1_2048_8192_SHA384
                    }
                    HashAlgorithm::SHA2_512 if matches!(algorithm, SignatureAlgorithm::RsaPkcs1v15(_)) => {
                        &signature::RSA_PKCS1_2048_8192_SHA512
                    }
                    HashAlgorithm::SHA2_256 => &signature::RSA_PSS_2048_8192_SHA256,
                    HashAlgorithm::SHA2_384 => &signature::RSA_PSS_2048_8192_SHA384,
                    HashAlgorithm::SHA2_512 => &signature::RSA_PSS_2048_8192_SHA512,
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
                    (EcCurve::NistP521, HashAlgorithm::SHA2_512) => &signature::ECDSA_P521_SHA512_ASN1,
                    _ => unreachable!("policy checked above"),
                };
                (verification_algorithm, key.encoded_point().to_vec())
            }
            SignatureAlgorithm::Ed25519 => {
                require_signature(algorithm, None).map_err(policy_error)?;
                let key = EdPublicKey::try_from(public_key)?;
                if key.algorithm() != &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) {
                    return Err(SignatureError::AlgorithmDisabledByPolicy {
                        algorithm: key.algorithm().to_string(),
                    });
                }
                (&signature::ED25519, key.data().to_vec())
            }
        };

        UnparsedPublicKey::new(verification_algorithm, key_bytes)
            .verify(msg, signature_bytes)
            .map_err(|_| SignatureError::BadSignature)
    }
}

#[cfg(feature = "fips")]
pub(crate) mod fips {
    use crate::key::{PrivateKey, PublicKey};
    use crate::signature::{SignatureAlgorithm, SignatureError};

    pub(crate) fn sign(
        algorithm: SignatureAlgorithm,
        msg: &[u8],
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>, SignatureError> {
        #[cfg(feature = "fips-aws-lc")]
        {
            super::aws_lc_fips::sign(algorithm, msg, private_key)
        }
    }

    pub(crate) fn verify(
        algorithm: SignatureAlgorithm,
        public_key: &PublicKey,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        #[cfg(feature = "fips-aws-lc")]
        {
            super::aws_lc_fips::verify(algorithm, public_key, msg, signature)
        }
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

    #[cfg(feature = "fips")]
    #[test]
    fn approved_rsa_signatures_use_fips_provider() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;

        let key = PrivateKey::from_pem_str(picky_test_data::RSA_2048_PK_1).unwrap();
        let public_key = key.to_public_key().unwrap();
        let message = b"picky FIPS provider test";

        for hash in [
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
        ] {
            for algorithm in [SignatureAlgorithm::RsaPkcs1v15(hash), SignatureAlgorithm::RsaPss(hash)] {
                let signature = algorithm.sign(message, &key).unwrap();

                algorithm.verify(&public_key, message, &signature).unwrap();
                assert!(matches!(
                    algorithm.verify(&public_key, b"tampered", &signature),
                    Err(SignatureError::BadSignature)
                ));
            }
        }
    }

    #[cfg(feature = "fips-aws-lc")]
    #[test]
    fn rejects_odd_bit_rsa_signature_keys() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;
        use aws_lc_rs::signature::{self, RsaKeyPair};

        // Unequal 1025/1024-bit primes yield a genuinely 2049-bit modulus.
        let key = PrivateKey::from_pem_str(
            r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEBMWu5HlK+Ioo39MV0kMX+z5iUwVuMBEdNttxCO1EZkWGWCxfj
Hc1f1jkJXj3NDFaIn3/mlEtI6w31jHmF1OVSYlzfLg6YFDYR/rO4e3lX0nIYKVJd
ipszaOD7fis1wo5QlIQxyXTPj8fpRRa+2UxdfToeWZQ7Y1z9Bu1pQWl275EvMatv
z9t0IIZjtY8Cqqd1V7mMgNS72AYNV2xsxMZNiMGl945gj6I2w2m8uhie+VuR4BwO
FFn7ZTtx7Jhpyhpvkhn7W2pV23nsBGNQc1imw73B4keCYQNHrnJ5n+T48p/yJy6w
TVq5WuGaBOZDfJBZzQY0SufdaMl4TWIAZSRDAQIDAQABAoIBAQDxwui9VRgGtUyH
6AlWVDRY1dnimPnjpSGiPwX6eD758rpXu6ffPmO/alS9EcSPIKxzPUYjWti0n88g
TE2g8YneLM/JYGoHjal+6Xp92tam0gPIKde70RDH01egTsn2YLruZRoX8uweT0ua
kd+umKFkcC34ELtV8xSjeCiaS8aG6J7kfBAUtEwe1S3j7L+3Ls9k14qiPU2u0FXS
p8yy/GNTRfBUmkt+nq6YjrG6MNC7TrSG1lf1qMRp4aROFxsLokH7PjqcqEwk8bdl
lXjkpWeOvqBnxL4wiXvrROcKF9UnDeypZbIORXre8dESi5D6nY2HrIb9USVuG2Cr
wP7YdbIlAoGBAYJTC2FCHRJt8pG8T92SvkEQvNJMSOqB1zTEVZCALAP4+ghQdEQJ
h7Hq58n1sPZt/a8vhBpcSCMSkg29EGuZYAm9J6gDkx5jnOG65dca5l1hC7VKcwFT
gVGe19UUyQSOOMxhnjkD3qYasOM0+U4rM4m4bBbUiH8+1Mm9JS39JTfjAoGBAMpj
hzKeNEJEe0+IalctL981eBvKf6szSMtxeICnySk3TaaIWbmMSTSdinWXyYPMteXH
/qo3Rir0/rPPJgrb8BCpFyY9dcBcpiOwjtZH8rZnPU/gXsQhIoBKGLbWJw5/YX0h
SOUifhkFtcoXKlqVOj/FwRnsyT5/EP0b860T2ebLAoGBAOfw2e07l17AOhl7WOvr
tWQ1G1ibSk/ZQo7AraqC+WotKlihjRxoKFsOcLlVVDiv0tZCDesRqpG8DYpID7q6
K+nM8ikydDqTjdYMsv+Re+tmX3QpzaBnNUX+uxCIWSPuC3XRyf/rLdrGPZs7684d
q+Ssn+CZG5Zh77lrYQ4aZSUHAoGADsIhOry0nNx3jX4qGv9NjV5NyuECXE6aEVPN
8LvLfHju7aTlvhUPxYlzbk3KQRUtcnsaA/mR4VIKPLxvTr1pDR33dS9oJcXby6B1
WgTXGxv+KZP39R9hb693i+Wj5Xe+eSxzL1pLjbGP5xO3X/Gf1MSr5yMQLcGAUKS4
KTfYXO8CgYBAtN1e9tWX2OXySakxKjvk6q9buGls19PTnbC1e27gdfOug8xy5esC
0n5M4n/YkuyVWCxXu3B/VFGf/SwjoBg+J9/DuZ0rgjzOja3u9SMZ5OWrY2yHPZSN
t6WtoN4Zq7v+V5ZeVw6rnm8MEX/Fa+6Q24SGQqkaOmzDLLku6h02dg==
-----END RSA PRIVATE KEY-----"#,
        )
        .unwrap();
        let public_key = key.to_public_key().unwrap();
        let picky_asn1_x509::PublicKey::Rsa(rsa) = &public_key.as_inner().subject_public_key else {
            panic!("expected RSA key");
        };
        let modulus = rsa.modulus.as_unsigned_bytes_be();
        assert_eq!(modulus.len() * 8 - modulus[0].leading_zeros() as usize, 2049);
        let provider_key = RsaKeyPair::from_der(&key.to_pkcs1().unwrap()).unwrap();
        let message = b"odd-bit RSA regression";
        for (algorithm, encoding) in [
            (
                SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256),
                &signature::RSA_PKCS1_SHA256,
            ),
            (
                SignatureAlgorithm::RsaPss(HashAlgorithm::SHA2_256),
                &signature::RSA_PSS_SHA256,
            ),
        ] {
            let mut signature = vec![0; provider_key.public_modulus_len()];
            provider_key
                .sign(encoding, &aws_lc_rs::rand::SystemRandom::new(), message, &mut signature)
                .unwrap();
            assert!(matches!(
                algorithm.sign(message, &key),
                Err(SignatureError::AlgorithmDisabledByPolicy { algorithm }) if algorithm.contains("2049 bits")
            ));
            assert!(matches!(
                algorithm.verify(&public_key, message, &signature),
                Err(SignatureError::AlgorithmDisabledByPolicy { algorithm }) if algorithm.contains("2049 bits")
            ));
        }
    }

    #[cfg(feature = "fips")]
    #[test]
    fn approved_ecdsa_signatures_use_fips_provider() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;

        let message = b"picky FIPS provider test";

        for (pem, hash) in [
            (picky_test_data::EC_NIST256_PK_1, HashAlgorithm::SHA2_256),
            (picky_test_data::EC_NIST384_PK_1, HashAlgorithm::SHA2_384),
            (picky_test_data::EC_NIST521_PK_1, HashAlgorithm::SHA2_512),
        ] {
            let key = PrivateKey::from_pem_str(pem).unwrap();
            let public_key = key.to_public_key().unwrap();
            let algorithm = SignatureAlgorithm::Ecdsa(hash);
            let signature = algorithm.sign(message, &key).unwrap();

            algorithm.verify(&public_key, message, &signature).unwrap();
            assert!(matches!(
                algorithm.verify(&public_key, b"tampered", &signature),
                Err(SignatureError::BadSignature)
            ));
        }
    }

    #[cfg(feature = "fips")]
    #[test]
    fn rejects_legacy_signature_algorithms() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;

        let key = PrivateKey::from_pem_str(picky_test_data::RSA_2048_PK_1).unwrap();
        for hash in [HashAlgorithm::SHA1, HashAlgorithm::MD5] {
            let error = SignatureAlgorithm::RsaPkcs1v15(hash).sign(b"legacy", &key).unwrap_err();

            assert!(matches!(
                error,
                SignatureError::AlgorithmDisabledByPolicy { ref algorithm }
                    if algorithm == &format!("RsaPkcs1v15({hash:?})")
            ));
            assert_eq!(
                error.to_string(),
                format!("algorithm disabled by the active cryptographic policy: RsaPkcs1v15({hash:?})")
            );
        }
    }

    #[cfg(feature = "fips")]
    #[test]
    fn approved_ed25519_signatures_use_fips_provider() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;

        let key = PrivateKey::from_pem_str(picky_test_data::ED25519_PEM_PK_1).unwrap();
        let public_key = key.to_public_key().unwrap();
        let message = b"picky FIPS Ed25519 provider test";
        let signature = SignatureAlgorithm::Ed25519.sign(message, &key).unwrap();

        SignatureAlgorithm::Ed25519
            .verify(&public_key, message, &signature)
            .unwrap();
        assert!(matches!(
            SignatureAlgorithm::Ed25519.verify(&public_key, b"tampered", &signature),
            Err(SignatureError::BadSignature)
        ));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn approved_p521_curve_uses_fips_provider() {
        use crate::key::PrivateKey;
        use crate::signature::SignatureError;

        let key = PrivateKey::from_pem_str(picky_test_data::EC_NIST521_PK_1).unwrap();
        let public_key = key.to_public_key().unwrap();
        let algorithm = SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512);
        let signature = algorithm.sign(b"P-521", &key).unwrap();

        algorithm.verify(&public_key, b"P-521", &signature).unwrap();
        assert!(matches!(
            algorithm.verify(&public_key, b"tampered", &signature),
            Err(SignatureError::BadSignature)
        ));
    }
}
