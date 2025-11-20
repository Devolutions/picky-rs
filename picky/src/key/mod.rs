//! Wrappers around public and private keys raw data providing an easy to use API

pub(crate) mod ec;
pub(crate) mod ed;

use crate::pem::{parse_pem, Pem, PemError};
use const_oid::ObjectIdentifier;

use der::asn1::{BitString, OctetString, UintRef};
use num_bigint_dig::traits::ModInverse;
use num_bigint_dig::BigUint;
use picky_asn1_x509::oids;
use pkcs1::{RsaPrivateKey as Pkcs1RsaPrivateKey, RsaPublicKey as Pkcs1RsaPublicKey};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo, SecretDocument};
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sec1::EcPrivateKey;
use spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoOwned};
use thiserror::Error;
use zeroize::Zeroize;

use ec::{calculate_public_ec_key, EcComponent, NamedEcCurve};
use ed::{NamedEdAlgorithm, X25519FieldElement, X25519_FIELD_ELEMENT_SIZE};

pub use ec::EcCurve;
pub use ed::EdAlgorithm;

#[derive(Debug, Error)]
pub enum KeyError {
    /// ASN1 serialization error
    #[error("(ASN1) couldn't serialize {element}: {source}")]
    Asn1Serialization { element: &'static str, source: der::Error },

    /// ASN1 deserialization error
    #[error("(ASN1) couldn't deserialize {element}: {source}")]
    Asn1Deserialization { element: &'static str, source: der::Error },

    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// EC error
    #[error("EC error: {context}")]
    Ec { context: String },

    /// ED error
    #[error("ED error: {context}")]
    Ed { context: String },

    /// invalid PEM label error
    #[error("invalid PEM label: {label}")]
    InvalidPemLabel { label: String },

    /// unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: &'static str },

    /// invalid PEM provided
    #[error("invalid PEM provided: {source}")]
    Pem { source: PemError },
}

impl KeyError {
    pub(crate) fn unsupported_curve(curve_oid: &ObjectIdentifier, context: &'static str) -> Self {
        Self::Ec {
            context: format!("EC curve with oid `{curve_oid}` is not supported in context of {context}",),
        }
    }

    pub(crate) fn unsupported_ed_algorithm(oid: &ObjectIdentifier, context: &'static str) -> Self {
        Self::Ed {
            context: format!(
                "algorithm with oid `{oid}` based on Edwards curves is not supported in context of {context}",
            ),
        }
    }
}

impl From<rsa::errors::Error> for KeyError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Rsa { context: e.to_string() }
    }
}

impl From<PemError> for KeyError {
    fn from(e: PemError) -> Self {
        Self::Pem { source: e }
    }
}

impl From<picky_asn1_x509::PublicKeyError> for KeyError {
    fn from(e: picky_asn1_x509::PublicKeyError) -> Self {
        match e {
            picky_asn1_x509::PublicKeyError::UnsupportedAlgorithm { oid } => Self::UnsupportedAlgorithm {
                algorithm: "PublicKey parsing detected unsupported algorithm",
            },
            picky_asn1_x509::PublicKeyError::RsaParseError(der_err) => Self::Asn1Deserialization {
                source: der_err,
                element: "RSA public key",
            },
            picky_asn1_x509::PublicKeyError::InvalidKeyData => Self::Asn1Deserialization {
                source: der::ErrorKind::Failed.into(),
                element: "public key data",
            },
        }
    }
}

impl From<picky_asn1_x509::PrivateKeyError> for KeyError {
    fn from(e: picky_asn1_x509::PrivateKeyError) -> Self {
        match e {
            picky_asn1_x509::PrivateKeyError::UnsupportedAlgorithm { oid } => Self::UnsupportedAlgorithm {
                algorithm: "PrivateKey parsing detected unsupported algorithm",
            },
            picky_asn1_x509::PrivateKeyError::ParseError(der_err) => Self::Asn1Deserialization {
                source: der_err,
                element: "private key",
            },
            picky_asn1_x509::PrivateKeyError::InvalidKeyData => Self::Asn1Deserialization {
                source: der::ErrorKind::Failed.into(),
                element: "private key data",
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    Ec,
    Ed,
    Unknown,
}

// === private key === //

const PRIVATE_KEY_PEM_LABEL: &str = "PRIVATE KEY";
const RSA_PRIVATE_KEY_PEM_LABEL: &str = "RSA PRIVATE KEY";
const EC_PRIVATE_KEY_LABEL: &str = "EC PRIVATE KEY";

// We dont compress EC points by default to avoid potential interoperability issues.
// Namely, `ring` library has bug in it, which causes it to fail when validating
// encoded public key, comparing it with generated one (It assumes uncompressed point).
// [https://github.com/briansmith/ring/blob/155231fb017acaaa94a044f124bb34a777d115ef/src/ec/suite_b.rs#L221-L225]
const COMPRESS_EC_POINT_BY_DEFAULT: bool = false;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrivateKeyKind {
    Rsa,
    Ec {
        public_key: Option<Vec<u8>>,
        private_key: Vec<u8>,
        curve_oid: ObjectIdentifier,
    },
    Ed {
        public_key: Option<Vec<u8>>,
        private_key: Vec<u8>,
        algorithm_oid: ObjectIdentifier,
    },
}

impl Drop for PrivateKeyKind {
    fn drop(&mut self) {
        match self {
            PrivateKeyKind::Rsa => {}
            PrivateKeyKind::Ec { private_key, .. } => {
                private_key.zeroize();
            }
            PrivateKeyKind::Ed { private_key, .. } => {
                private_key.zeroize();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKey {
    /// Inner key details. This should never be puiblicly exposed.
    kind: PrivateKeyKind,
    /// Inner representation in Pkcs8 - using SecretDocument for secure storage
    inner: SecretDocument,
}

impl TryFrom<&'_ PrivateKey> for RsaPrivateKey {
    type Error = KeyError;

    fn try_from(v: &PrivateKey) -> Result<Self, Self::Error> {
        use picky_asn1_x509::{PrivateKey as ParsedPrivateKey, PrivateKeyInfoExt};

        let private_key_info = v.as_inner()?;

        match private_key_info.parse().map_err(|e| KeyError::from(e))? {
            ParsedPrivateKey::Rsa(rsa_key) => {
                // Convert from PKCS#1 RSA private key to rsa crate's RsaPrivateKey
                let p1 = BigUint::from_bytes_be(rsa_key.prime1.as_bytes());
                let p2 = BigUint::from_bytes_be(rsa_key.prime2.as_bytes());

                RsaPrivateKey::from_components(
                    BigUint::from_bytes_be(rsa_key.modulus.as_bytes()),
                    BigUint::from_bytes_be(rsa_key.public_exponent.as_bytes()),
                    BigUint::from_bytes_be(rsa_key.private_exponent.as_bytes()),
                    vec![p1, p2],
                )
                .map_err(|e| KeyError::Rsa {
                    context: format!("failed to construct private key from components: {e}"),
                })
            }
            _ => Err(KeyError::Rsa {
                context: "RSA private key cannot be constructed from non-RSA private key.".to_owned(),
            }),
        }
    }
}

impl TryFrom<&'_ PrivateKey> for RsaPublicKey {
    type Error = KeyError;

    fn try_from(v: &PrivateKey) -> Result<Self, Self::Error> {
        use picky_asn1_x509::{PrivateKey as ParsedPrivateKey, PrivateKeyInfoExt};

        let private_key_info = v.as_inner()?;

        match private_key_info.parse().map_err(|e| KeyError::from(e))? {
            ParsedPrivateKey::Rsa(rsa_key) => Ok(RsaPublicKey::new_with_max_size(
                BigUint::from_bytes_be(rsa_key.modulus.as_bytes()),
                BigUint::from_bytes_be(rsa_key.public_exponent.as_bytes()),
                8192,
            )?),
            _ => Err(KeyError::Rsa {
                context: "RSA public key cannot be constructed from non-RSA private key.".to_string(),
            }),
        }
    }
}

impl PrivateKey {
    pub fn from_rsa_components(
        modulus: &BigUint,
        public_exponent: &BigUint,
        private_exponent: &BigUint,
        primes: &[BigUint],
    ) -> Result<Self, KeyError> {
        use der::{asn1::UintRef, Encode};
        use picky_asn1_x509::oids;
        use pkcs1::RsaPrivateKey as Pkcs1RsaPrivateKey;
        use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};

        let mut primes_it = primes.iter();
        let prime_1 = primes_it.next().ok_or_else(|| KeyError::Rsa {
            context: format!("invalid number of primes provided: expected 2, got: {}", primes.len()),
        })?;
        let prime_2 = primes_it.next().ok_or_else(|| KeyError::Rsa {
            context: format!("invalid number of primes provided: expected 2, got: {}", primes.len()),
        })?;

        let exponent_1 = private_exponent.clone() % (prime_1 - 1u8);
        let exponent_2 = private_exponent.clone() % (prime_2 - 1u8);

        let coefficient = prime_2
            .mod_inverse(prime_1)
            .ok_or_else(|| KeyError::Rsa {
                context: "no modular inverse for prime 1".to_string(),
            })?
            .to_biguint()
            .ok_or_else(|| KeyError::Rsa {
                context: "BigUint conversion failed".to_string(),
            })?;

        // Create PKCS#1 RSA private key structure
        // Create byte arrays with sufficient lifetime
        let modulus_bytes = modulus.to_bytes_be();
        let public_exponent_bytes = public_exponent.to_bytes_be();
        let private_exponent_bytes = private_exponent.to_bytes_be();
        let prime_1_bytes = prime_1.to_bytes_be();
        let prime_2_bytes = prime_2.to_bytes_be();
        let exponent_1_bytes = exponent_1.to_bytes_be();
        let exponent_2_bytes = exponent_2.to_bytes_be();
        let coefficient_bytes = coefficient.to_bytes_be();

        let rsa_private_key = Pkcs1RsaPrivateKey {
            modulus: UintRef::new(&modulus_bytes).map_err(|source| KeyError::Asn1Serialization {
                source,
                element: "RSA modulus",
            })?,
            public_exponent: UintRef::new(&public_exponent_bytes).map_err(|source| {
                KeyError::Asn1Serialization {
                    source,
                    element: "RSA public exponent",
                }
            })?,
            private_exponent: UintRef::new(&private_exponent_bytes).map_err(|source| {
                KeyError::Asn1Serialization {
                    source,
                    element: "RSA private exponent",
                }
            })?,
            prime1: UintRef::new(&prime_1_bytes).map_err(|source| KeyError::Asn1Serialization {
                source,
                element: "RSA prime1",
            })?,
            prime2: UintRef::new(&prime_2_bytes).map_err(|source| KeyError::Asn1Serialization {
                source,
                element: "RSA prime2",
            })?,
            exponent1: UintRef::new(&exponent_1_bytes).map_err(|source| KeyError::Asn1Serialization {
                source,
                element: "RSA exponent1",
            })?,
            exponent2: UintRef::new(&exponent_2_bytes).map_err(|source| KeyError::Asn1Serialization {
                source,
                element: "RSA exponent2",
            })?,
            coefficient: UintRef::new(&coefficient_bytes).map_err(|source| KeyError::Asn1Serialization {
                source,
                element: "RSA coefficient",
            })?,
            other_prime_infos: None,
        };

        // Encode the PKCS#1 private key to DER.
        let rsa_private_key_der = rsa_private_key.to_der().map_err(|source| KeyError::Asn1Serialization {
            source,
            element: "PKCS#1 RSA private key",
        })?;

        // Create PKCS#8 PrivateKeyInfo.
        let algorithm = AlgorithmIdentifierRef {
            oid: oids::RSA_ENCRYPTION,
            parameters: None,
        };

        let private_key_info = PrivateKeyInfo {
            algorithm,
            private_key: &rsa_private_key_der,
            public_key: None,
        };

        // Encode to PKCS#8 DER and create SecretDocument.
        let inner = SecretDocument::encode_msg(&private_key_info).map_err(|source| KeyError::Asn1Deserialization {
            source,
            element: "SecretDocument",
        })?;

        Ok(Self {
            kind: PrivateKeyKind::Rsa,
            inner,
        })
    }

    /// Builds new EC key from given components. Note that only curves, declared in [`EcCurve`]
    /// are supported for key generation.
    pub fn from_ec_components(
        curve: EcCurve,
        secret: &BigUint,
        point_x: &BigUint,
        point_y: &BigUint,
    ) -> Result<Self, KeyError> {
        use p256::elliptic_curve::generic_array::GenericArray as GenericArrayP256;
        use p256::EncodedPoint as EncodedPointP256;

        use p384::elliptic_curve::generic_array::GenericArray as GenericArrayP384;
        use p384::EncodedPoint as EncodedPointP384;

        use p521::elliptic_curve::generic_array::GenericArray as GenericArrayP521;
        use p521::EncodedPoint as EncodedPointP521;

        let curve_oid: ObjectIdentifier = NamedEcCurve::Known(curve).into();
        let px_bytes = expand_ec_field(point_x.to_bytes_be(), curve);
        let py_bytes = expand_ec_field(point_y.to_bytes_be(), curve);

        let px_validated = curve.validate_component(EcComponent::PointX(&px_bytes))?;
        let py_validated = curve.validate_component(EcComponent::PointY(&py_bytes))?;

        let point_bytes = match curve {
            EcCurve::NistP256 => {
                let x = GenericArrayP256::from_slice(px_validated);
                let y = GenericArrayP256::from_slice(py_validated);
                let point = EncodedPointP256::from_affine_coordinates(x, y, COMPRESS_EC_POINT_BY_DEFAULT);
                point.as_bytes().to_vec()
            }
            EcCurve::NistP384 => {
                let x = GenericArrayP384::from_slice(px_validated);
                let y = GenericArrayP384::from_slice(py_validated);
                let point = EncodedPointP384::from_affine_coordinates(x, y, COMPRESS_EC_POINT_BY_DEFAULT);
                point.as_bytes().to_vec()
            }
            EcCurve::NistP521 => {
                let x = GenericArrayP521::from_slice(px_validated);
                let y = GenericArrayP521::from_slice(py_validated);
                let point = EncodedPointP521::from_affine_coordinates(x, y, COMPRESS_EC_POINT_BY_DEFAULT);
                point.as_bytes().to_vec()
            }
        };

        let secret = secret.to_bytes_be();

        // Create EC private key structure and serialize to DER
        let ec_private_key = sec1::EcPrivateKey {
            private_key: &secret,
            parameters: Some(sec1::EcParameters::NamedCurve(curve_oid.clone())),
            public_key: Some(der::asn1::BitString::from_bytes(point_bytes.as_slice()).unwrap()),
        };
        
        let ec_der = ec_private_key.to_der().map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "EC private key",
        })?;

        // Create PKCS#8 DER and SecretDocument
        let pkcs8_params = der::asn1::Any::new(der::Tag::ObjectIdentifier, curve_oid.as_bytes())
            .map_err(|e| KeyError::Asn1Serialization {
                source: e,
                element: "EC curve parameters",
            })?;
        
        let pkcs8_pki = pkcs8::PrivateKeyInfo {
            algorithm: spki::AlgorithmIdentifierRef {
                oid: oids::EC_PUBLIC_KEY,
                parameters: Some(pkcs8_params.into()),
            },
            private_key: &ec_der,
            public_key: None,
        };

        let pkcs8_der = pkcs8_pki.to_der().map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "PKCS#8 private key info",
        })?;

        let inner = SecretDocument::from_der(&pkcs8_der).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "SecretDocument",
        })?;

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key: Some(point_bytes),
            private_key: secret,
        };

        Ok(Self { kind, inner })
    }

    /// Infallible method to create new EC key from given components. Note that no checks performed
    /// on the validity of the secret and point bytes representation in regards to selected
    /// curve oid.
    pub fn from_ec_encoded_components(curve_oid: ObjectIdentifier, secret: &[u8], point: Option<&[u8]>) -> Self {
        let inner = {
            use pkcs8::PrivateKeyInfo;
            use der::Encode;
            
            // Create EC private key structure  
            let ec_private_key = sec1::EcPrivateKey {
                private_key: secret,
                parameters: Some(sec1::EcParameters::NamedCurve(curve_oid.clone())),
                public_key: point.map(|p| der::asn1::BitString::from_bytes(p).unwrap()),
            };
            
            let ec_der = ec_private_key.to_der().unwrap();
            
            PrivateKeyInfo {
                algorithm: spki::AlgorithmIdentifier {
                    oid: oids::EC_PUBLIC_KEY,
                    parameters: Some(der::asn1::Any::new(der::Tag::ObjectIdentifier, curve_oid.as_bytes()).unwrap()),
                },
                private_key: &ec_der,
                public_key: None,
            }
        };

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key: point.map(|point| point.to_vec()),
            private_key: secret.to_vec(),
        };

        Self { kind, inner }
    }

    pub fn from_ed_encoded_components(
        algorithm_oid: ObjectIdentifier,
        secret: &[u8],
        public_key: Option<&[u8]>,
    ) -> Self {
        let public_key_bit_string = public_key.map(|p| BitString::from_bytes(&p).unwrap());

        let inner = {
            use pkcs8::PrivateKeyInfo;
            
            PrivateKeyInfo {
                algorithm: spki::AlgorithmIdentifier {
                    oid: algorithm_oid.clone(),
                    parameters: None,
                },
                private_key: secret,
                public_key: public_key_bit_string.as_ref().map(|bs| bs.as_bytes()),
            }
        };

        let kind = PrivateKeyKind::Ed {
            algorithm_oid,
            public_key: public_key.map(|key| key.to_vec()),
            private_key: secret.to_vec(),
        };

        Self { kind, inner }
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, KeyError> {
        match pem.label() {
            PRIVATE_KEY_PEM_LABEL => Self::from_pkcs8(pem.data()),
            RSA_PRIVATE_KEY_PEM_LABEL => Self::from_pkcs1(pem.data()),
            EC_PRIVATE_KEY_LABEL => Self::from_ec_der(pem.data()),
            _ => Err(KeyError::InvalidPemLabel {
                label: pem.label().to_owned(),
            }),
        }
    }

    pub fn from_pem_str(pem_str: &str) -> Result<Self, KeyError> {
        let pem = parse_pem(pem_str)?;
        Self::from_pem(&pem)
    }

    pub fn from_pkcs8<T: ?Sized + AsRef<[u8]>>(pkcs8: &T) -> Result<Self, KeyError> {
        use picky_asn1_x509::{PrivateKey as ParsedPrivateKey, PrivateKeyInfoExt};

        // Create SecretDocument from PKCS#8 DER data
        let secret_doc = SecretDocument::from_der(pkcs8.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "private key info (pkcs8)",
        })?;

        // Parse the private key info to determine type
        let private_key_info =
            PrivateKeyInfo::from_der(secret_doc.as_bytes()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "private key info parsing",
            })?;

        match private_key_info.parse().map_err(|e| KeyError::from(e))? {
            ParsedPrivateKey::Rsa(_) => Ok(Self {
                kind: PrivateKeyKind::Rsa,
                inner: secret_doc,
            }),
            ParsedPrivateKey::Ec(ec_key) => {
                // Extract curve OID from algorithm parameters
                let curve_oid =
                    match private_key_info.algorithm.parameters {
                        Some(params) => {
                            // Try to decode as EC parameters - this is a simplified approach
                            // In a full implementation, we'd properly decode the parameters
                            match private_key_info.algorithm.oid {
                                oids::EC_PUBLIC_KEY => {
                                    // For now, we'll extract from the parsed key or use a default
                                    // This would need proper parameter parsing in a complete implementation
                                    ec_key.parameters.map(|p| p.named_curve()).flatten().ok_or_else(|| {
                                        KeyError::Ec {
                                            context: "Missing or unsupported EC curve parameters".to_string(),
                                        }
                                    })?
                                }
                                _ => {
                                    return Err(KeyError::Ec {
                                        context: "Invalid EC algorithm OID".to_string(),
                                    })
                                }
                            }
                        }
                        None => {
                            return Err(KeyError::Ec {
                                context: "Missing EC algorithm parameters".to_string(),
                            })
                        }
                    };

                // Extract public and private key components
                let private_key = ec_key.private_key.to_vec();
                let public_key = ec_key.public_key.map(|pk| pk.raw_bytes().to_vec());

                Ok(Self {
                    kind: PrivateKeyKind::Ec {
                        curve_oid,
                        public_key,
                        private_key,
                    },
                    inner: secret_doc,
                })
            }
            ParsedPrivateKey::Ed(ed_key) => {
                let algorithm_oid = private_key_info.algorithm.oid;
                let algorithm = NamedEdAlgorithm::from(&algorithm_oid);
                let private_key = ed_key.as_bytes().to_vec();

                let public_key = match &algorithm {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => {
                        let private_key_bytes = private_key.as_slice().try_into().map_err(|e| KeyError::Ed {
                            context: format!("invalid size for Ed25519 private key: {e}"),
                        })?;
                        let private_key = ed25519_dalek::SigningKey::from_bytes(private_key_bytes);
                        let public_key = private_key.verifying_key();
                        Some(public_key.to_bytes().to_vec())
                    }
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                        let len = private_key.len();
                        let secret: X25519FieldElement =
                            private_key.as_slice().try_into().map_err(|_| KeyError::Ed {
                                context: format!(
                                "Invalid X25519 private key size. Expected: {X25519_FIELD_ELEMENT_SIZE}, actual: {len}"
                            ),
                            })?;
                        let secret = x25519_dalek::StaticSecret::from(secret);
                        let public_key = x25519_dalek::PublicKey::from(&secret);
                        Some(public_key.to_bytes().to_vec())
                    }
                    NamedEdAlgorithm::Unsupported(_) => {
                        // We can't generate public key from private key for unsupported algorithms
                        None
                    }
                };

                Ok(Self {
                    kind: PrivateKeyKind::Ed {
                        algorithm_oid,
                        public_key,
                        private_key,
                    },
                    inner: secret_doc,
                })
            }
        }
    }

    /// Decodes a DER-encoded RSA private key
    pub fn from_pkcs1<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use der::Encode;
        use pkcs1::RsaPrivateKey as Pkcs1RsaPrivateKey;

        // Parse the PKCS#1 RSA private key
        use der::Decode;
        let pkcs1_key = Pkcs1RsaPrivateKey::from_der(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "rsa private key",
        })?;

        // Create PKCS#8 PrivateKeyInfo
        let algorithm = AlgorithmIdentifierRef {
            oid: oids::RSA_ENCRYPTION,
            parameters: None,
        };

        let private_key_info = PrivateKeyInfo {
            algorithm,
            private_key: der.as_ref(),
            public_key: None,
        };

        // Encode to PKCS#8 DER and create SecretDocument
        let pkcs8_der = private_key_info.to_der().map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "PKCS#8 private key info",
        })?;

        let inner = SecretDocument::from_der(&pkcs8_der).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "SecretDocument",
        })?;

        Ok(Self {
            kind: PrivateKeyKind::Rsa,
            inner,
        })
    }

    /// Loads an EC private key from a DER-encoded private key with supported curve. Also see
    /// [`Self::from_ec_der_with_curve_oid`] for loading keys with unsupported curves.
    pub fn from_ec_der_with_curve<T: ?Sized + AsRef<[u8]>>(der: &T, curve: EcCurve) -> Result<Self, KeyError> {
        Self::from_ec_der_with_curve_oid(der, NamedEcCurve::Known(curve).into())
    }

    /// Internal method to load an EC private key from ASN.1 structure [`ECPrivateKey`] and the
    /// given curve OID. (Curve id is required as [`ECPrivateKey`] does not guarantee that the
    /// cureve parameters are present). If public key is absent in the ASN.1 structure, it will be
    /// calculated from the private key (Only if curve is supported. In other case - throws error)
    fn from_ec_decoded_der_with_curve_oid(
        curve_oid: ObjectIdentifier,
        decoded: &EcPrivateKey,
    ) -> Result<Self, KeyError> {
        // Generate the public key if it's not present in the `EcPrivateKey` representation
        let (public_key, public_key_is_generated) = match decoded.public_key {
            Some(public_key_bytes) => (Some(public_key_bytes.to_vec()), false),
            None => (
                calculate_public_ec_key(&curve_oid, decoded.private_key, COMPRESS_EC_POINT_BY_DEFAULT)?,
                true,
            ),
        };
        let private_key = decoded.private_key.to_vec();
        // if the public key is generated, we need to skip it when encoding, to preserve the
        // original `ECPrivateKey` structure in encoded representation
        let public_key_encoded = public_key
            .as_deref()
            .and_then(|public_key| (!public_key_is_generated).then(|| BitString::from_bytes(&public_key).unwrap()));
        // if the parameters are missing during parsing, we need to skip them when encoding
        let der_skip_parameters = decoded.parameters.is_none();

        // Create PKCS#8 PrivateKeyInfo for EC key
        use der::Encode;

        let algorithm = AlgorithmIdentifierRef {
            oid: oids::EC_PUBLIC_KEY,
            parameters: Some(der::asn1::AnyRef::new(curve_oid.as_bytes()).map_err(|e| {
                KeyError::Asn1Serialization {
                    source: e,
                    element: "EC curve OID parameters",
                }
            })?),
        };

        // For EC keys, the private key data in PKCS#8 is the SEC1 EcPrivateKey structure
        let sec1_der = decoded.to_der().map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "SEC1 EC private key",
        })?;

        let private_key_info = PrivateKeyInfo {
            algorithm,
            private_key: &sec1_der,
            public_key: None,
        };

        // Encode to PKCS#8 DER and create SecretDocument
        let pkcs8_der = private_key_info.to_der().map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "PKCS#8 private key info",
        })?;

        let inner = SecretDocument::from_der(&pkcs8_der).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "SecretDocument",
        })?;

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key,
            private_key,
        };

        Ok(Self { kind, inner })
    }

    /// Same as [`Self::from_ec_der_with_curve`], but with manually specified curve OID. Arithmetic
    /// operations are not available for unknown curves, but this method allows to load key from
    /// DER-encoded data to perfor non-arithmetic operations like extracting public key or
    /// re-encoding into pkcs8.
    pub fn from_ec_der_with_curve_oid<T: ?Sized + AsRef<[u8]>>(
        der: &T,
        curve_oid: ObjectIdentifier,
    ) -> Result<Self, KeyError> {
        use der::Decode;
        let private_key = EcPrivateKey::from_der(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "ec private key",
        })?;

        Self::from_ec_decoded_der_with_curve_oid(curve_oid, &private_key)
    }

    /// Returns the private key as a DER-encoded EC private key. Note that generally, DER-encoded
    /// EC keys do not contain the curve parameters, so this method will return if it cannot find
    /// such parameters.
    ///
    /// Usually, EC keys are encoded in PKCS#8 format, which contain all required
    /// information to reconstruct the key. See [`Self::from_pkcs8`]
    ///
    /// However, if the key is encoded in the DER format, and the curve parameters are missing, you
    /// could load it via [`Self::from_ec_der_with_curve`] and specify the curve manually.
    ///
    /// Also, if public key is absent is missing in the parsed file, it will be calculated from the
    /// private key (Only if curve is supported. In other case - throws error)
    pub fn from_ec_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use der::Decode;
        let private_key = EcPrivateKey::from_der(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "ec private key",
        })?;

        // By specification (https://www.rfc-editor.org/rfc/rfc5915) `parameters` files SHOULD
        // be present when EC key is encoded as standalone DER. However, some implementations
        // do not include parameters, so we have to check for that.
        let curve_oid = match &private_key.parameters.0 .0 {
            Some(params) => params.curve_oid().clone(),
            None => {
                return Err(KeyError::Ec {
                    context: "EC parameters are missing from DER-encoded private key".into(),
                });
            }
        };

        Self::from_ec_decoded_der_with_curve_oid(curve_oid, &private_key)
    }

    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.inner.as_bytes().to_vec())
    }

    pub fn to_pkcs1(&self) -> Result<Vec<u8>, KeyError> {
        use picky_asn1_x509::{PrivateKey as ParsedPrivateKey, PrivateKeyInfoExt};

        // First check if this is an RSA key
        match self.kind {
            PrivateKeyKind::Rsa => {
                let private_key_info = self.as_inner()?;
                match private_key_info.parse().map_err(|e| KeyError::from(e))? {
                    ParsedPrivateKey::Rsa(rsa_key) => {
                        // Re-encode the RSA private key to DER (PKCS#1)
                        use der::Encode;
                        rsa_key.to_der().map_err(|e| KeyError::Asn1Serialization {
                            source: e,
                            element: "RSA private key (pkcs1)",
                        })
                    }
                    _ => Err(KeyError::Rsa {
                        context: String::from("invalid RSA key structure"),
                    }),
                }
            }
            _ => Err(KeyError::Rsa {
                context: String::from("can't export a non-RSA key to PKCS#1 format"),
            }),
        }
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, KeyError> {
        let pkcs8 = self.to_pkcs8()?;
        Ok(Pem::new(PRIVATE_KEY_PEM_LABEL, pkcs8))
    }

    pub fn to_pem_str(&self) -> Result<String, KeyError> {
        self.to_pem().map(|pem| pem.to_string())
    }

    pub fn to_pkcs1_pem(&self) -> Result<Pem<'static>, KeyError> {
        let pkcs1 = self.to_pkcs1()?;
        Ok(Pem::new(RSA_PRIVATE_KEY_PEM_LABEL, pkcs1))
    }

    pub fn to_pkcs1_pem_str(&self) -> Result<String, KeyError> {
        self.to_pkcs1_pem().map(|pem| pem.to_string())
    }

    pub fn to_public_key(&self) -> Result<PublicKey, KeyError> {
        use der::{asn1::BitString, Encode};
        use picky_asn1_x509::{PrivateKey as ParsedPrivateKey, PrivateKeyInfoExt};
        use spki::SubjectPublicKeyInfo;

        match &self.kind {
            PrivateKeyKind::Rsa => {
                let private_key_info = self.as_inner()?;
                match private_key_info.parse().map_err(|e| KeyError::from(e))? {
                    ParsedPrivateKey::Rsa(rsa_key) => {
                        // Create RSA public key from private key components
                        let rsa_public_key = pkcs1::RsaPublicKey {
                            modulus: rsa_key.modulus,
                            public_exponent: rsa_key.public_exponent,
                        };

                        let public_key_der = rsa_public_key.to_der().map_err(|e| KeyError::Asn1Serialization {
                            source: e,
                            element: "RSA public key",
                        })?;

                        let spki = SubjectPublicKeyInfo {
                            algorithm: AlgorithmIdentifierRef {
                                oid: oids::RSA_ENCRYPTION,
                                parameters: None,
                            },
                            subject_public_key: &public_key_der,
                        };

                        Ok(PublicKey::from(spki))
                    }
                    _ => Err(KeyError::Rsa {
                        context: "Invalid RSA key structure".to_string(),
                    }),
                }
            }
            PrivateKeyKind::Ec {
                public_key, curve_oid, ..
            } => match public_key {
                Some(data) => {
                    let spki = SubjectPublicKeyInfo {
                        algorithm: AlgorithmIdentifierRef {
                            oid: oids::EC_PUBLIC_KEY,
                            parameters: Some(der::asn1::AnyRef::new(curve_oid.as_bytes()).map_err(|e| {
                                KeyError::Asn1Serialization {
                                    source: e,
                                    element: "EC curve OID parameters",
                                }
                            })?),
                        },
                        subject_public_key: data.as_slice(),
                    };

                    Ok(PublicKey::from(spki))
                }
                None => Err(KeyError::Ec {
                    context: "Public key can't be calculated for unknown EC algorithms".into(),
                }),
            },
            PrivateKeyKind::Ed {
                public_key,
                algorithm_oid,
                ..
            } => match public_key {
                Some(data) => {
                    let spki = SubjectPublicKeyInfo {
                        algorithm: AlgorithmIdentifierRef {
                            oid: *algorithm_oid,
                            parameters: None,
                        },
                        subject_public_key: data.as_slice(),
                    };

                    Ok(PublicKey::from(spki))
                }
                None => Err(KeyError::Ed {
                    context: "Public key can't be calculated for unknown edwards curves-based algorithms".into(),
                }),
            },
        }
    }

    /// **Beware**: this is insanely slow in debug builds.
    pub fn generate_rsa(bits: usize) -> Result<Self, KeyError> {
        use rand::rngs::OsRng;

        let key = RsaPrivateKey::new(&mut OsRng, bits)?;

        let modulus = key.n();
        let public_exponent = key.e();
        let private_exponent = key.d();

        Self::from_rsa_components(modulus, public_exponent, private_exponent, key.primes())
    }

    /// Generates new ec key pair with specified supported curve.
    pub fn generate_ec(curve: EcCurve) -> Result<Self, KeyError> {
        use rand::rngs::OsRng;

        let curve_oid: ObjectIdentifier = NamedEcCurve::Known(curve).into();

        let (secret, point) = match curve {
            EcCurve::NistP256 => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;

                let key = p256::SecretKey::random(&mut OsRng);
                let secret = key.to_bytes().to_vec();
                let point = key
                    .public_key()
                    .to_encoded_point(COMPRESS_EC_POINT_BY_DEFAULT)
                    .as_bytes()
                    .to_vec();
                (secret, point)
            }
            EcCurve::NistP384 => {
                use p384::elliptic_curve::sec1::ToEncodedPoint;

                let key = p384::SecretKey::random(&mut OsRng);
                let secret = key.to_bytes().to_vec();
                let point = key
                    .public_key()
                    .to_encoded_point(COMPRESS_EC_POINT_BY_DEFAULT)
                    .as_bytes()
                    .to_vec();
                (secret, point)
            }
            EcCurve::NistP521 => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;

                let key = p521::SecretKey::random(&mut OsRng);
                let secret = key.to_bytes().to_vec();
                let point = key
                    .public_key()
                    .to_encoded_point(COMPRESS_EC_POINT_BY_DEFAULT)
                    .as_bytes()
                    .to_vec();
                (secret, point)
            }
        };

        let inner = PrivateKeyInfo::new_ec_encryption(
            curve_oid.clone(),
            secret.clone(),
            Some(BitString::from_bytes(point.as_slice()).unwrap()),
            false,
        );

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key: Some(point),
            private_key: secret,
        };

        Ok(Self { kind, inner })
    }

    /// Generates new ed key pair with specified supported algorithm.
    ///
    /// `write_public_key` specifies whether to include public key in the private key file.
    /// Note that OpenSSL does not support ed keys with public key included.
    pub fn generate_ed(algorithm: EdAlgorithm, write_public_key: bool) -> Result<Self, KeyError> {
        use rand::rngs::OsRng;

        let algorithm_oid: ObjectIdentifier = NamedEdAlgorithm::Known(algorithm).into();

        let (private_key, public_key) = match algorithm {
            EdAlgorithm::Ed25519 => {
                let private = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let public = private.verifying_key();
                (private.to_bytes().to_vec(), public.to_bytes().to_vec())
            }
            EdAlgorithm::X25519 => {
                let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                let public = x25519_dalek::PublicKey::from(&private);
                (private.to_bytes().to_vec(), public.to_bytes().to_vec())
            }
        };

        let public_key_bit_string = write_public_key.then(|| BitString::from_bytes(public_key.as_slice()).unwrap());

        let inner = {
            use pkcs8::PrivateKeyInfo;
            
            PrivateKeyInfo {
                algorithm: spki::AlgorithmIdentifier {
                    oid: algorithm_oid.clone(),
                    parameters: None,
                },
                private_key: &private_key,
                public_key: public_key_bit_string.as_ref().map(|bs| bs.as_bytes()),
            }
        };

        let kind = PrivateKeyKind::Ed {
            algorithm_oid,
            public_key: Some(public_key),
            private_key,
        };

        Ok(Self { kind, inner })
    }

    pub fn kind(&self) -> KeyKind {
        match self.kind {
            PrivateKeyKind::Rsa => KeyKind::Rsa,
            PrivateKeyKind::Ec { .. } => KeyKind::Ec,
            PrivateKeyKind::Ed { .. } => KeyKind::Ed,
        }
    }

    pub(crate) fn as_inner(&self) -> Result<PrivateKeyInfo<'_>, KeyError> {
        PrivateKeyInfo::from_der(self.inner.as_bytes()).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "private key info",
        })
    }

    #[cfg(any(feature = "ssh", feature = "jose"))]
    pub(crate) fn as_kind(&self) -> &PrivateKeyKind {
        &self.kind
    }
}

// === public key === //

const PUBLIC_KEY_PEM_LABEL: &str = "PUBLIC KEY";
const RSA_PUBLIC_KEY_PEM_LABEL: &str = "RSA PUBLIC KEY";
const EC_PUBLIC_KEY_PEM_LABEL: &str = "EC PUBLIC KEY";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// DER-encoded SubjectPublicKeyInfo
    inner: Vec<u8>,
}

// Note: This conversion is not possible with the new inner Vec<u8> structure
// Users should use PublicKey::from(spki.clone()) instead

// Note: This conversion is not possible with the new inner Vec<u8> structure
// Users should use key.as_inner() instead

impl<Params, Key> From<spki::SubjectPublicKeyInfo<Params, Key>> for PublicKey
where
    spki::SubjectPublicKeyInfo<Params, Key>: der::Encode,
{
    #[inline]
    fn from(spki: spki::SubjectPublicKeyInfo<Params, Key>) -> Self {
        use der::Encode;
        let inner = spki.to_der().expect("failed to encode SPKI");
        Self { inner }
    }
}

impl From<PublicKey> for SubjectPublicKeyInfoOwned {
    #[inline]
    fn from(key: PublicKey) -> Self {
        use der::Decode;
        SubjectPublicKeyInfoOwned::from_der(&key.inner).expect("failed to decode SPKI")
    }
}
impl TryFrom<PrivateKey> for PublicKey {
    type Error = KeyError;

    #[inline]
    fn try_from(key: PrivateKey) -> Result<Self, Self::Error> {
        key.to_public_key()
    }
}

// Note: AsRef<SubjectPublicKeyInfo> is not directly possible with new structure
// Users should use as_inner() method instead

impl AsRef<PublicKey> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &PublicKey {
        self
    }
}

impl TryFrom<&'_ PublicKey> for RsaPublicKey {
    type Error = KeyError;

    fn try_from(v: &PublicKey) -> Result<Self, Self::Error> {
        use picky_asn1_x509::{PublicKey as ParsedPublicKey};

        let spki = v.as_inner()?;

        match picky_asn1_x509::parse_subject_public_key_info(&spki).map_err(|e| KeyError::from(e))? {
            ParsedPublicKey::Rsa(rsa_key) => {
                // Use the already parsed PKCS#1 RSA public key
                Ok(RsaPublicKey::new_with_max_size(
                    BigUint::from_bytes_be(rsa_key.modulus.as_bytes()),
                    BigUint::from_bytes_be(rsa_key.public_exponent.as_bytes()),
                    8192,
                )?)
            }
            _ => Err(KeyError::UnsupportedAlgorithm {
                algorithm: "only RSA keys are supported in this context",
            }),
        }
    }
}

impl PublicKey {
    pub(crate) fn as_inner(&self) -> Result<spki::SubjectPublicKeyInfo<der::asn1::AnyRef<'_>, der::asn1::BitStringRef<'_>>, KeyError> {
        use der::Decode;
        spki::SubjectPublicKeyInfo::from_der(&self.inner).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "SubjectPublicKeyInfo",
        })
    }

    pub fn from_rsa_components(modulus: &BigUint, public_exponent: &BigUint) -> Self {
        use der::asn1::{Any, Null, UintRef};
        use der::Encode;
        use picky_asn1_x509::AlgorithmIdentifier;
        use spki::SubjectPublicKeyInfo;

        // Create PKCS#1 RSA public key
        let modulus_bytes = modulus.to_bytes_be();
        let public_exp_bytes = public_exponent.to_bytes_be();

        let rsa_key = pkcs1::RsaPublicKey {
            modulus: UintRef::new(&modulus_bytes).unwrap(),
            public_exponent: UintRef::new(&public_exp_bytes).unwrap(),
        };

        let rsa_key_der = rsa_key.to_der().unwrap();

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: picky_asn1_x509::oids::RSA_ENCRYPTION,
                parameters: Some(Any::from(Null)),
            },
            subject_public_key: der::asn1::BitString::from_bytes(&rsa_key_der).unwrap(),
        };

        let inner = spki.to_der().unwrap();
        Self { inner }
    }

    /// `point` is SEC1 encoded point data
    pub fn from_ec_encoded_components(curve: &ObjectIdentifier, point: &[u8]) -> Self {
        use der::asn1::Any;
        use der::Encode;
        use picky_asn1_x509::AlgorithmIdentifier;
        use spki::SubjectPublicKeyInfo;

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: picky_asn1_x509::oids::EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(curve).unwrap()),
            },
            subject_public_key: der::asn1::BitString::from_bytes(point).unwrap(),
        };

        let inner = spki.to_der().unwrap();
        Self { inner }
    }

    /// `public_key` is raw edwards curve public key
    pub fn from_ed_encoded_components(algorithm: &ObjectIdentifier, public_key: &[u8]) -> Self {
        use der::Encode;
        use picky_asn1_x509::AlgorithmIdentifier;
        use spki::SubjectPublicKeyInfo;

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifier {
                oid: *algorithm,
                parameters: None,
            },
            subject_public_key: der::asn1::BitString::from_bytes(public_key).unwrap(),
        };

        let inner = spki.to_der().unwrap();
        Self { inner }
    }

    /// Creates public key from its raw components. Only curves declared in [`EcCurve`] are
    /// supported. For correct encoding of the point, we need to know which curve-specific
    /// arithmetic crate to use. If you want to use a curve that is not declared in [`EcCurve`],
    /// and encoded representation of the point is available - use [`Self::from_ec_encoded_components`]
    pub fn from_ec_components(curve: EcCurve, x: &BigUint, y: &BigUint) -> Result<Self, KeyError> {
        let px_bytes = expand_ec_field(x.to_bytes_be(), curve);
        let py_bytes = expand_ec_field(y.to_bytes_be(), curve);

        let px_validated = curve.validate_component(EcComponent::PointX(&px_bytes))?;
        let py_validated = curve.validate_component(EcComponent::PointY(&py_bytes))?;

        match curve {
            EcCurve::NistP256 => {
                use p256::elliptic_curve::generic_array::GenericArray as GenericArrayP256;

                let p = p256::EncodedPoint::from_affine_coordinates(
                    GenericArrayP256::from_slice(px_validated),
                    GenericArrayP256::from_slice(py_validated),
                    COMPRESS_EC_POINT_BY_DEFAULT,
                );

                Ok(Self::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    p.as_bytes(),
                ))
            }
            EcCurve::NistP384 => {
                use p256::elliptic_curve::generic_array::GenericArray as GenericArrayP384;

                let p = p384::EncodedPoint::from_affine_coordinates(
                    GenericArrayP384::from_slice(px_validated),
                    GenericArrayP384::from_slice(py_validated),
                    COMPRESS_EC_POINT_BY_DEFAULT,
                );

                Ok(Self::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    p.as_bytes(),
                ))
            }
            EcCurve::NistP521 => {
                use p521::elliptic_curve::generic_array::GenericArray as GenericArrayP521;

                let p = p521::EncodedPoint::from_affine_coordinates(
                    GenericArrayP521::from_slice(px_validated),
                    GenericArrayP521::from_slice(py_validated),
                    COMPRESS_EC_POINT_BY_DEFAULT,
                );

                Ok(Self::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    p.as_bytes(),
                ))
            }
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.inner.clone())
    }

    pub fn to_pkcs1(&self) -> Result<Vec<u8>, KeyError> {
        use der::Encode;

        let spki = self.as_inner()?;
        match picky_asn1_x509::parse_subject_public_key_info(&spki).map_err(|e| KeyError::from(e))? {
            picky_asn1_x509::PublicKey::Rsa(rsa_key) => {
                // Re-encode the RSA public key to DER
                rsa_key.to_der().map_err(|e| KeyError::Asn1Serialization {
                    source: e,
                    element: "RSA public key",
                })
            }
            _ => Err(KeyError::Rsa {
                context: String::from("can't export a non-RSA key to PKCS#1 format"),
            }),
        }
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, KeyError> {
        let der = self.to_der()?;
        Ok(Pem::new(PUBLIC_KEY_PEM_LABEL, der))
    }

    pub fn to_pem_str(&self) -> Result<String, KeyError> {
        self.to_pem().map(|pem| pem.to_string())
    }

    pub fn to_pkcs1_pem(&self) -> Result<Pem<'static>, KeyError> {
        let pkcs1 = self.to_pkcs1()?;
        Ok(Pem::new(RSA_PUBLIC_KEY_PEM_LABEL, pkcs1))
    }

    pub fn to_pkcs1_pem_str(&self) -> Result<String, KeyError> {
        self.to_pkcs1_pem().map(|pem| pem.to_string())
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, KeyError> {
        match pem.label() {
            PUBLIC_KEY_PEM_LABEL | EC_PUBLIC_KEY_PEM_LABEL => Self::from_der(pem.data()),
            RSA_PUBLIC_KEY_PEM_LABEL => Self::from_pkcs1(pem.data()),
            _ => Err(KeyError::InvalidPemLabel {
                label: pem.label().to_owned(),
            }),
        }
    }

    pub fn from_pem_str(pem_str: &str) -> Result<Self, KeyError> {
        let pem = parse_pem(pem_str)?;
        Self::from_pem(&pem)
    }

    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use der::Decode;

        // Validate by parsing
        let _spki: spki::SubjectPublicKeyInfo<der::asn1::AnyRef, der::asn1::BitStringRef> =
            spki::SubjectPublicKeyInfo::from_der(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "subject public key info",
            })?;

        Ok(Self {
            inner: der.as_ref().to_vec(),
        })
    }

    pub fn from_pkcs1<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use der::asn1::{Any, Null};
        use der::{Decode, Encode};
        use picky_asn1_x509::AlgorithmIdentifier;
        use spki::SubjectPublicKeyInfo;

        // Parse the PKCS#1 RSA public key to validate it
        let _public_key = pkcs1::RsaPublicKey::from_der(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "rsa public key",
        })?;

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: picky_asn1_x509::oids::RSA_ENCRYPTION,
                parameters: Some(Any::from(Null)),
            },
            subject_public_key: der::asn1::BitString::from_bytes(der.as_ref()).map_err(|e| {
                KeyError::Asn1Deserialization {
                    source: e,
                    element: "bit string",
                }
            })?,
        };

        let inner = spki.to_der().map_err(|e| KeyError::Asn1Deserialization {
            source: e,
            element: "subject public key info",
        })?;

        Ok(Self { inner })
    }

    pub fn kind(&self) -> KeyKind {
        use picky_asn1_x509::parse_subject_public_key_info;

        match self.as_inner() {
            Ok(spki) => {
                match parse_subject_public_key_info(&spki) {
                    Ok(parsed) => match parsed {
                        picky_asn1_x509::PublicKey::Rsa(_) => KeyKind::Rsa,
                        picky_asn1_x509::PublicKey::Ec(_) => KeyKind::Ec,
                        picky_asn1_x509::PublicKey::Ed(_) => KeyKind::Ed,
                    }
                    Err(_) => KeyKind::Unknown,
                }
            }
            Err(_) => KeyKind::Unknown,
        }
    }
}

/// EC field's BigUint -> bytes conversion does not include leading zeros, therefore we need to
/// expand the bytes to the curve's field size.
fn expand_ec_field(bytes: Vec<u8>, curve: EcCurve) -> Vec<u8> {
    match curve.field_bytes_size().checked_sub(bytes.len()) {
        None | Some(0) => bytes,
        Some(leading_zeros) => {
            let mut expanded = Vec::with_capacity(curve.field_bytes_size());
            expanded.resize(leading_zeros, 0x00);
            expanded.extend(bytes);
            expanded
        }
    }
}

#[cfg(test)]
mod tests {
    use rsa::traits::PublicKeyParts;
    use rstest::rstest;

    use super::*;
    use crate::hash::HashAlgorithm;
    use crate::key::ed::EdKeypair;
    use crate::signature::SignatureAlgorithm;

    cfg_if::cfg_if! { if #[cfg(feature = "x509")] {
        use picky_asn1_x509::NameExt as _;
        use x509_cert::name::Name;

        use crate::x509::{certificate::CertificateBuilder, date::UtcDate};

        fn generate_certificate_from_pk(private_key: PrivateKey) {
            let valid_from = UtcDate::new(2019, 10, 10, 0, 0, 0).unwrap();
            let valid_to = UtcDate::new(2019, 10, 11, 0, 0, 0).unwrap();

            CertificateBuilder::new()
                .validity(valid_from, valid_to)
                .self_signed(Name::new_common_name("Test Root CA"), &private_key)
                .ca(true)
                .build()
                .expect("couldn't build root ca");
        }
    } else {
        fn generate_certificate_from_pk(_: PrivateKey) {}
    }}

    /// Generating RSA keys in debug is very slow. Therefore, this test is ignored in debug builds
    #[test]
    #[cfg_attr(debug_assertions, ignore)]
    fn generate_rsa_key() {
        let private_key = PrivateKey::generate_rsa(4096).expect("couldn't generate rsa key");
        generate_certificate_from_pk(private_key);
    }

    const PKCS1_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
                            MIIEpAIBAAKCAQEA5Kz4i/+XZhiE+fyrgtx/4yI3i6C6HXbC4QJYpDuSUEKN2bO9\n\
                            RsE+Fnds/FizHtJVWbvya9ktvKdDPBdy58+CIM46HEKJhYLnBVlkEcg9N2RNgR3x\n\
                            HnpRbKfv+BmWjOpSmWrmJSDLY0dbw5X5YL8TU69ImoouCUfStyCgrpwkctR0GD3G\n\
                            fcGjbZRucV7VvVH9bS1jyaT/9yORyzPOSTwb+K9vOr6XlJX0CGvzQeIOcOimejHx\n\
                            ACFOCnhEKXiwMsmL8FMz0drkGeMuCODY/OHVmAdXDE5UhroL0oDhSmIrdZ8CxngO\n\
                            xHr1WD2yC0X0jAVP/mrxjSSfBwmmqhSMmONlvQIDAQABAoIBAQCJrBl3L8nWjayB\n\
                            VL1ta5MTC+alCX8DfhyVmvQC7FqKN4dvKecqUe0vWXcj9cLhK4B3JdAtXfNLQOgZ\n\
                            pYRoS2XsmjwiB20EFGtBrS+yBPvV/W0r7vrbfojHAdRXahBZhjl0ZAdrEvNgMfXt\n\
                            Kr2YoXDhUQZFBCvzKmqSFfKnLRpEhsCBOsp+Sx0ZbP3yVPASXnqiZmKblpY4qcE5\n\
                            KfYUO0nUWBSzY8I5c/29IY5oBbOUGS1DTMkx3R7V0BzbH/xmskVACn+cMzf467vp\n\
                            yupTKG9hIX8ff0QH4Ggx88uQTRTI9IvfrAMnICFtR6U7g70hLN6j9ujXkPNhmycw\n\
                            E5nQCmuBAoGBAPVbYtGBvnlySN73UrlyJ1NItUmOGhBt/ezpRjMIdMkJ6dihq7i2\n\
                            RpE76sRvwHY9Tmw8oxR/V1ITK3dM2jZP1SRcm1mn5Y1D3K38jwFS0C47AXzIN2N+\n\
                            LExekI1J4YOPV9o378vUKQuWpbQrQOOvylQBkRJ0Cd8DI3xhiBT/AVGbAoGBAO6Y\n\
                            WBP3GMloO2v6PHijhRqrNdaI0qht8tDhO5L1troFLst3sfpK9fUP/KTlhHOzNVBF\n\
                            fIJnNdcYAe9BISBbfSat+/R9F+GoUvpoC4j8ygHTQkT6ZMcMDfR8RQ4BlqGHIDKZ\n\
                            YaAJoPZVkg7hNRMcvIruYpzFrheDE/4xvnC51GeHAoGAHzCFyFIw72lKwCU6e956\n\
                            B0lH2ljZEVuaGuKwjM43YlMDSgmLNcjeAZpXRq9aDO3QKUwwAuwJIqLTNLAtURgm\n\
                            5R9slCIWuTV2ORvQ5f8r/aR8lOsyt1ATu4WN5JgOtdWj+laAAi4vJYz59YRGFGuF\n\
                            UdZ9JZZgptvUR/xx+xFLjp8CgYBMRzghaeXqvgABTUb36o8rL4FOzP9MCZqPXPKG\n\
                            0TdR0UZcli+4LS7k4e+LaDUoKCrrNsvPhN+ZnHtB2jiU96rTKtxaFYQFCKM+mvTV\n\
                            HrwWSUvucX62hAwSFYieKbPWgDSy+IZVe76SAllnmGg3bAB7CitMo4Y8zhMeORkB\n\
                            QOe/EQKBgQDgeNgRud7S9BvaT3iT7UtizOr0CnmMfoF05Ohd9+VE4ogvLdAoDTUF\n\
                            JFtdOT/0naQk0yqIwLDjzCjhe8+Ji5Y/21pjau8bvblTnASq26FRRjv5+hV8lmcR\n\
                            zzk3Y05KXvJL75ksJdomkzZZb0q+Omf3wyjMR8Xl5WueJH1fh4hpBw==\n\
                            -----END RSA PRIVATE KEY-----";

    #[test]
    fn private_key_from_rsa_pem() {
        PrivateKey::from_pem(&PKCS1_PEM.parse::<Pem>().expect("pem")).expect("private key");
    }

    #[test]
    fn check_pkcs1() {
        let private_pkcs1_pem = PKCS1_PEM.parse::<Pem>().expect("pem");
        let private = PrivateKey::from_pem(&private_pkcs1_pem).expect("private key");

        let private_pkcs1 = private.to_pkcs1().unwrap();
        PrivateKey::from_pkcs1(&private_pkcs1).unwrap();
        assert_eq!(private_pkcs1, private_pkcs1_pem.data());

        let public = private.to_public_key().unwrap();
        let public_pkcs1 = public.to_pkcs1().unwrap();
        PublicKey::from_pkcs1(&public_pkcs1).unwrap();
    }

    const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
                                  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n\
                                  +rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n\
                                  EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n\
                                  oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n\
                                  Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n\
                                  lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n\
                                  ZQIDAQAB\n\
                                  -----END PUBLIC KEY-----";

    #[test]
    fn public_key_from_pem() {
        PublicKey::from_pem(&PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
    }

    #[test]
    fn public_key_to_and_from_pkcs1() {
        let public_key = PublicKey::from_pem(&PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
        let pkcs1 = public_key.to_pkcs1().expect("PKCS1");
        let public_key_round_trip = PublicKey::from_pkcs1(&pkcs1).expect("round trip parse");
        assert_eq!(public_key_round_trip, public_key);
    }

    const RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN RSA PUBLIC KEY-----\n\
                                      MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa\n\
                                      D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw\n\
                                      luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB\n\
                                      o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV\n\
                                      gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH\n\
                                      Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB\n\
                                      -----END RSA PUBLIC KEY-----";

    #[test]
    fn public_key_from_rsa_pem() {
        PublicKey::from_pem(&RSA_PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
    }

    const GARBAGE_PEM: &str = "-----BEGIN GARBAGE-----R0FSQkFHRQo=-----END GARBAGE-----";

    #[test]
    fn public_key_from_garbage_pem_err() {
        let err = PublicKey::from_pem(&GARBAGE_PEM.parse::<Pem>().expect("pem")).expect_err("key error");
        assert_eq!(err.to_string(), "invalid PEM label: GARBAGE");
    }

    fn check_pk(pem_str: &str) {
        const MSG: &[u8] = b"abcde";

        let pem = pem_str.parse::<Pem>().expect("pem");
        let pk = PrivateKey::from_pem(&pem).expect("private key");
        let algo = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256);
        let signed_rsa = algo.sign(MSG, &pk).expect("rsa sign");
        algo.verify(&pk.to_public_key().unwrap(), MSG, &signed_rsa)
            .expect("rsa verify rsa");

        println!("Success!");
    }

    #[test]
    fn invalid_coeff_private_key_regression() {
        println!("2048 PK 7");
        check_pk(picky_test_data::RSA_2048_PK_7);
        println!("4096 PK 3");
        check_pk(picky_test_data::RSA_4096_PK_3);
    }

    #[test]
    fn rsa_crate_private_key_conversion() {
        use rsa::pkcs8::DecodePrivateKey;

        let pk_pem = picky_test_data::RSA_2048_PK_1.parse::<crate::pem::Pem>().unwrap();
        let pk = PrivateKey::from_pem(&pk_pem).unwrap();
        let converted_rsa_private_key = RsaPrivateKey::try_from(&pk).unwrap();
        let expected_rsa_private_key = RsaPrivateKey::from_pkcs8_der(pk_pem.data()).unwrap();

        assert_eq!(converted_rsa_private_key.n(), expected_rsa_private_key.n());
        assert_eq!(converted_rsa_private_key.e(), expected_rsa_private_key.e());
        assert_eq!(converted_rsa_private_key.d(), expected_rsa_private_key.d());

        let converted_primes = converted_rsa_private_key.primes();
        let expected_primes = expected_rsa_private_key.primes();
        assert_eq!(converted_primes.len(), expected_primes.len());
        for (converted_prime, expected_prime) in converted_primes.iter().zip(expected_primes.iter()) {
            assert_eq!(converted_prime, expected_prime);
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore)] // this test is slow in debug
    fn ring_understands_picky_pkcs8_rsa() {
        // Make sure we're generating pkcs8 understood by the `ring` crate
        let key = PrivateKey::generate_rsa(2048).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();
        ring::signature::RsaKeyPair::from_pkcs8(&pkcs8).unwrap();
    }

    #[rstest]
    #[case(EcCurve::NistP256, &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING)]
    #[case(EcCurve::NistP384, &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING)]
    fn ring_understands_picky_pkcs8_ec(
        #[case] curve: EcCurve,
        #[case] signing_alg: &'static ring::signature::EcdsaSigningAlgorithm,
    ) {
        // Make sure we're generating pkcs8 understood by the `ring` crate
        let key = PrivateKey::generate_ec(curve).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();
        let rng = ring::rand::SystemRandom::new();

        ring::signature::EcdsaKeyPair::from_pkcs8(signing_alg, &pkcs8, &rng).unwrap();
    }

    // Read from x25519 keys is not supported in `ring`, because it is mainly used for key
    // exchange for which key serialization/deserialization is not needed at all. But we support,
    // just to be consistent with OpenSSL and RFC https://www.rfc-editor.org/rfc/rfc8410
    #[test]
    fn ring_understands_picky_pkcs8_ed25519() {
        // Make sure we're generating pkcs8 understood by the `ring` crate.
        // `ring` is very specific about the format of the ED25519 private key, and in contrast
        // to OpenSSL, it uses newer v2 version of `PrivateKeyInfo` structure (`OneAsymmetricKey`)
        // which always includes public key in the private key structure.
        let key = PrivateKey::generate_ed(EdAlgorithm::Ed25519, true).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();

        ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    }

    #[test]
    fn ring_ed25519_pkcs8_keys_could_be_parsed() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        let key = PrivateKey::from_pkcs8(&pkcs8_bytes).unwrap();
        let _pair = EdKeypair::try_from(&key).unwrap();
    }
}
