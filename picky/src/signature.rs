use crate::{
    key::{PrivateKey, PublicKey},
    oids,
    private::private_key_info,
    AlgorithmIdentifier,
};
use picky_asn1::wrapper::{BitStringAsn1Container, OctetStringAsn1Container};
use rsa::{hash::Hashes, BigUint, PaddingScheme, PublicKey as RsaPublicKeyInterface, RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum SignatureError {
    /// RSA error
    #[snafu(display("RSA error: {}", context))]
    Rsa { context: String },

    /// invalid signature
    BadSignature,

    /// unsupported algorithm
    #[snafu(display("unsupported algorithm: {}", algorithm))]
    UnsupportedAlgorithm { algorithm: String },
}

impl From<rsa::errors::Error> for SignatureError {
    fn from(e: rsa::errors::Error) -> Self {
        SignatureError::Rsa { context: e.to_string() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureHashType {
    #[serde(rename = "RS1")]
    RsaSha1,
    #[serde(rename = "RS224")]
    RsaSha224,
    #[serde(rename = "RS256")]
    RsaSha256,
    #[serde(rename = "RS384")]
    RsaSha384,
    #[serde(rename = "RS512")]
    RsaSha512,
}

macro_rules! hash {
    ($algorithm:ident, $input:ident) => {{
        let mut digest = $algorithm::new();
        digest.input($input);
        digest.result().as_slice().to_vec()
    }};
}

impl SignatureHashType {
    pub fn from_algorithm_identifier(algorithm_identifier: &AlgorithmIdentifier) -> Result<Self, SignatureError> {
        let oid_string: String = algorithm_identifier.oid().into();
        match oid_string.as_str() {
            oids::SHA1_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha1),
            oids::SHA224_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha224),
            oids::SHA256_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha256),
            oids::SHA384_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha384),
            oids::SHA512_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha512),
            _ => Err(SignatureError::UnsupportedAlgorithm { algorithm: oid_string }),
        }
    }

    pub fn hash(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::RsaSha1 => hash!(Sha1, msg),
            Self::RsaSha224 => hash!(Sha224, msg),
            Self::RsaSha256 => hash!(Sha256, msg),
            Self::RsaSha384 => hash!(Sha384, msg),
            Self::RsaSha512 => hash!(Sha512, msg),
        }
    }

    pub fn sign(self, msg: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, SignatureError> {
        let rsa_private_key = match &private_key.as_inner().private_key {
            private_key_info::PrivateKeyValue::RSA(OctetStringAsn1Container(key)) => RSAPrivateKey::from_components(
                BigUint::from_bytes_be(key.modulus().as_bytes_be()),
                BigUint::from_bytes_be(key.public_exponent().as_bytes_be()),
                BigUint::from_bytes_be(key.private_exponent().as_bytes_be()),
                key.primes()
                    .iter()
                    .map(|p| BigUint::from_bytes_be(p.as_bytes_be()))
                    .collect(),
            ),
        };

        let digest = self.hash(msg);

        let hash_algo = match self {
            Self::RsaSha1 => &Hashes::SHA1,
            Self::RsaSha224 => &Hashes::SHA2_224,
            Self::RsaSha256 => &Hashes::SHA2_256,
            Self::RsaSha384 => &Hashes::SHA2_384,
            Self::RsaSha512 => &Hashes::SHA2_512,
        };

        let signature = rsa_private_key.sign_blinded(
            &mut rand::rngs::OsRng,
            PaddingScheme::PKCS1v15,
            Some(hash_algo),
            &digest,
        )?;

        Ok(signature)
    }

    pub fn verify(self, public_key: &PublicKey, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        use crate::private::subject_public_key_info::PublicKey as InnerPublicKey;

        let public_key = match &public_key.as_inner().subject_public_key {
            InnerPublicKey::RSA(BitStringAsn1Container(key)) => RSAPublicKey::new(
                BigUint::from_bytes_be(key.modulus.as_bytes_be()),
                BigUint::from_bytes_be(key.public_exponent.as_bytes_be()),
            )?,
            InnerPublicKey::EC(_) => {
                return Err(SignatureError::UnsupportedAlgorithm {
                    algorithm: "elliptic curves".into(),
                });
            }
        };

        let hash_algorithm = match self {
            Self::RsaSha1 => &Hashes::SHA1,
            Self::RsaSha224 => &Hashes::SHA2_224,
            Self::RsaSha256 => &Hashes::SHA2_256,
            Self::RsaSha384 => &Hashes::SHA2_384,
            Self::RsaSha512 => &Hashes::SHA2_512,
        };

        let digest = self.hash(msg);

        public_key
            .verify(PaddingScheme::PKCS1v15, Some(hash_algorithm), &digest, signature)
            .map_err(|_| SignatureError::BadSignature)?;

        Ok(())
    }
}

impl From<SignatureHashType> for AlgorithmIdentifier {
    fn from(ty: SignatureHashType) -> Self {
        match ty {
            SignatureHashType::RsaSha1 => AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
            SignatureHashType::RsaSha224 => AlgorithmIdentifier::new_sha224_with_rsa_encryption(),
            SignatureHashType::RsaSha256 => AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
            SignatureHashType::RsaSha384 => AlgorithmIdentifier::new_sha384_with_rsa_encryption(),
            SignatureHashType::RsaSha512 => AlgorithmIdentifier::new_sha512_with_rsa_encryption(),
        }
    }
}
