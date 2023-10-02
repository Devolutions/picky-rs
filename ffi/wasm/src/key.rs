use crate::pem::Pem;
use wasm_bindgen::prelude::*;

define_error!(KeyError, picky::key::KeyError);

impl From<picky::key::EcCurve> for EcCurve {
    fn from(value: picky::key::EcCurve) -> Self {
        match value {
            picky::key::EcCurve::NistP256 => Self::NistP256,
            picky::key::EcCurve::NistP384 => Self::NistP384,
        }
    }
}

impl From<EcCurve> for picky::key::EcCurve {
    fn from(value: EcCurve) -> Self {
        match value {
            EcCurve::NistP256 => Self::NistP256,
            EcCurve::NistP384 => Self::NistP384,
        }
    }
}

/// Known elliptic curve name used for ECDSA arithmetic operations
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum EcCurve {
    /// NIST P-256
    NistP256,
    /// NIST P-384
    NistP384,
}

impl From<picky::key::EdAlgorithm> for EdAlgorithm {
    fn from(value: picky::key::EdAlgorithm) -> Self {
        match value {
            picky::key::EdAlgorithm::Ed25519 => Self::Ed25519,
            picky::key::EdAlgorithm::X25519 => Self::X25519,
        }
    }
}

impl From<EdAlgorithm> for picky::key::EdAlgorithm {
    fn from(value: EdAlgorithm) -> Self {
        match value {
            EdAlgorithm::Ed25519 => Self::Ed25519,
            EdAlgorithm::X25519 => Self::X25519,
        }
    }
}

/// Known Edwards curve-based algorithm name
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum EdAlgorithm {
    /// Ed25519 signing algorithm
    Ed25519,
    /// X25519 key agreement algorithm
    X25519,
}

#[wasm_bindgen]
pub struct PrivateKey(pub(crate) picky::key::PrivateKey);

#[wasm_bindgen]
impl PrivateKey {
    /// Extracts private key from PEM object.
    pub fn from_pem(pem: &Pem) -> Result<PrivateKey, KeyError> {
        let key = picky::key::PrivateKey::from_pem(&pem.0)?;
        Ok(Self(key))
    }

    /// Reads a private key from its PKCS8 storage.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<PrivateKey, KeyError> {
        let key = picky::key::PrivateKey::from_pkcs8(pkcs8)?;
        Ok(Self(key))
    }

    /// Generates a new RSA private key.
    ///
    /// This is slow in debug builds.
    pub fn generate_rsa(bits: usize) -> Result<PrivateKey, KeyError> {
        let key = picky::key::PrivateKey::generate_rsa(bits)?;
        Ok(Self(key))
    }

    /// Generates a new EC private key.
    pub fn generate_ec(curve: EcCurve) -> Result<PrivateKey, KeyError> {
        let key = picky::key::PrivateKey::generate_ec(curve.into())?;
        Ok(Self(key))
    }

    /// Generates new ed key pair with specified supported algorithm.
    ///
    /// `write_public_key` specifies whether to include public key in the private key file.
    /// Note that OpenSSL does not support ed keys with public key included.
    pub fn generate_ed(algorithm: EdAlgorithm, write_public_key: bool) -> Result<PrivateKey, KeyError> {
        let key = picky::key::PrivateKey::generate_ed(algorithm.into(), write_public_key)?;
        Ok(Self(key))
    }

    /// Exports the private key into a PEM object
    pub fn to_pem(&self) -> Result<Pem, KeyError> {
        let pem = self.0.to_pem()?;
        Ok(Pem(pem))
    }

    /// Extracts the public part of this private key
    pub fn to_public_key(&self) -> Result<PublicKey, KeyError> {
        Ok(PublicKey(self.0.to_public_key()?))
    }
}

#[wasm_bindgen]
pub struct PublicKey(pub(crate) picky::key::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    /// Extracts public key from PEM object.
    pub fn from_pem(pem: &Pem) -> Result<PublicKey, KeyError> {
        let key = picky::key::PublicKey::from_pem(&pem.0)?;
        Ok(Self(key))
    }

    /// Reads a public key from its DER encoding.
    pub fn from_der(der: &[u8]) -> Result<PublicKey, KeyError> {
        let key = picky::key::PublicKey::from_der(der)?;
        Ok(Self(key))
    }

    /// Exports the public key into a PEM object
    pub fn to_pem(&self) -> Result<Pem, KeyError> {
        let pem = self.0.to_pem()?;
        Ok(Pem(pem))
    }
}
