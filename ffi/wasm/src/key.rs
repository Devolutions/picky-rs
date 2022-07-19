use crate::pem::Pem;
use wasm_bindgen::prelude::*;

define_error!(KeyError, picky::key::KeyError);

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

    /// Exports the private key into a PEM object
    pub fn to_pem(&self) -> Result<Pem, KeyError> {
        let pem = self.0.to_pem()?;
        Ok(Pem(pem))
    }

    /// Extracts the public part of this private key
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.to_public_key())
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
