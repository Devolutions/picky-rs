use crate::key::{EcCurve, PrivateKey, PublicKey};
use crate::pem::Pem;

use wasm_bindgen::prelude::*;

define_error!(SshPrivateKeyError, picky::ssh::private_key::SshPrivateKeyError);
define_error!(SshPublicKeyError, picky::ssh::public_key::SshPublicKeyError);

#[wasm_bindgen]
pub struct SshPrivateKey(pub(crate) picky::ssh::private_key::SshPrivateKey);

#[wasm_bindgen]
impl SshPrivateKey {
    /// Generates a new RSA SSH private key
    pub fn generate_rsa(
        bits: usize,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<SshPrivateKey, SshPrivateKeyError> {
        let key = picky::ssh::private_key::SshPrivateKey::generate_rsa(bits, passphrase, comment)?;
        Ok(Self(key))
    }

    /// Generates a new EC SSH private key
    pub fn generate_ec(
        curve: EcCurve,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<SshPrivateKey, SshPrivateKeyError> {
        let key = picky::ssh::private_key::SshPrivateKey::generate_ec(curve.into(), passphrase, comment)?;
        Ok(Self(key))
    }

    /// Generates a new Ed25519 SSH private key
    pub fn generate_ed25519(
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<SshPrivateKey, SshPrivateKeyError> {
        let key = picky::ssh::private_key::SshPrivateKey::generate_ed25519(passphrase, comment)?;
        Ok(Self(key))
    }

    /// Parses SSH private key from PEM object
    pub fn from_pem(pem: &Pem, passphrase: Option<String>) -> Result<SshPrivateKey, SshPrivateKeyError> {
        let key = picky::ssh::private_key::SshPrivateKey::from_pem(&pem.0, passphrase)?;
        Ok(Self(key))
    }

    /// Converts SSH private key to PEM object
    pub fn to_pem(&self) -> Result<Pem, SshPrivateKeyError> {
        Ok(Pem(self.0.to_pem()?))
    }

    /// Sets SSH private key comment
    pub fn set_comment(&mut self, comment: String) {
        self.0.comment = comment;
    }

    /// Returns comment of the SSH private key
    pub fn comment(&self) -> String {
        self.0.comment.clone()
    }

    /// Returns cipher name of the SSH private key
    pub fn cipher_name(&self) -> String {
        self.0.cipher_name.clone()
    }

    /// Returns inner private key from SSH private key
    pub fn inner_key(&self) -> Result<PrivateKey, SshPrivateKeyError> {
        Ok(PrivateKey(self.0.inner_key()?.clone()))
    }

    /// Extracts the public part from SSH private key
    pub fn public_key(&self) -> SshPublicKey {
        SshPublicKey(self.0.public_key().clone())
    }
}

#[wasm_bindgen]
pub struct SshPublicKey(pub(crate) picky::ssh::public_key::SshPublicKey);

#[wasm_bindgen]
impl SshPublicKey {
    /// Parses string representation of a SSH Public Key.
    pub fn parse(repr: &str) -> Result<SshPublicKey, SshPublicKeyError> {
        let key: picky::ssh::public_key::SshPublicKey = repr.parse()?;
        Ok(Self(key))
    }

    /// Converts SSH public key to string representation
    pub fn to_string(&self) -> Result<String, SshPublicKeyError> {
        Ok(self.0.to_string()?)
    }

    /// Returns the comment of the SSH public key
    pub fn comment(&self) -> String {
        self.0.comment.clone()
    }

    /// Sets the comment of the SSH public key
    pub fn set_comment(&mut self, comment: String) {
        self.0.comment = comment;
    }

    /// Returns the inner public key from SSH public key
    pub fn inner_key(&self) -> PublicKey {
        PublicKey(self.0.inner_key().clone())
    }
}
