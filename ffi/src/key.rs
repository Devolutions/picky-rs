#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::pem::ffi::Pem;
    use diplomat_runtime::DiplomatResult;

    #[diplomat::opaque]
    pub struct PrivateKey(pub picky::key::PrivateKey);

    impl PrivateKey {
        /// Extracts private key from PEM object.
        pub fn from_pem(pem: &Pem) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::from_pem(&pem.0));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Reads a private key from its PKCS8 storage.
        pub fn from_pkcs8(pkcs8: &[u8]) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::from_pkcs8(pkcs8));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Generates a new RSA private key.
        ///
        /// This is slow in debug builds.
        pub fn generate_rsa(bits: usize) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::generate_rsa(bits));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Exports the private key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<Pem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(Pem(pem))).into()
        }

        /// Extracts the public part of this private key
        pub fn to_public_key(&self) -> Box<PublicKey> {
            Box::new(PublicKey(self.0.to_public_key()))
        }
    }

    #[diplomat::opaque]
    pub struct PublicKey(pub picky::key::PublicKey);

    impl PublicKey {
        /// Extracts public key from PEM object.
        pub fn from_pem(pem: &Pem) -> DiplomatResult<Box<PublicKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PublicKey::from_pem(&pem.0));
            Ok(Box::new(PublicKey(key))).into()
        }

        /// Reads a public key from its DER encoding.
        pub fn from_der(der: &[u8]) -> DiplomatResult<Box<PublicKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PublicKey::from_der(der));
            Ok(Box::new(PublicKey(key))).into()
        }

        /// Exports the public key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<Pem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(Pem(pem))).into()
        }
    }
}
