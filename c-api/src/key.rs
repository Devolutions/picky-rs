#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::pem::ffi::PickyPem;
    use diplomat_runtime::DiplomatResult;

    #[diplomat::opaque]
    pub struct PickyPrivateKey(pub picky::key::PrivateKey);

    impl PickyPrivateKey {
        /// Extracts private key from PEM object.
        pub fn from_pem(pem: &PickyPem) -> DiplomatResult<Box<PickyPrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::from_pem(&pem.0));
            Ok(Box::new(PickyPrivateKey(key))).into()
        }

        /// Reads a private key from its PKCS8 storage.
        pub fn from_pkcs8(pkcs8: &[u8]) -> DiplomatResult<Box<PickyPrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::from_pkcs8(pkcs8));
            Ok(Box::new(PickyPrivateKey(key))).into()
        }

        /// Generates a new RSA private key.
        ///
        /// This is slow in debug builds.
        pub fn generate_rsa(bits: usize) -> DiplomatResult<Box<PickyPrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::generate_rsa(bits));
            Ok(Box::new(PickyPrivateKey(key))).into()
        }

        /// Exports the private key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<PickyPem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(PickyPem(pem))).into()
        }

        /// Extracts the public part of this private key
        pub fn to_public_key(&self) -> Box<PickyPublicKey> {
            Box::new(PickyPublicKey(self.0.to_public_key()))
        }
    }

    #[diplomat::opaque]
    pub struct PickyPublicKey(pub picky::key::PublicKey);

    impl PickyPublicKey {
        /// Extracts public key from PEM object.
        pub fn from_pem(pem: &PickyPem) -> DiplomatResult<Box<PickyPublicKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PublicKey::from_pem(&pem.0));
            Ok(Box::new(PickyPublicKey(key))).into()
        }

        /// Reads a public key from its DER encoding.
        pub fn from_der(der: &[u8]) -> DiplomatResult<Box<PickyPublicKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PublicKey::from_der(der));
            Ok(Box::new(PickyPublicKey(key))).into()
        }

        /// Exports the public key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<PickyPem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(PickyPem(pem))).into()
        }
    }
}
