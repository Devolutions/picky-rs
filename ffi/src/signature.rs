#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::hash::ffi::HashAlgorithm;
    use crate::key::ffi::PublicKey;

    #[diplomat::opaque]
    pub struct SignatureAlgorithm(pub picky::signature::SignatureAlgorithm);

    impl SignatureAlgorithm {
        pub fn new_rsa_pkcs_1v15(hash_algorithm: HashAlgorithm) -> Result<Box<SignatureAlgorithm>, Box<PickyError>> {
            let algo = picky::hash::HashAlgorithm::try_from(hash_algorithm).map_err(|()| "invalid hash algorithm")?;
            Ok(Box::new(Self(picky::signature::SignatureAlgorithm::RsaPkcs1v15(algo))))
        }

        pub fn new_ecdsa(hash_algorithm: HashAlgorithm) -> Result<Box<SignatureAlgorithm>, Box<PickyError>> {
            let algo = picky::hash::HashAlgorithm::try_from(hash_algorithm).map_err(|()| "invalid hash algorithm")?;
            Ok(Box::new(Self(picky::signature::SignatureAlgorithm::Ecdsa(algo))))
        }

        pub fn verify(&self, public_key: &PublicKey, msg: &[u8], signature: &[u8]) -> Result<(), Box<PickyError>> {
            self.0.verify(&public_key.0, msg, signature)?;
            Ok(())
        }
    }
}
