#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::hash::ffi::HashAlgorithm;
    use crate::key::ffi::PublicKey;
    use diplomat_runtime::DiplomatResult;

    #[diplomat::opaque]
    pub struct SignatureAlgorithm(pub picky::signature::SignatureAlgorithm);

    impl SignatureAlgorithm {
        pub fn new_rsa_pkcs_1v15(
            hash_algorithm: HashAlgorithm,
        ) -> DiplomatResult<Box<SignatureAlgorithm>, Box<PickyError>> {
            let algo = match picky::hash::HashAlgorithm::try_from(hash_algorithm) {
                Ok(v) => v,
                Err(()) => return Err(Box::new(PickyError::from("Invalid hash algorithm"))).into(),
            };
            Ok(Box::new(Self(picky::signature::SignatureAlgorithm::RsaPkcs1v15(algo)))).into()
        }

        pub fn verify(
            &self,
            public_key: &PublicKey,
            msg: &[u8],
            signature: &[u8],
        ) -> DiplomatResult<(), Box<PickyError>> {
            err_check_from!(self.0.verify(&public_key.0, msg, signature));
            Ok(()).into()
        }
    }
}
