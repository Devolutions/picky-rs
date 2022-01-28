#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::hash::ffi::PickyHashAlgorithm;
    use crate::key::ffi::PickyPublicKey;
    use diplomat_runtime::DiplomatResult;
    use picky::hash::HashAlgorithm;
    use picky::signature::SignatureAlgorithm;

    #[diplomat::opaque]
    pub struct PickySignatureAlgorithm(pub SignatureAlgorithm);

    impl PickySignatureAlgorithm {
        pub fn new_rsa_pkcs_1v15(
            hash_algorithm: PickyHashAlgorithm,
        ) -> DiplomatResult<Box<PickySignatureAlgorithm>, Box<PickyError>> {
            let algo = match HashAlgorithm::try_from(hash_algorithm) {
                Ok(v) => v,
                Err(()) => return Err(Box::new(PickyError("Invalid hash algorithm".to_owned()))).into(),
            };
            Ok(Box::new(Self(SignatureAlgorithm::RsaPkcs1v15(algo)))).into()
        }

        pub fn verify(
            &self,
            public_key: &PickyPublicKey,
            msg: &[u8],
            signature: &[u8],
        ) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(self.0.verify(&public_key.0, msg, signature));
            Ok(()).into()
        }
    }
}
