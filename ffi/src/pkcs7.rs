#[diplomat::bridge]
pub mod ffi {

    use picky::x509::pkcs7::{self};

    use crate::error::ffi::PickyError;
    use crate::pem::ffi::Pem;
    use crate::x509::ffi::{AlgorithmIdentifiers, CertVec, Der, EncapsulatedContentInfo, SignerInfo, SignerInfos};

    #[diplomat::opaque]
    pub struct Pkcs7(pub pkcs7::Pkcs7);

    impl Pkcs7 {
        pub fn from_der(data: &[u8]) -> Result<Box<Pkcs7>, Box<PickyError>> {
            let pkcs7 = pkcs7::Pkcs7::from_der(data)?;
            Ok(Box::new(Pkcs7(pkcs7)))
        }

        pub fn from_pem(pem: &Pem) -> Result<Box<Pkcs7>, Box<PickyError>> {
            let pkcs7 = pkcs7::Pkcs7::from_pem(&pem.0)?;
            Ok(Box::new(Pkcs7(pkcs7)))
        }

        pub fn from_pem_str(pem_str: &str) -> Result<Box<Pkcs7>, Box<PickyError>> {
            let pkcs7 = pkcs7::Pkcs7::from_pem_str(pem_str)?;
            Ok(Box::new(Pkcs7(pkcs7)))
        }

        pub fn to_der(&self) -> Result<Box<Der>, Box<PickyError>> {
            Ok(Box::new(Der(self.0.to_der()?)))
        }

        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        pub fn digest_algorithms(&self) -> Box<AlgorithmIdentifiers> {
            let algos = self.0.digest_algorithms();
            Box::new(AlgorithmIdentifiers(algos.to_vec()))
        }

        pub fn signer_infos(&self) -> Box<SignerInfos> {
            let infos = self.0.signer_infos();
            Box::new(SignerInfos(infos.iter().map(|info| SignerInfo(info.clone())).collect()))
        }

        pub fn encapsulated_content_info(&self) -> Box<EncapsulatedContentInfo> {
            Box::new(EncapsulatedContentInfo(self.0.encapsulated_content_info().clone()))
        }

        pub fn decode_certificates(&self) -> Box<CertVec> {
            let certs = self.0.decode_certificates();
            Box::new(CertVec(certs))
        }
    }
}
