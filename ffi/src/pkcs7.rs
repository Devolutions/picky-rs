#[diplomat::bridge]
pub mod ffi {
    use picky::x509::pkcs7::{self};

    use crate::error::ffi::PickyError;
    use crate::pem::ffi::Pem;
    use crate::utils::ffi::Buffer;
    use crate::x509::ffi::CertIterator;

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

        pub fn to_der(&self) -> Result<Box<Buffer>, Box<PickyError>> {
            Ok(Box::new(Buffer(self.0.to_der()?)))
        }

        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        pub fn digest_algorithms(&self) -> Box<crate::x509::algorithm_identifier::ffi::AlgorithmIdentifierIterator> {
            let algos = self.0.digest_algorithms();
            Box::new(crate::x509::algorithm_identifier::ffi::AlgorithmIdentifierIterator(
                algos.to_vec(),
            ))
        }

        pub fn signer_infos(&self) -> Box<crate::x509::singer_info::ffi::SignerInfoIterator> {
            let infos = self.0.signer_infos();
            Box::new(crate::x509::singer_info::ffi::SignerInfoIterator(
                infos
                    .iter()
                    .map(|info| crate::x509::singer_info::ffi::SignerInfo(info.clone()))
                    .collect(),
            ))
        }

        pub fn encapsulated_content_info(&self) -> Box<crate::x509::attribute::ffi::EncapsulatedContentInfo> {
            Box::new(crate::x509::attribute::ffi::EncapsulatedContentInfo(
                self.0.encapsulated_content_info().clone(),
            ))
        }

        pub fn decode_certificates(&self) -> Box<CertIterator> {
            let certs = self.0.decode_certificates();
            Box::new(CertIterator(certs))
        }
    }
}
