#![allow(clippy::needless_lifetimes)] // Diplomat requires explicit lifetimes

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;

    #[diplomat::opaque]
    pub struct AlgorithmIdentifier(pub picky::AlgorithmIdentifier);

    impl AlgorithmIdentifier {
        pub fn is_a(&self, other: &str) -> Result<bool, Box<PickyError>> {
            Ok(self
                .0
                .is_a(picky::oid::ObjectIdentifier::try_from(other).map_err(|_| "invalid OID")?))
        }

        pub fn get_oid(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let string: String = self.0.oid().into();
            write!(writable, "{}", string)?;
            Ok(())
        }

        pub fn get_parameters<'a>(&'a self) -> Box<AlgorithmIdentifierParameters<'a>> {
            Box::new(AlgorithmIdentifierParameters(self.0.parameters()))
        }
    }

    /// TODO/FIXME: Is having a reference here safe? We perhaps need to clone the parameters.
    #[diplomat::opaque]
    pub struct AlgorithmIdentifierParameters<'a>(pub &'a picky_asn1_x509::AlgorithmIdentifierParameters);

    pub enum AlgorithmIdentifierParametersType {
        None,
        Null,
        Aes,
        Ec,
        RsassaPss,
    }

    impl AlgorithmIdentifierParameters<'_> {
        pub fn get_type(&self) -> AlgorithmIdentifierParametersType {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::None => AlgorithmIdentifierParametersType::None,
                picky_asn1_x509::AlgorithmIdentifierParameters::Null => AlgorithmIdentifierParametersType::Null,
                picky_asn1_x509::AlgorithmIdentifierParameters::Aes(_) => AlgorithmIdentifierParametersType::Aes,
                picky_asn1_x509::AlgorithmIdentifierParameters::Ec(_) => AlgorithmIdentifierParametersType::Ec,
                picky_asn1_x509::AlgorithmIdentifierParameters::RsassaPss(_) => {
                    AlgorithmIdentifierParametersType::RsassaPss
                }
            }
        }

        pub fn to_aes(&self) -> Option<Box<AesParameters>> {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::Aes(params) => {
                    Some(Box::new(AesParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_ec(&self) -> Option<Box<EcParameters>> {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::Ec(params) => {
                    Some(Box::new(EcParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_rsassa_pss(&self) -> Option<Box<RsassaPssParameters>> {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::RsassaPss(params) => {
                    Some(Box::new(RsassaPssParameters(params.clone())))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct AesParameters(pub picky_asn1_x509::AesParameters);

    #[diplomat::opaque]
    pub struct EcParameters(pub picky_asn1_x509::EcParameters);

    #[diplomat::opaque]
    pub struct RsassaPssParameters(pub picky_asn1_x509::RsassaPssParams);

    pub enum AesParametersType {
        Null,
        InitializationVector,
        AuthenticatedEncryptionParameters,
    }

    impl AesParameters {
        pub fn get_type(&self) -> AesParametersType {
            match self.0 {
                picky_asn1_x509::AesParameters::Null => AesParametersType::Null,
                picky_asn1_x509::AesParameters::InitializationVector(_) => AesParametersType::InitializationVector,
                picky_asn1_x509::AesParameters::AuthenticatedEncryptionParameters(_) => {
                    AesParametersType::AuthenticatedEncryptionParameters
                }
            }
        }

        pub fn to_initialization_vector(&self) -> Option<Box<crate::utils::ffi::VecU8>> {
            match &self.0 {
                picky_asn1_x509::AesParameters::InitializationVector(iv) => Some(Box::new(iv.into())),
                _ => None,
            }
        }

        pub fn to_authenticated_encryption_parameters(&self) -> Option<Box<AesAuthEncParams>> {
            match &self.0 {
                picky_asn1_x509::AesParameters::AuthenticatedEncryptionParameters(params) => {
                    Some(Box::new(AesAuthEncParams(params.clone())))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct AesAuthEncParams(pub picky_asn1_x509::AesAuthEncParams);

    #[diplomat::opaque]
    pub struct AlgorithmIdentifierIterator(pub Vec<picky::AlgorithmIdentifier>);

    impl AlgorithmIdentifierIterator {
        pub fn next(&mut self) -> Option<Box<AlgorithmIdentifier>> {
            self.0.pop().map(|algo| Box::new(AlgorithmIdentifier(algo)))
        }
    }
}
